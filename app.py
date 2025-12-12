import os
import re
import json
import tempfile
import hashlib
import secrets
from datetime import datetime
from io import BytesIO

import streamlit as st
import pandas as pd
from pdfminer.high_level import extract_text

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer

CSS = """
<style>
.block-container { padding-top: 1.0rem; }
h1, h2, h3 { letter-spacing: -0.02em; }
.small-muted { color: #6b7280; font-size: 0.9rem; }
.stButton>button { border-radius: 12px; }
</style>
"""

APP_DIR = os.path.dirname(os.path.abspath(__file__))

def _safe_path(filename: str) -> str:
    p = os.path.join(APP_DIR, filename)
    try:
        with open(p, "a", encoding="utf-8"):
            pass
        return p
    except Exception:
        return os.path.join(tempfile.gettempdir(), filename)

USERS_PATH = _safe_path("users.json")
HISTORY_PATH = _safe_path("history.json")
SHARED_STATE_PATH = _safe_path("shared_state.json")

def _load_json(path: str, default):
    try:
        if not os.path.exists(path):
            return default
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def _atomic_write_json(path: str, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)

# --------------------------- AUTH LOCAL ---------------------------

def _hash_password(password: str, salt_hex: str | None = None) -> dict:
    if salt_hex is None:
        salt = secrets.token_bytes(16)
        salt_hex = salt.hex()
    else:
        salt = bytes.fromhex(salt_hex)

    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 150_000)
    return {"salt": salt_hex, "hash": dk.hex()}

def _verify_password(password: str, stored: dict) -> bool:
    if not stored or "salt" not in stored or "hash" not in stored:
        return False
    calc = _hash_password(password, salt_hex=stored["salt"])
    return secrets.compare_digest(calc["hash"], stored["hash"])

def _users_load() -> dict:
    return _load_json(USERS_PATH, default={"users": {}})

def _users_save(data: dict) -> None:
    _atomic_write_json(USERS_PATH, data)

def auth_screen() -> str:
    st.markdown(CSS, unsafe_allow_html=True)
    st.title("🔐 Acesso")
    st.markdown('<div class="small-muted">Entrar ou criar conta (cadastro local)</div>', unsafe_allow_html=True)
    st.info("⚠️ Cadastro local: em hospedagem gratuita ele pode ser perdido se o app reiniciar.")

    if st.session_state.get("auth_user"):
        return st.session_state["auth_user"]

    users_db = _users_load()
    users = users_db.get("users", {})

    tab_login, tab_signup = st.tabs(["Entrar", "Cadastrar-se"])

    with tab_login:
        u = st.text_input("Usuário", key="login_user")
        p = st.text_input("Senha", type="password", key="login_pass")
        if st.button("Entrar", type="primary"):
            u = (u or "").strip().lower()
            if not u or not p:
                st.warning("Preencha usuário e senha.")
            elif u not in users:
                st.error("Usuário não encontrado.")
            elif not _verify_password(p, users[u]):
                st.error("Senha incorreta.")
            else:
                st.session_state["auth_user"] = u
                st.success("Login ok!")
                st.rerun()

    with tab_signup:
        u2 = st.text_input("Criar usuário (ex: nome.sobrenome)", key="signup_user")
        p2 = st.text_input("Criar senha", type="password", key="signup_pass")
        p3 = st.text_input("Confirmar senha", type="password", key="signup_pass2")
        if st.button("Cadastrar", type="primary"):
            u2 = (u2 or "").strip().lower()
            if not u2 or not p2 or not p3:
                st.warning("Preencha todos os campos.")
            elif len(u2) < 3:
                st.warning("Usuário muito curto.")
            elif u2 in users:
                st.error("Esse usuário já existe.")
            elif p2 != p3:
                st.error("As senhas não conferem.")
            elif len(p2) < 4:
                st.warning("Senha muito curta (mínimo 4).")
            else:
                users[u2] = _hash_password(p2)
                users_db["users"] = users
                _users_save(users_db)
                st.session_state["auth_user"] = u2
                st.success("Cadastro feito! Você já entrou.")
                st.rerun()

    st.stop()

# --------------------------- HISTÓRICO ---------------------------

def history_append(event: dict):
    data = _load_json(HISTORY_PATH, {"events": []})
    data["events"].append(event)
    data["events"] = data["events"][-5000:]
    _atomic_write_json(HISTORY_PATH, data)

def history_df(user: str | None = None, filial: str | None = None) -> pd.DataFrame:
    data = _load_json(HISTORY_PATH, {"events": []})
    rows = data.get("events", [])
    if user:
        rows = [r for r in rows if r.get("user") == user]
    if filial:
        rows = [r for r in rows if r.get("filial") == filial]
    if not rows:
        return pd.DataFrame(columns=["ts", "user", "filial", "action", "detail"])
    df = pd.DataFrame(rows)
    if "ts" in df.columns:
        df = df.sort_values("ts", ascending=False)
    return df[["ts", "user", "filial", "action", "detail"]]

# --------------------------- MULTIUSUÁRIO (fila compartilhada local) ---------------------------

def shared_load() -> dict:
    return _load_json(SHARED_STATE_PATH, {"RJ": {}, "SJP": {}})

def shared_save(state: dict):
    _atomic_write_json(SHARED_STATE_PATH, state)

def persist_to_shared(filial: str):
    state = shared_load()
    state[filial] = {
        "orders": st.session_state.orders,
        "queue_super_longa": st.session_state.queue_super_longa,
        "queue_longa": st.session_state.queue_longa,
        "queue_media": st.session_state.queue_media,
        "queue_curta": st.session_state.queue_curta,
        "selected_fleets": st.session_state.selected_fleets,
        "frotas_destacadas": st.session_state.frotas_destacadas,
        "frotas_removidas": sorted(list(st.session_state.frotas_removidas)),
        "registro_pegaram_carga": st.session_state.registro_pegaram_carga,
        "registro_excluidas": st.session_state.registro_excluidas,
    }
    shared_save(state)

def load_from_shared(filial: str):
    state = shared_load().get(filial, {})
    if not state:
        return
    st.session_state.orders = state.get("orders", [])
    st.session_state.queue_super_longa = state.get("queue_super_longa", [])
    st.session_state.queue_longa = state.get("queue_longa", [])
    st.session_state.queue_media = state.get("queue_media", [])
    st.session_state.queue_curta = state.get("queue_curta", [])
    st.session_state.selected_fleets = state.get("selected_fleets", [])
    st.session_state.frotas_destacadas = state.get("frotas_destacadas", [])
    st.session_state.frotas_removidas = set(state.get("frotas_removidas", []))
    st.session_state.registro_pegaram_carga = state.get("registro_pegaram_carga", [])
    st.session_state.registro_excluidas = state.get("registro_excluidas", [])

# =============================================================================
#                           SEU APP (parsing e filas)
# =============================================================================

FROTAS_VALIDAS = {
    203,205,207,208,211,212,215,218,219,222,223,226,227,228,229,230,
    231,232,233,234,235,236,237,238,239,240,241,242,243,244,245,246,
    247,248,249,250,251,252,253,267,301,302,303,304,305,306,307,308,
    309,310,311,312,313,314,315,316,317,318,319,320,321,322,323,324,
    325,326,327,328,329,330,331,332,333,334,335,336,401,402,403,404,
    405,406,407,408,409,410,411,412,413,414,415,416,417,418,419,420,
    421,422,423,424,425,426,427,428,429,430,431,432,433,434,435,436,
    437,438,439,440,451,452,453,454,455,456,457,458,459,460,461,462,
    463,464,466,467,468,469,470
}
FROTAS_VALIDAS_STR = {str(x) for x in FROTAS_VALIDAS}

SECTION_TITLES_RJ = [
    "INTER - RESENDE",
    "SUPER LONGA - RESENDE",
    "LONGA - RESENDE",
    "MEDIA RESENDE",
    "CURTA - RESENDE",
]

SEC_PATTERNS_RJ = [
    (re.compile(r"INTER\s*-\s*RESENDE", re.IGNORECASE), 0),
    (re.compile(r"SUPER\s*LONGA\s*-\s*RESENDE", re.IGNORECASE), 1),
    (re.compile(r"LONGA\s*-\s*RESENDE", re.IGNORECASE), 2),
    (re.compile(r"MEDIA\s*RESENDE", re.IGNORECASE), 3),
    (re.compile(r"CURTA\s*-\s*RESENDE", re.IGNORECASE), 4),
]

PATTERN_SEQ_INTERNO_FROTA_RJ = re.compile(
    r'(?:\bSIM\b\s+)?\b\d+\b\s+\b\d+\.\d+\b\s+(\d{2,3})\b',
    re.IGNORECASE
)
PATTERN_ISOLATED_NUM_RJ = re.compile(r'(?<!\.)\b\d{2,6}\b(?!\.)')

def extract_orders_rj_from_text(text: str):
    if not text:
        return [[] for _ in range(5)]
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    sections = [[] for _ in range(5)]
    current_sec_index = None
    for line in lines:
        for pattern, idx in SEC_PATTERNS_RJ:
            if pattern.search(line):
                current_sec_index = idx
                break
        if current_sec_index is None:
            continue

        m = PATTERN_SEQ_INTERNO_FROTA_RJ.search(line)
        if m:
            frota_cand = m.group(1)
            n_norm = str(int(frota_cand))
            if n_norm in FROTAS_VALIDAS_STR and n_norm not in sections[current_sec_index]:
                sections[current_sec_index].append(n_norm)
            continue

        nums = PATTERN_ISOLATED_NUM_RJ.findall(line)
        if nums:
            chosen = None
            for n in nums:
                try:
                    n_norm = str(int(n))
                except Exception:
                    continue
                if n_norm in FROTAS_VALIDAS_STR:
                    chosen = n_norm
                    break
            if chosen and chosen not in sections[current_sec_index]:
                sections[current_sec_index].append(chosen)
    return sections

def extract_rj_from_uploaded_pdf(uploaded_pdf):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
        tmp.write(uploaded_pdf.read())
        tmp_path = tmp.name
    try:
        text = extract_text(tmp_path)
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass
    return extract_orders_rj_from_text(text)

SECTION_LABELS_SJP = [
    "LONGA MT-GO-DF-TO",
    "SUPER CURTA",
    "SUPER-LONGA MA-PA-AC-RO",
    "MEDIA SP - RJ - MS",
    "CURTA - PR - PORTO",
    "INTERNACIONAL",
]

SECTION_TITLES_SJP_REGEX = [
    r"LONGA\s+MT-?GO-?DF-?TO",
    r"SUPER\s+CURTA",
    r"SUPER[-\s]*LONGA\s+MA-?PA-?AC-?RO",
    r"MEDIA\s+SP\s*-\s*RJ\s*-\s*MS",
    r"CURTA\s*-\s*PR\s*-\s*PORTO",
    r"INTERNACIONAL",
]
SECTION_PATTERNS_SJP = [re.compile(p, re.IGNORECASE) for p in SECTION_TITLES_SJP_REGEX]

PATTERN_SEQ_INTERNO_FROTA_SJP = re.compile(
    r'(?:\bSIM\b\s+)?\b\d+\b\s+\b\d+\.\d+\b\s+(\d{2,6})\b',
    re.IGNORECASE
)
PATTERN_ISOLATED_NUM_SJP = re.compile(r'(?<!\.)\b\d{2,6}\b(?!\.)')

def split_text_into_sections_sjp(text: str):
    positions = []
    for pat in SECTION_PATTERNS_SJP:
        m = pat.search(text)
        positions.append(m.start() if m else -1)
    if all(p == -1 for p in positions):
        return []
    found = [(pos, i) for i, pos in enumerate(positions) if pos != -1]
    found.sort(key=lambda x: x[0])
    sections = []
    for i, (pos, idx) in enumerate(found):
        start = pos
        end = found[i + 1][0] if i + 1 < len(found) else len(text)
        sections.append((idx, text[start:end]))
    blocks = [""] * len(SECTION_LABELS_SJP)
    for idx, blk in sections:
        blocks[idx] = blk
    return blocks

def extract_fleets_from_block_sjp(block_text: str):
    ordered = []
    seen = set()
    for line in block_text.splitlines():
        line = line.strip()
        if not line:
            continue
        m = PATTERN_SEQ_INTERNO_FROTA_SJP.search(line)
        if m:
            frota_cand = m.group(1)
            try:
                n_norm = str(int(frota_cand))
            except Exception:
                n_norm = None
            if n_norm and n_norm in FROTAS_VALIDAS_STR and n_norm not in seen:
                seen.add(n_norm)
                ordered.append(n_norm)
            continue

        nums = PATTERN_ISOLATED_NUM_SJP.findall(line)
        if nums:
            chosen = None
            for n in nums:
                try:
                    n_norm = str(int(n))
                except Exception:
                    continue
                if n_norm in FROTAS_VALIDAS_STR:
                    chosen = n_norm
                    break
            if chosen and chosen not in seen:
                seen.add(chosen)
                ordered.append(chosen)
    return ordered

def extract_orders_sjp_from_text(text: str):
    if not text or len(text.strip()) < 5:
        return [[] for _ in SECTION_LABELS_SJP]
    blocks = split_text_into_sections_sjp(text)
    if not blocks:
        fallback = []
        seen = set()
        for line in text.splitlines():
            nums = PATTERN_ISOLATED_NUM_SJP.findall(line)
            for n in nums:
                n_norm = str(int(n))
                if n_norm in FROTAS_VALIDAS_STR and n_norm not in seen:
                    seen.add(n_norm)
                    fallback.append(n_norm)
        return [fallback for _ in range(len(SECTION_LABELS_SJP))]
    return [extract_fleets_from_block_sjp(blk) if blk else [] for blk in blocks]

def extract_sjp_from_uploaded_pdf(uploaded_pdf):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
        tmp.write(uploaded_pdf.read())
        tmp_path = tmp.name
    try:
        text = extract_text(tmp_path)
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass
    return extract_orders_sjp_from_text(text)

def normalize_fleet_list(raw: str):
    partes = [p.strip() for p in (raw or "").split(",") if p.strip()]
    normalized = []
    for p in partes:
        digits = re.sub(r"\D", "", p)
        normalized.append(str(int(digits)) if digits else p)
    return normalized

def reset_state_preserve_filial():
    defaults = {
        "orders": [],
        "queue_super_longa": [],
        "queue_longa": [],
        "queue_media": [],
        "queue_curta": [],
        "selected_fleets": [],
        "frotas_destacadas": [],
        "frotas_removidas": set(),
        "registro_pegaram_carga": [],
        "registro_excluidas": [],
        "generated_pdf_bytes": None,
        "generated_pdf_filename": None,
        "mode_shared": True,
        "filial": None,
    }
    for k, v in defaults.items():
        st.session_state[k] = v

def show_queue(label: str, queue_list):
    st.subheader(label)
    if not queue_list:
        st.info("Fila vazia.")
        return
    data = []
    for idx, f in enumerate(queue_list, start=1):
        destaque = "⭐" if f in st.session_state.frotas_destacadas else ""
        data.append({"Posição": idx, "Frota": f, "Destaque": destaque})
    st.dataframe(pd.DataFrame(data), hide_index=True, use_container_width=True)

def rebuild_queues(filial: str, normalized: list[str]):
    if filial == "RJ":
        mapping = {"super_longa": 1, "longa": 2, "media": 3, "curta": 4}
    else:
        mapping = {"super_longa": 2, "longa": 0, "media": 3, "curta": 4}

    removidas = st.session_state.get("frotas_removidas", set())

    present_in_sections = set()
    for _, sec_idx in mapping.items():
        if sec_idx < len(st.session_state.orders):
            present_in_sections.update(st.session_state.orders[sec_idx])

    def build_queue_from_pdf(order_idx):
        if order_idx >= len(st.session_state.orders):
            return []
        return [f for f in st.session_state.orders[order_idx] if (f in normalized) and (f not in removidas)]

    st.session_state.queue_super_longa = build_queue_from_pdf(mapping["super_longa"])
    st.session_state.queue_longa = build_queue_from_pdf(mapping["longa"])
    st.session_state.queue_media = build_queue_from_pdf(mapping["media"])
    st.session_state.queue_curta = build_queue_from_pdf(mapping["curta"])
    st.session_state.selected_fleets = [f for f in normalized if (f in present_in_sections) and (f not in removidas)]
    st.session_state.frotas_destacadas = [f for f in st.session_state.frotas_destacadas if f in st.session_state.selected_fleets]

def handle_remove_frota(user: str, filial: str, raw: str, is_carga: bool, fila_sel: str | None = None):
    if not st.session_state.orders or all(len(o) == 0 for o in st.session_state.orders):
        st.warning("Leia primeiro o arquivo PDF.")
        return

    raw = (raw or "").strip()
    if not raw:
        st.warning("Digite a frota.")
        return
    if "," in raw:
        st.warning("Digite apenas UMA frota.")
        return

    digits = re.sub(r"\D", "", raw)
    if not digits:
        st.warning("Frota inválida.")
        return

    f_norm = str(int(digits))
    removed_any = False

    for name in ["selected_fleets", "queue_longa", "queue_super_longa", "queue_media", "queue_curta"]:
        lst = st.session_state.get(name, [])
        if f_norm in lst:
            lst.remove(f_norm)
            removed_any = True

    if removed_any:
        st.session_state.frotas_removidas.add(f_norm)

        ts_human = datetime.now().strftime("%d/%m %H:%M")
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if is_carga:
            st.session_state.registro_pegaram_carga.append({"frota": f_norm, "fila": fila_sel, "ts": ts_human})
            history_append({"ts": ts, "user": user, "filial": filial, "action": "pegou_carga", "detail": f"{f_norm} ({fila_sel})"})
            st.success(f"Frota {f_norm} removida (pegou carga).")
        else:
            st.session_state.registro_excluidas.append({"frota": f_norm, "ts": ts_human})
            history_append({"ts": ts, "user": user, "filial": filial, "action": "excluida", "detail": f_norm})
            st.success(f"Frota {f_norm} excluída.")

        if f_norm in st.session_state.frotas_destacadas:
            st.session_state.frotas_destacadas.remove(f_norm)

        if st.session_state.get("mode_shared"):
            persist_to_shared(filial)
    else:
        st.info(f"{f_norm} não encontrada nas filas.")

def generate_pdf_registro(suffix: str):
    if not (st.session_state.registro_pegaram_carga or st.session_state.registro_excluidas):
        return None, None

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    elems = []

    elems.append(Paragraph(f"RELATÓRIO DE MOVIMENTAÇÕES - {suffix}", styles["Heading1"]))
    elems.append(Paragraph(datetime.now().strftime("%d/%m/%Y %H:%M"), styles["Normal"]))
    elems.append(Spacer(1, 12))

    if st.session_state.registro_pegaram_carga:
        elems.append(Paragraph("FROTAS QUE PEGARAM CARGA", styles["Heading2"]))
        data = [["Data/Hora", "Frota", "Fila"]]
        for r in st.session_state.registro_pegaram_carga:
            data.append([r["ts"], r["frota"], r.get("fila", "")])
        t = Table(data, colWidths=[110, 80, 170])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
        ]))
        elems.append(t)
        elems.append(Spacer(1, 18))

    if st.session_state.registro_excluidas:
        elems.append(Paragraph("FROTAS EXCLUÍDAS", styles["Heading2"]))
        data2 = [["Data/Hora", "Frota"]]
        for r in st.session_state.registro_excluidas:
            data2.append([r["ts"], r["frota"]])
        t2 = Table(data2, colWidths=[140, 80])
        t2.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
        ]))
        elems.append(t2)

    doc.build(elems)
    buffer.seek(0)
    filename = f"registro_{suffix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    return buffer.getvalue(), filename

def main():
    st.set_page_config(page_title="Gerenciador de Filas – Web", layout="wide")
    st.markdown(CSS, unsafe_allow_html=True)

    if "orders" not in st.session_state:
        reset_state_preserve_filial()

    user = auth_screen()

    st.sidebar.markdown("## 👤 Sessão")
    st.sidebar.write(f"Usuário: **{user}**")
    if st.sidebar.button("Sair"):
        st.session_state.pop("auth_user", None)
        st.rerun()

    st.title("🚛 Gerenciador de Filas – Versão Web")
    st.markdown('<div class="small-muted">RJ e SJP • login/cadastro local • histórico • multiusuário</div>', unsafe_allow_html=True)

    st.sidebar.markdown("## 👥 Multiusuário")
    st.session_state.mode_shared = st.sidebar.toggle("Fila compartilhada por filial", value=st.session_state.get("mode_shared", True))

    if st.session_state.filial is None:
        st.write("Selecione abaixo qual fila deseja utilizar (fluxo igual ao programa desktop).")
        col_a, col_b = st.columns(2)
        with col_a:
            if st.button("➡️ Iniciar Fila RJ", use_container_width=True):
                reset_state_preserve_filial()
                st.session_state.filial = "RJ"
                if st.session_state.mode_shared:
                    load_from_shared("RJ")
                st.rerun()
        with col_b:
            if st.button("➡️ Iniciar Fila SJP", use_container_width=True):
                reset_state_preserve_filial()
                st.session_state.filial = "SJP"
                if st.session_state.mode_shared:
                    load_from_shared("SJP")
                st.rerun()
        st.info("Dica: você pode ativar/desativar a fila compartilhada na barra lateral.")
        return

    filial = st.session_state.filial

    st.sidebar.markdown("## 📌 Navegação")
    if st.sidebar.button("Voltar ao início"):
        st.session_state.filial = None
        st.rerun()

    st.markdown(f"### Filial selecionada: **{filial}**")

    tab_arquivo, tab_select, tab_ops, tab_hist = st.tabs(
        ["📄 Arquivo", "🧾 Selecionar & Montar", "✔ Gestão & Relatório", "🕓 Histórico"]
    )

    with tab_arquivo:
        st.subheader("Leitura do PDF")
        uploaded_pdf = st.file_uploader("Selecione o PDF da fila", type=["pdf"], key="pdf_uploader")

        if st.button("Ler PDF", type="primary"):
            if not uploaded_pdf:
                st.warning("Selecione um arquivo PDF primeiro.")
            else:
                if filial == "RJ":
                    orders = extract_rj_from_uploaded_pdf(uploaded_pdf)
                    section_labels = SECTION_TITLES_RJ
                else:
                    orders = extract_sjp_from_uploaded_pdf(uploaded_pdf)
                    section_labels = SECTION_LABELS_SJP

                if not orders or all(len(o) == 0 for o in orders):
                    st.error("Não foi possível ler o arquivo (nenhuma frota identificada).")
                else:
                    st.session_state.orders = orders
                    st.session_state.queue_super_longa = []
                    st.session_state.queue_longa = []
                    st.session_state.queue_media = []
                    st.session_state.queue_curta = []
                    st.session_state.selected_fleets = []
                    st.session_state.frotas_destacadas = []
                    st.session_state.registro_pegaram_carga = []
                    st.session_state.registro_excluidas = []
                    st.success("Arquivo lido com sucesso.")

                    history_append({"ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                    "user": user, "filial": filial, "action": "ler_pdf", "detail": "PDF carregado"})
                    if st.session_state.mode_shared:
                        persist_to_shared(filial)

                    rows = []
                    for sec_idx, sec_list in enumerate(orders):
                        sec_name = section_labels[sec_idx] if sec_idx < len(section_labels) else f"Seção {sec_idx}"
                        for pos, frota in enumerate(sec_list, start=1):
                            rows.append({"Seção": sec_name, "Posição": pos, "Frota": frota})
                    if rows:
                        st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)

    with tab_select:
        st.subheader("Montagem das Filas")
        fleets_input = st.text_input("Digite as frotas separadas por vírgula")

        if st.button("Montar Filas"):
            if not st.session_state.orders or all(len(o) == 0 for o in st.session_state.orders):
                st.warning("Leia primeiro o arquivo PDF na aba 'Arquivo'.")
            elif not fleets_input.strip():
                st.warning("Digite as frotas desejadas.")
            else:
                normalized = normalize_fleet_list(fleets_input)
                rebuild_queues(filial, normalized)

                history_append({"ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "user": user, "filial": filial, "action": "montar_filas",
                                "detail": f"{len(st.session_state.selected_fleets)} frotas"})
                if st.session_state.mode_shared:
                    persist_to_shared(filial)

                st.success("Filas montadas (ordem do PDF).")

        st.markdown("---")
        st.subheader("Destaque de Frotas")
        destacar_input = st.text_input("Destacar frotas (separadas por vírgula, após montar as filas)")
        if st.button("Atualizar Destaques"):
            parts = normalize_fleet_list(destacar_input)
            for f in parts:
                if f not in st.session_state.selected_fleets:
                    continue
                if f in st.session_state.frotas_destacadas:
                    st.session_state.frotas_destacadas.remove(f)
                else:
                    st.session_state.frotas_destacadas.append(f)

            history_append({"ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "user": user, "filial": filial, "action": "destaques",
                            "detail": ", ".join(parts) if parts else ""})
            if st.session_state.mode_shared:
                persist_to_shared(filial)

            st.success("Frotas destacadas atualizadas.")

        st.markdown("---")
        st.subheader("Visualização das Filas")
        col1, col2 = st.columns(2)
        with col1:
            show_queue("1 - SUPER LONGA", st.session_state.queue_super_longa)
            show_queue("2 - LONGA", st.session_state.queue_longa)
        with col2:
            show_queue("3 - MÉDIA", st.session_state.queue_media)
            show_queue("4 - CURTA", st.session_state.queue_curta)

    with tab_ops:
        st.subheader("Gestão das Filas")
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("#### ✅ Frota que pegou carga")
            frota_pego = st.text_input("Frota", key="frota_pego")
            fila_sel = st.selectbox("Fila da qual saiu", ["Super Longa", "Longa", "Média", "Curta"], key="fila_sel")
            if st.button("Remover (Pegou Carga)", type="primary"):
                handle_remove_frota(user, filial, frota_pego, is_carga=True, fila_sel=fila_sel)

        with col2:
            st.markdown("#### ❌ Frota excluída")
            frota_exc = st.text_input("Frota", key="frota_excluida")
            if st.button("Excluir Frota"):
                handle_remove_frota(user, filial, frota_exc, is_carga=False, fila_sel=None)

        st.markdown("---")
        st.subheader("Registros atuais")

        if st.session_state.registro_pegaram_carga:
            st.markdown("### Frotas que pegaram carga")
            st.dataframe(pd.DataFrame(st.session_state.registro_pegaram_carga), hide_index=True, use_container_width=True)

        if st.session_state.registro_excluidas:
            st.markdown("### Frotas excluídas")
            st.dataframe(pd.DataFrame(st.session_state.registro_excluidas), hide_index=True, use_container_width=True)

        st.markdown("---")
        st.subheader("Gerar PDF de Registro")

        if st.button("Gerar PDF (Registro)"):
            if not (st.session_state.registro_pegaram_carga or st.session_state.registro_excluidas):
                st.info("Sem dados para gerar PDF.")
            else:
                pdf_bytes, filename = generate_pdf_registro(filial)
                if pdf_bytes:
                    st.session_state.generated_pdf_bytes = pdf_bytes
                    st.session_state.generated_pdf_filename = filename
                    history_append({"ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                    "user": user, "filial": filial, "action": "gerar_pdf", "detail": filename})
                    st.success("PDF gerado. Use o botão abaixo para baixar.")

        if st.session_state.get("generated_pdf_bytes"):
            st.download_button(
                label="Baixar PDF do Registro",
                data=st.session_state.generated_pdf_bytes,
                file_name=st.session_state.generated_pdf_filename,
                mime="application/pdf",
            )

    with tab_hist:
        st.subheader("Histórico (ações)")
        c1, c2 = st.columns(2)
        with c1:
            filtro_user = st.selectbox("Usuário", ["Todos", user], index=1)
        with c2:
            filtro_filial = st.selectbox("Filial", ["Todas", "RJ", "SJP"], index=0)

        dfh = history_df(
            user=None if filtro_user == "Todos" else user,
            filial=None if filtro_filial == "Todas" else filtro_filial
        )
        st.dataframe(dfh, hide_index=True, use_container_width=True)
        st.download_button("Baixar histórico (CSV)", data=dfh.to_csv(index=False).encode("utf-8"), file_name="historico.csv", mime="text/csv")

if __name__ == "__main__":
    main()
