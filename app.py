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
HISTORY_PATH = _safe_path("history.json")  # legado (não usado)
def _history_path_for_user(username: str) -> str:
    u = re.sub(r"[^a-zA-Z0-9_.-]", "_", (username or "anon"))
    return _safe_path(f"history_{u}.json")

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


# --------------------------- SESSÕES (1 login por usuário) + LOG ADMIN ---------------------------

SESSIONS_PATH = _safe_path("sessions.json")
ADMIN_LOG_PATH = _safe_path("admin_log.json")
SESSION_TIMEOUT_MIN = 5  # libera sozinho após 5 min sem atividade

def _now_ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def _minutes_diff(ts_str: str) -> float:
    try:
        dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
        return (datetime.now() - dt).total_seconds() / 60.0
    except Exception:
        return 9999.0

def _sessions_load() -> dict:
    return _load_json(SESSIONS_PATH, {"locks": {}})

def _sessions_save(data: dict) -> None:
    _atomic_write_json(SESSIONS_PATH, data)

def _sessions_cleanup(locks: dict) -> dict:
    for u in list(locks.keys()):
        if _minutes_diff((locks.get(u) or {}).get("last_seen", "")) > SESSION_TIMEOUT_MIN:
            locks.pop(u, None)
    return locks

def get_session_id() -> str:
    if "session_id" not in st.session_state:
        st.session_state.session_id = secrets.token_hex(16)
    return st.session_state.session_id

def lock_user(username: str, session_id: str) -> tuple[bool, str]:
    """Trava: só 1 sessão ativa por usuário."""
    data = _sessions_load()
    locks = _sessions_cleanup(data.get("locks", {}))

    rec = locks.get(username)
    if rec and rec.get("session_id") != session_id:
        return False, "Usuário já está conectado em outro dispositivo. Tente novamente em alguns minutos."

    locks[username] = {"session_id": session_id, "last_seen": _now_ts()}
    data["locks"] = locks
    _sessions_save(data)
    return True, ""

def touch_lock(username: str, session_id: str) -> None:
    data = _sessions_load()
    locks = _sessions_cleanup(data.get("locks", {}))
    rec = locks.get(username)
    if rec and rec.get("session_id") == session_id:
        rec["last_seen"] = _now_ts()
        locks[username] = rec
        data["locks"] = locks
        _sessions_save(data)

def unlock_user(username: str, session_id: str) -> None:
    data = _sessions_load()
    locks = data.get("locks", {})
    rec = locks.get(username)
    if rec and rec.get("session_id") == session_id:
        locks.pop(username, None)
        data["locks"] = locks
        _sessions_save(data)

def online_users_df() -> pd.DataFrame:
    data = _sessions_load()
    locks = _sessions_cleanup(data.get("locks", {}))
    rows = []
    for u, rec in locks.items():
        last_seen = rec.get("last_seen", "")
        mins = _minutes_diff(last_seen)
        status = "online" if mins <= SESSION_TIMEOUT_MIN else "expirado"
        rows.append({"usuario": u, "ultima_atividade": last_seen, "status": status})
    if not rows:
        return pd.DataFrame(columns=["usuario", "ultima_atividade", "status"])
    return pd.DataFrame(rows).sort_values(["status", "usuario"])

def admin_log_append(actor: str, action: str, detail: str = "") -> None:
    data = _load_json(ADMIN_LOG_PATH, {"events": []})
    data["events"].append({"ts": _now_ts(), "actor": actor, "action": action, "detail": detail})
    data["events"] = data["events"][-5000:]
    _atomic_write_json(ADMIN_LOG_PATH, data)

def admin_force_logout(actor: str, target_user: str) -> bool:
    data = _sessions_load()
    locks = _sessions_cleanup(data.get("locks", {}))
    if target_user in locks:
        locks.pop(target_user, None)
        data["locks"] = locks
        _sessions_save(data)
        admin_log_append(actor, "force_logout", target_user)
        return True
    return False

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


def ensure_admin_user():
    """Garante que o usuário admin exista (mesmo se não tiver cadastro)."""
    ADMIN_USERNAME = "mateus.s"
    ADMIN_PASSWORD = "110824"  # troque se quiser
    db = _users_load()
    users = db.get("users", {})
    if ADMIN_USERNAME not in users:
        users[ADMIN_USERNAME] = _hash_password(ADMIN_PASSWORD)
        db["users"] = users
        _users_save(db)

ADMIN_USERS = {"mateus.s"}  # usuários admin fixos

def auth_screen() -> str:
    """Tela inicial: somente LOGIN (1 sessão por usuário). Criação de usuários é feita pelo admin."""
    st.markdown(CSS, unsafe_allow_html=True)
    st.title("🔐 Acesso")
    st.markdown('<div class="small-muted">Entre com seu usuário e senha</div>', unsafe_allow_html=True)
    st.info("⚠️ Cadastro local: em hospedagem gratuita ele pode ser perdido se o app reiniciar.")

    if st.session_state.get("auth_user"):
        return st.session_state["auth_user"]

    users_db = _users_load()
    users = users_db.get("users", {})

    u = st.text_input("Usuário", key="login_user")
    p = st.text_input("Senha", type="password", key="login_pass")

    if st.button("Entrar", type="primary"):
        u = (u or "").strip().lower()
        if not u or not p:
            st.warning("Preencha usuário e senha.")
            st.stop()

        if u not in users:
            st.error("Usuário não encontrado.")
            st.stop()

        if not _verify_password(p, users[u]):
            st.error("Senha incorreta.")
            st.stop()

        sid = get_session_id()
        ok, msg = lock_user(u, sid)
        if not ok:
            st.error(msg)
            st.stop()

        st.session_state["auth_user"] = u
        st.success("Login ok!")
        st.rerun()

    st.stop()

# --------------------------- HISTÓRICO ---------------------------

def history_append(event: dict):
    """Salva histórico por usuário (privado)."""
    username = (event.get("user") or "anon")
    path = _history_path_for_user(username)
    data = _load_json(path, {"events": []})
    data["events"].append(event)
    data["events"] = data["events"][-5000:]
    _atomic_write_json(path, data)

def history_df(requesting_user: str, filial: str | None = None, include_all: bool = False) -> pd.DataFrame:
    """Carrega histórico.
    - Por padrão: somente do usuário logado.
    - Se include_all=True (admin): tenta juntar todos os arquivos history_*.json que existirem.
    """
    rows = []
    if include_all:
        base_dir = os.path.dirname(_history_path_for_user(requesting_user))
        try:
            for fn in os.listdir(base_dir):
                if fn.startswith('history_') and fn.endswith('.json'):
                    d = _load_json(os.path.join(base_dir, fn), {"events": []})
                    rows.extend(d.get('events', []))
        except Exception:
            d = _load_json(_history_path_for_user(requesting_user), {"events": []})
            rows = d.get('events', [])
    else:
        d = _load_json(_history_path_for_user(requesting_user), {"events": []})
        rows = d.get('events', [])

    if filial:
        rows = [r for r in rows if r.get('filial') == filial]

    if not rows:
        return pd.DataFrame(columns=["ts", "user", "filial", "action", "detail"])

    df = pd.DataFrame(rows)
    if 'ts' in df.columns:
        df = df.sort_values('ts', ascending=False)
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

    ensure_admin_user()

    user = auth_screen()

    touch_lock(user, get_session_id())

    st.sidebar.markdown("## 👤 Sessão")
    st.sidebar.write(f"Usuário: **{user}**")
    if st.sidebar.button("Sair"):
        unlock_user(user, get_session_id())
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

    tabs = ["📄 Arquivo", "🧾 Selecionar & Montar", "✔ Gestão & Relatório", "🕓 Histórico"]
    is_admin = user in ADMIN_USERS
    if is_admin:
        tabs.append("👥 Usuários")

    tab_list = st.tabs(tabs)
    tab_arquivo, tab_select, tab_ops, tab_hist = tab_list[:4]
    tab_users = tab_list[4] if is_admin else None

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
        is_admin = user in ADMIN_USERS
        c1, c2 = st.columns(2)
        with c1:
            filtro_filial = st.selectbox("Filial", ["Todas", "RJ", "SJP"], index=0)
        with c2:
            ver_todos = st.toggle("Ver histórico de todos (admin)", value=False, disabled=not is_admin)

        dfh = history_df(
            requesting_user=user,
            filial=None if filtro_filial == "Todas" else filtro_filial,
            include_all=(is_admin and ver_todos),
        )
        st.dataframe(dfh, hide_index=True, use_container_width=True)
        st.download_button(
            "Baixar histórico (CSV)",
            data=dfh.to_csv(index=False).encode("utf-8"),
            file_name="historico.csv",
            mime="text/csv",
        )



    if tab_users is not None:
        with tab_users:
            st.subheader("👥 Gestão de usuários (Admin)")

            db = _users_load()
            users_map = (db.get("users", {}) or {})
            users_list = sorted(list(users_map.keys()))

            st.markdown("### ✅ Criar novo usuário")
            c1, c2, c3 = st.columns(3)
            with c1:
                new_user = st.text_input("Novo usuário", key="new_user").strip().lower()
            with c2:
                new_pass = st.text_input("Senha", type="password", key="new_pass")
            with c3:
                new_pass2 = st.text_input("Confirmar senha", type="password", key="new_pass2")

            if st.button("Criar usuário", type="primary"):
                if not new_user or not new_pass or not new_pass2:
                    st.warning("Preencha usuário e senha.")
                elif len(new_user) < 3:
                    st.warning("Usuário muito curto.")
                elif new_user in users_map:
                    st.error("Esse usuário já existe.")
                elif new_pass != new_pass2:
                    st.error("As senhas não conferem.")
                elif len(new_pass) < 4:
                    st.warning("Senha muito curta (mínimo 4).")
                else:
                    users_map[new_user] = _hash_password(new_pass)
                    db["users"] = users_map
                    _users_save(db)
                    admin_log_append(user, "create_user", f"criou {new_user}")
                    st.success(f"Usuário '{new_user}' criado.")
                    st.rerun()

            st.markdown("---")
            st.markdown("### 🔑 Resetar senha")
            if users_list:
                target = st.selectbox("Usuário", users_list, key="reset_user")
                rp1 = st.text_input("Nova senha", type="password", key="reset_p1")
                rp2 = st.text_input("Confirmar nova senha", type="password", key="reset_p2")
                if st.button("Resetar senha", key="btn_reset"):
                    if not rp1 or not rp2:
                        st.warning("Preencha a nova senha.")
                    elif rp1 != rp2:
                        st.error("As senhas não conferem.")
                    elif len(rp1) < 4:
                        st.warning("Senha muito curta (mínimo 4).")
                    else:
                        users_map[target] = _hash_password(rp1)
                        db["users"] = users_map
                        _users_save(db)
                        admin_log_append(user, "reset_password", f"resetou senha de {target}")
                        st.success(f"Senha de '{target}' resetada.")
                        st.rerun()
            else:
                st.info("Nenhum usuário cadastrado ainda.")

            st.markdown("---")
            st.markdown("### ❌ Excluir usuário")
            safe_users = [u for u in users_list if u != "mateus.s"]
            del_user = st.selectbox("Selecione um usuário", ["(nenhum)"] + safe_users, key="del_user")
            if st.button("Excluir usuário", key="btn_del"):
                if del_user == "(nenhum)":
                    st.info("Selecione um usuário.")
                elif del_user not in users_map:
                    st.error("Usuário não encontrado.")
                else:
                    users_map.pop(del_user, None)
                    db["users"] = users_map
                    _users_save(db)
                    admin_log_append(user, "delete_user", f"excluiu {del_user}")
                    st.success(f"Usuário '{del_user}' excluído.")
                    st.rerun()

            st.markdown("---")
            st.markdown("### 🟢 Usuários online")
            df_on = online_users_df()
            st.dataframe(df_on, hide_index=True, use_container_width=True)

            st.markdown("### 🚫 Derrubar sessão")
            online_list = df_on["usuario"].tolist() if not df_on.empty else []
            target_online = st.selectbox("Usuário online", ["(nenhum)"] + online_list, key="force_user")
            if st.button("Derrubar sessão", key="btn_force"):
                if target_online == "(nenhum)":
                    st.info("Selecione um usuário online.")
                else:
                    ok = admin_force_logout(user, target_online)
                    if ok:
                        st.success(f"Sessão de '{target_online}' derrubada.")
                        st.rerun()
                    else:
                        st.info("Nenhuma sessão ativa encontrada.")

            st.markdown("---")
            st.markdown("### 🧾 Log do Admin (quem criou/resetou/excluiu/derrubou)")
            log = _load_json(ADMIN_LOG_PATH, {"events": []}).get("events", [])
            df_log = pd.DataFrame(log) if log else pd.DataFrame(columns=["ts","actor","action","detail"])
            if not df_log.empty:
                df_log = df_log.sort_values("ts", ascending=False)
            st.dataframe(df_log, hide_index=True, use_container_width=True)
            st.download_button(
                "Baixar log admin (CSV)",
                data=df_log.to_csv(index=False).encode("utf-8"),
                file_name="admin_log.csv",
                mime="text/csv",
            )

            st.caption("⚠️ As senhas não são exibidas (ficam armazenadas apenas como hash).")


if __name__ == "__main__":
    main()
