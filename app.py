
# -*- coding: utf-8 -*-
# app_final_v6.py — versão ajustada (apenas extração de Motorista e Última Viagem)

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

# Libs para PDF
from pdfminer.high_level import extract_text

# Libs para gerar PDF de registro
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer


# ------------------------------------------------------------
# CSS (mantido)
# ------------------------------------------------------------
CSS = """
"""

# ------------------------------------------------------------
# Caminhos e utilidades (mantidos)
# ------------------------------------------------------------
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


# ------------------------------------------------------------
# Sessões + Log Admin (mantidos)
# ------------------------------------------------------------
SESSIONS_PATH = _safe_path("sessions.json")
ADMIN_LOG_PATH = _safe_path("admin_log.json")
SESSION_TIMEOUT_MIN = 5

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


# ------------------------------------------------------------
# Auth local (mantido)
# ------------------------------------------------------------
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
    SEED_USERS = [
        {"username": "mateus.souza", "password": "Start@@2016", "force_password": True},
        {"username": "denis", "password": "112233", "force_password": False},
        {"username": "henrique", "password": "112233", "force_password": False},
    ]
    db = _users_load()
    users = db.get("users", {}) or {}
    changed = False
    for item in SEED_USERS:
        uname = (item.get("username") or "").strip().lower()
        pwd = item.get("password") or ""
        force = bool(item.get("force_password"))
        if not uname:
            continue
        if uname not in users:
            users[uname] = _hash_password(pwd)
            changed = True
        elif force:
            users[uname] = _hash_password(pwd)
            changed = True
    if changed:
        db["users"] = users
        _users_save(db)

ADMIN_USERS = {"mateus.souza"}

def auth_screen() -> str:
    st.markdown(CSS, unsafe_allow_html=True)
    st.title("🔐 Acesso")
    st.markdown('<p>Entre com seu usuário e senha</p>', unsafe_allow_html=True)
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
    return ""


# ======================================================================
# ⚙️ AJUSTE: PADRÕES DE LINHA (RJ + PR) e HELPERS DE META (NOVOS)
# ======================================================================

# PR/SJP — Linha COMPLETA com DATA + UF + MUNICÍPIO
META_ROW_RE_PR = re.compile(
    r'^(?P<frota>\d{1,3})\s+'
    r'(?P<data>\d{2}/\d{2}/\d{4})\s+'
    r'(?P<motorista>[A-ZÀ-Ü][A-ZÀ-Ü \.\'-]+?)\s+'
    r'(?P<uf>[A-Z]{2})\s+'
    r'(?P<municipio>[A-ZÀ-Ü \.\'-]+?)\s+'
    r'(?P<ult>\d{2,3}\.\d{3})\s+'
    r'(?:SIM\s+)?'
    r'(?P<seq>\d{1,3})'
    r'(?:\s+(?P<obs>DISPONIVEL|EM VIAGEM))?'
    r'$',
    re.UNICODE
)

# PR/SJP — Linha sem DATA/UF/MUNICÍPIO (SUPER CURTA/INTERNACIONAL simples)
META_ROW_RE_PR_NO_DATE = re.compile(
    r'^(?P<frota>\d{1,3})\s+'
    r'(?P<motorista>[A-ZÀ-Ü][A-ZÀ-Ü \.\'-]+?)\s+'
    r'(?P<ult>\d{2,3}\.\d{3})\s+'
    r'(?:SIM\s+)?'
    r'(?P<seq>\d{1,3})'
    r'(?:\s+(?P<obs>DISPONIVEL|EM VIAGEM))?'
    r'$',
    re.UNICODE
)

# RJ — Linha com DATA
META_ROW_RE_RJ = re.compile(
    r'^(?P<frota>\d{1,3})\s+'
    r'(?P<data>\d{2}/\d{2}/\d{4})\s+'
    r'(?P<motorista>[A-ZÀ-Ü][A-ZÀ-Ü \.\'-]+?)\s+'
    r'(?P<ult>\d{2,3}\.\d{3})\s+'
    r'(?:SIM\s+)?'
    r'(?P<seq>\d{1,3})'
    r'(?:\s+(?P<obs>DISPONIVEL|EM VIAGEM))?'
    r'$',
    re.UNICODE
)

# RJ — Linha curta sem DATA
META_ROW_RE_RJ_NO_DATE = re.compile(
    r'^(?P<frota>\d{1,3})\s+'
    r'(?P<motorista>[A-ZÀ-Ü][A-ZÀ-Ü \.\'-]+?)\s+'
    r'(?P<ult>\d{2,3}\.\d{3})\s+'
    r'(?:SIM\s+)?'
    r'(?P<seq>\d{1,3})'
    r'(?:\s+(?P<obs>DISPONIVEL|EM VIAGEM))?'
    r'$',
    re.UNICODE
)

# Âncora Frota+Data para fallback
FROTA_DATE_RE = re.compile(r'\b(?P<frota>\d{1,3})\s+(?P<data>\d{2}/\d{2}/\d{4})\b')

def _parse_dt(s: str):
    try:
        return datetime.strptime(s, "%d/%m/%Y")
    except Exception:
        return None

def _ok_frota(f: str) -> bool:
    """Valida faixas de frota. Nunca aceitar números com ponto como frota."""
    try:
        n = int(re.sub(r"\D", "", f) or "0")
    except Exception:
        return False
    return (200 <= n <= 470) or (501 <= n <= 576)

def _fix_glued_date(s: str) -> str:
    """Insere espaço quando a data vier colada ao texto."""
    if not s:
        return s
    return re.sub(r'([A-Za-zÀ-ü])(\d{2}/\d{2}/\d{4})', r'\1 \2', s)

def _cleanup_tail(s: str) -> str:
    """Remove tokens que atrapalham e normaliza espaços no tail após Frota+Data."""
    s = re.sub(r'\bSIM\b', ' ', s)
    s = re.sub(r'\bPRES(?:ENÇA|)?\b', ' ', s, flags=re.IGNORECASE)
    s = re.sub(r'\s+', ' ', (s or '')).strip()
    return s


# ======================================================================
# ⚙️ AJUSTE: EXTRAÇÃO DE META (Motorista + Última Viagem consolidada)
# ======================================================================
def extract_meta_from_text(text: str, orders: list[list[str]] | None = None, filial: str | None = None) -> dict:
    """
    Extrai meta por frota:
      meta[frota] = {
         "motorista": str,
         "ult_viag": "dd/mm/aaaa" | "NA",
         "uf": "UF|NA",
         "municipio": str|NA
      }

    Estratégia:
    - Varre TODO o texto do PDF.
    - Casa linhas RJ/PR em ambos os formatos (com/sem DATA/UF/Municipio).
    - Para cada frota, escolhe a DATA mais recente e atualiza o MOTORISTA correspondente.
    - NÃO remove números com ponto antes de parsear (para não perder 'Ult. Viagem').
    """
    meta: dict[str, dict] = {}
    if not text or len(text.strip()) < 5:
        return meta

    for raw in text.splitlines():
        line = (raw or "").strip()
        if not line:
            continue

        # Normalizações
        line = _fix_glued_date(line)
        line = re.sub(r"\s+", " ", line).strip()

        rec = None

        # 1) PR com DATA + UF + Município
        m = META_ROW_RE_PR.match(line)
        if m:
            rec = {
                "frota": m.group("frota"),
                "data":  m.group("data"),
                "motorista": (m.group("motorista") or "").strip(),
                "uf":   m.group("uf"),
                "municipio": (m.group("municipio") or "").strip(),
            }

        # 2) PR sem DATA
        if not rec:
            m = META_ROW_RE_PR_NO_DATE.match(line)
            if m:
                rec = {
                    "frota": m.group("frota"),
                    "data":  "NA",
                    "motorista": (m.group("motorista") or "").strip(),
                    "uf":   "NA",
                    "municipio": "NA",
                }

        # 3) RJ com DATA
        if not rec:
            m = META_ROW_RE_RJ.match(line)
            if m:
                rec = {
                    "frota": m.group("frota"),
                    "data":  m.group("data"),
                    "motorista": (m.group("motorista") or "").strip(),
                    "uf":   "NA",
                    "municipio": "NA",
                }

        # 4) RJ sem DATA
        if not rec:
            m = META_ROW_RE_RJ_NO_DATE.match(line)
            if m:
                rec = {
                    "frota": m.group("frota"),
                    "data":  "NA",
                    "motorista": (m.group("motorista") or "").strip(),
                    "uf":   "NA",
                    "municipio": "NA",
                }

        # 5) Fallback: Frota + Data e extrair tail
        if not rec:
            mfd = FROTA_DATE_RE.search(line)
            if mfd:
                frota = mfd.group("frota")
                data  = mfd.group("data")
                tail  = _cleanup_tail(line[mfd.end():])
                muf   = re.search(r'\b([A-Z]{2})\b', tail)
                if muf:
                    uf = muf.group(1)
                    motorista = tail[:muf.start()].strip()
                    municipio = tail[muf.end():].strip()
                else:
                    uf, municipio = "NA", "NA"
                    motorista = tail.strip()
                rec = {
                    "frota": frota,
                    "data":  data,
                    "motorista": motorista,
                    "uf":   uf,
                    "municipio": municipio,
                }

        if rec:
            frota_digits = re.sub(r"\D", "", rec["frota"] or "")
            if not frota_digits or not _ok_frota(frota_digits):
                continue
            frota = str(int(frota_digits))

            new_dt = _parse_dt(rec["data"]) if rec["data"] != "NA" else None
            cur = meta.get(frota)

            if not cur:
                meta[frota] = {
                    "motorista": rec["motorista"] or "NA",
                    "ult_viag":  rec["data"] or "NA",
                    "uf":        rec["uf"] or "NA",
                    "municipio": rec["municipio"] or "NA",
                }
                continue

            # Complementa UF/Municipio se estavam NA
            if (cur.get("uf") in (None, "", "NA")) and (rec["uf"] not in ("", "NA")):
                cur["uf"] = rec["uf"]
            if (cur.get("municipio") in (None, "", "NA")) and (rec["municipio"] not in ("", "NA")):
                cur["municipio"] = rec["municipio"]

            # Mantém data mais recente e motorista correspondente
            cur_dt = _parse_dt(cur.get("ult_viag", "NA")) if cur.get("ult_viag") != "NA" else None
            if new_dt and (cur_dt is None or new_dt > cur_dt):
                cur["ult_viag"] = rec["data"]
                if rec["motorista"] not in ("", "NA"):
                    cur["motorista"] = rec["motorista"]
            else:
                if (cur.get("motorista") in (None, "", "NA")) and (rec["motorista"] not in ("", "NA")):
                    cur["motorista"] = rec["motorista"]

            meta[frota] = cur

    return meta


# ------------------------------------------------------------
# Histórico (mantido)
# ------------------------------------------------------------
def _history_path_for_user(username: str) -> str:
    u = re.sub(r"[^a-zA-Z0-9_.-]", "_", (username or "anon"))
    return _safe_path(f"history_{u}.json")

def history_append(event: dict):
    username = (event.get("user") or "anon")
    path = _history_path_for_user(username)
    data = _load_json(path, {"events": []})
    data["events"].append(event)
    data["events"] = data["events"][-5000:]
    _atomic_write_json(path, data)

def history_df(requesting_user: str, filial: str | None = None, include_all: bool = False) -> pd.DataFrame:
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


# ------------------------------------------------------------
# Estado compartilhado (mantido)
# ------------------------------------------------------------
SHARED_STATE_PATH = _safe_path("shared_state.json")

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
        "queue_internacional": st.session_state.get("queue_internacional", []),
        "queue_super_curta": st.session_state.get("queue_super_curta", []),
        "selected_fleets": st.session_state.selected_fleets,
        # extras / 500
        "queue_super_longa_500": st.session_state.get("queue_super_longa_500", []),
        "queue_longa_500": st.session_state.get("queue_longa_500", []),
        "queue_media_500": st.session_state.get("queue_media_500", []),
        "queue_curta_500": st.session_state.get("queue_curta_500", []),
        "queue_internacional_500": st.session_state.get("queue_internacional_500", []),
        "queue_super_curta_500": st.session_state.get("queue_super_curta_500", []),
        "selected_fleets_500": st.session_state.get("selected_fleets_500", []),
        # comuns
        "frotas_destacadas": st.session_state.frotas_destacadas,
        "frotas_removidas": sorted(list(st.session_state.frotas_removidas)),
        "registro_pegaram_carga": st.session_state.registro_pegaram_carga,
        "registro_excluidas": st.session_state.registro_excluidas,
        "include_rest": st.session_state.get("include_rest", False),
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
    st.session_state.queue_internacional = state.get("queue_internacional", [])
    st.session_state.queue_super_curta = state.get("queue_super_curta", [])
    st.session_state.selected_fleets = state.get("selected_fleets", [])
    st.session_state.queue_super_longa_500 = state.get("queue_super_longa_500", [])
    st.session_state.queue_longa_500 = state.get("queue_longa_500", [])
    st.session_state.queue_media_500 = state.get("queue_media_500", [])
    st.session_state.queue_curta_500 = state.get("queue_curta_500", [])
    st.session_state.queue_internacional_500 = state.get("queue_internacional_500", [])
    st.session_state.queue_super_curta_500 = state.get("queue_super_curta_500", [])
    st.session_state.selected_fleets_500 = state.get("selected_fleets_500", [])
    st.session_state.frotas_destacadas = state.get("frotas_destacadas", [])
    st.session_state.frotas_removidas = set(state.get("frotas_removidas", []))
    st.session_state.registro_pegaram_carga = state.get("registro_pegaram_carga", [])
    st.session_state.registro_excluidas = state.get("registro_excluidas", [])
    st.session_state.include_rest = state.get("include_rest", False)


# ------------------------------------------------------------
# Frotas válidas e seções (mantidos)
# ------------------------------------------------------------
FROTAS_VALIDAS = {
    203,205,207,208,211,212,215,218,219,222,223,226,227,228,229,230,
    231,232,233,234,235,236,237,238,239,240,241,242,243,244,245,246,
    247,248,249,250,251,252,253,267,301,302,303,304,305,306,307,308,
    309,310,311,312,313,314,315,316,317,318,319,320,321,322,323,324,
    325,326,327,328,329,330,331,332,333,334,335,336,401,402,403,404,
    405,406,407,408,409,410,411,412,413,414,415,416,417,418,419,420,
    421,422,423,424,425,426,427,428,429,430,431,432,433,434,435,436,
    437,438,439,440,451,452,453,454,455,456,457,458,459,460,461,462,
    463,464,466,467,468,469,470,
    501,502,503,504,505,506,507,508,509,510,511,512,513,514,515,516,517,518,519,520,521,522,523,524,525,526,527,528,529,530,531,532,533,534,535,536,537,538,539,540,541,542,543,544,545,546,547,548,549,550,551,552,553,554,555,556,557,558,559,560,561,562,563,564,565,566,567,568,569,570,571,572,573,574,575,576
}
FROTAS_VALIDAS_500 = set(range(501, 577))

SECTION_TITLES_RJ = [
    "INTER - RESENDE",
    "SUPER LONGA - RESENDE",
    "LONGA - RESENDE",
    "MEDIA RESENDE",
    "CURTA - RESENDE",
    "500 - INTER - RESENDE",
    "500 - SUPER LONGA-RESENDE",
    "500 - LONGA-RESENDE",
    "500 - MEDIA-RESENDE",
    "500 - CURTA-RESENDE",
]

# Padrões de seção RJ (mantidos e tornados tolerantes a hífen/espaço)
SEC_PATTERNS_RJ = [
    (re.compile(r'^\s*\d*\s*INTER\s*-?\s*RESENDE\b', re.IGNORECASE), 0),
    (re.compile(r'^\s*\d*\s*SUPER\s*LONGA\s*-?\s*RESENDE\b', re.IGNORECASE), 1),
    (re.compile(r'^\s*\d*\s*LONGA\s*-?\s*RESENDE\b', re.IGNORECASE), 2),
    (re.compile(r'^\s*\d*\s*MEDIA\s*RESENDE\b', re.IGNORECASE), 3),
    (re.compile(r'^\s*\d*\s*CURTA\s*-?\s*RESENDE\b', re.IGNORECASE), 4),
    (re.compile(r'^\s*\d*\s*500\s*-?\s*INTER\s*-?\s*RESENDE\b', re.IGNORECASE), 5),
    (re.compile(r'^\s*\d*\s*500\s*-?\s*SUPER\s*LONGA\s*-?\s*RESENDE\b', re.IGNORECASE), 6),
    (re.compile(r'^\s*\d*\s*500\s*-?\s*LONGA\s*-?\s*RESENDE\b', re.IGNORECASE), 7),
    (re.compile(r'^\s*\d*\s*500\s*-?\s*MEDIA\s*-?\s*RESENDE\b', re.IGNORECASE), 8),
    (re.compile(r'^\s*\d*\s*500\s*-?\s*CURTA\s*-?\s*RESENDE\b', re.IGNORECASE), 9),
]

# Labels SJP (mantidos)
SECTION_LABELS_SJP = [
    "LONGA MT-GO-DF-TO",
    "SUPER CURTA",
    "SUPER-LONGA MA-PA-AC-RO",
    "MEDIA SP - RJ - MS",
    "CURTA - PR - PORTO",
    "INTERNACIONAL",
    "SUPER CURTA 500",
    "500 - INTERN-SJP",
    "500 - CURTA-SJP",
    "500 - SUPER LONGA-SJP",
    "500 - LONGA-SJP",
    "500 - MEDIA-SJP",
]

SECTION_TITLES_SJP_REGEX = [
    r"LONGA\s+MT-?GO-?DF-?TO",
    r"SUPER\s+CURTA(?!\s*500)",
    r"SUPER[\-\s]*LONGA\s+MA-?PA-?AC-?RO",
    r"MEDIA\s+SP\s*\-\s*RJ\s*\-\s*MS",
    r"CURTA\s*\-\s*PR\s*\-\s*PORTO",
    r"INTERNACIONAL(?!\s*500)",
    r"SUPER\s+CURTA\s*500",
    r"500\s*\-\s*INTERN-?SJP",
    r"500\s*\-\s*CURTA-?SJP",
    r"500\s*\-\s*SUPER\s*LONGA-?SJP",
    r"500\s*\-\s*LONGA-?SJP",
    r"500\s*\-\s*MEDIA-?SJP",
]
SECTION_PATTERNS_SJP = [re.compile(p, re.IGNORECASE) for p in SECTION_TITLES_SJP_REGEX]


# ------------------------------------------------------------
# Leitura de PDF: RJ
# ------------------------------------------------------------
def extract_orders_rj_from_text(text: str) -> list[list[str]]:
    """
    (Mantido) Extrai 'orders' (listas de frotas por seção RJ).
    Preserva sua lógica original de identificar frotas por padrões de seção.
    """
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    sections = [[] for _ in range(10)]  # 5 principais + 5 extras 500
    current_sec_index = None

    for line in lines:
        # atualiza seção
        for pat, idx in SEC_PATTERNS_RJ:
            if pat.search(line):
                current_sec_index = idx
                break
        if current_sec_index is None:
            continue

        # tenta achar frota por números isolados
        nums = re.findall(r'\b(\d{2,3})\b', line)
        for n in nums:
            try:
                n_norm = str(int(n))
            except Exception:
                continue
            allowed = (FROTAS_VALIDAS - FROTAS_VALIDAS_500) if current_sec_index < 5 else FROTAS_VALIDAS_500
            if n_norm in {str(x) for x in allowed}:
                if n_norm not in sections[current_sec_index]:
                    sections[current_sec_index].append(n_norm)
                break

    return sections

def extract_rj_from_uploaded_pdf(uploaded_pdf):
    pdf_bytes = uploaded_pdf.read()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
        tmp.write(pdf_bytes)
        tmp_path = tmp.name
    try:
        text = extract_text(tmp_path)
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass

    orders = extract_orders_rj_from_text(text)
    meta = extract_meta_from_text(text, orders=orders, filial="RJ")
    return orders, meta


# ------------------------------------------------------------
# Leitura de PDF: SJP/PR
# ------------------------------------------------------------
def extract_orders_sjp_from_text(text: str) -> list[list[str]]:
    """
    (Mantido) Extrai 'orders' para SJP em 12 seções.
    Usa padrões de títulos SJP e captura números de frotas válidos.
    """
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    sections = [[] for _ in range(12)]
    current_sec_index = None

    for line in lines:
        for idx, pat in enumerate(SECTION_PATTERNS_SJP):
            if pat.search(line):
                current_sec_index = idx
                break
        if current_sec_index is None:
            continue

        nums = re.findall(r'\b(\d{2,3})\b', line)
        for n in nums:
            try:
                n_norm = str(int(n))
            except Exception:
                continue
            allowed = (FROTAS_VALIDAS - FROTAS_VALIDAS_500) if current_sec_index < 6 else FROTAS_VALIDAS_500
            if n_norm in {str(x) for x in allowed}:
                if n_norm not in sections[current_sec_index]:
                    sections[current_sec_index].append(n_norm)
                break

    return sections

def extract_sjp_from_uploaded_pdf(uploaded_pdf):
    pdf_bytes = uploaded_pdf.read()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
        tmp.write(pdf_bytes)
        tmp_path = tmp.name
    try:
        text = extract_text(tmp_path)
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass

    orders = extract_orders_sjp_from_text(text)
    meta = extract_meta_from_text(text, orders=orders, filial="SJP")
    return orders, meta


# ------------------------------------------------------------
# Utilidades de fila e UI (mantidos)
# ------------------------------------------------------------
def _split_frotas_por_grupo(frotas: list[str]) -> tuple[list[str], list[str]]:
    principais, extras = [], []
    for f in frotas:
        try:
            n = int(re.sub(r"\D", "", str(f)) or "0")
        except Exception:
            n = 0
        if 200 <= n <= 470:
            principais.append(str(n))
        elif 501 <= n <= 576:
            extras.append(str(n))
    return principais, extras

def rebuild_queues_all(filial: str, normalized: list[str]):
    principais, extras = _split_frotas_por_grupo(normalized)
    if filial == "RJ":
        map_main  = {"super": 1, "longa": 2, "media": 3, "curta": 4, "intern": 0}
        map_extra = {"super": 6, "longa": 7, "media": 8, "curta": 9, "intern": 5}
    else:
        map_main  = {"longa": 0, "supercurta": 1, "super": 2, "media": 3, "curta": 4, "intern": 5}
        map_extra = {"supercurta": 6, "intern": 7, "curta": 8, "super": 9, "longa": 10, "media": 11}

    removidas = st.session_state.get("frotas_removidas", set())
    def build_queue(order_idx: int, selected_list: list[str]):
        if order_idx >= len(st.session_state.orders):
            return []
        return [f for f in st.session_state.orders[order_idx] if (f in selected_list) and (f not in removidas)]

    # principais
    st.session_state.queue_super_longa = build_queue(map_main.get("super", 0), principais)
    st.session_state.queue_longa       = build_queue(map_main.get("longa", 0), principais)
    st.session_state.queue_media       = build_queue(map_main.get("media", 0), principais)
    st.session_state.queue_curta       = build_queue(map_main.get("curta", 0), principais)
    st.session_state.queue_internacional = build_queue(map_main.get("intern", 0), principais)
    st.session_state.queue_super_curta = build_queue(map_main.get("supercurta", 0), principais) if filial != "RJ" else []

    present_main = set()
    for k in ["super", "longa", "media", "curta", "intern", "supercurta"]:
        idx = map_main.get(k)
        if idx is not None and idx < len(st.session_state.orders):
            present_main.update(st.session_state.orders[idx])
    st.session_state.selected_fleets = [f for f in principais if (f in present_main) and (f not in removidas)]

    # extras / 500
    st.session_state.queue_super_longa_500 = build_queue(map_extra.get("super", 0), extras)
    st.session_state.queue_longa_500       = build_queue(map_extra.get("longa", 0), extras)
    st.session_state.queue_media_500       = build_queue(map_extra.get("media", 0), extras)
    st.session_state.queue_curta_500       = build_queue(map_extra.get("curta", 0), extras)
    st.session_state.queue_internacional_500 = build_queue(map_extra.get("intern", 0), extras)
    st.session_state.queue_super_curta_500 = build_queue(map_extra.get("supercurta", 0), extras) if filial != "RJ" else []

    present_extra = set()
    for k in ["super", "longa", "media", "curta", "intern", "supercurta"]:
        idx = map_extra.get(k)
        if idx is not None and idx < len(st.session_state.orders):
            present_extra.update(st.session_state.orders[idx])
    st.session_state.selected_fleets_500 = [f for f in extras if (f in present_extra) and (f not in removidas)]

    # manter destaques apenas das selecionadas
    allowed = set(st.session_state.selected_fleets) | set(st.session_state.selected_fleets_500)
    st.session_state.frotas_destacadas = [f for f in st.session_state.frotas_destacadas if f in allowed]


# ------------------------------------------------------------
# Remoções/Registros/Relatórios (mantidos)
# ------------------------------------------------------------
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
    for name in [
        "selected_fleets", "selected_fleets_500",
        "queue_longa", "queue_super_longa", "queue_media", "queue_curta",
        "queue_internacional", "queue_super_curta",
        "queue_longa_500", "queue_super_longa_500", "queue_media_500",
        "queue_curta_500", "queue_internacional_500", "queue_super_curta_500"
    ]:
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


# ------------------------------------------------------------
# UI principal (mantida) — apenas consumindo meta consolidada
# ------------------------------------------------------------
def normalize_fleet_list(raw: str) -> list[str]:
    parts = [p.strip() for p in (raw or "").split(",") if p.strip()]
    out = []
    for p in parts:
        digits = re.sub(r"\D", "", p)
        if digits:
            out.append(str(int(digits)))
    return out

def show_queue(title: str, queue_list, dot_class: str, filial: str, group: str, kind: str):
    # (Mantido)
    st.markdown(f"<h4>{title}</h4>", unsafe_allow_html=True)
    if not queue_list:
        st.info("Fila vazia.")
        return
    if filial == "RJ":
        sec_map = {
            "main": {"intern": 0, "super": 1, "longa": 2, "media": 3, "curta": 4},
            "extra": {"intern": 5, "super": 6, "longa": 7, "media": 8, "curta": 9},
        }
    else:
        sec_map = {
            "main": {"longa": 0, "supercurta": 1, "super": 2, "media": 3, "curta": 4, "intern": 5},
            "extra": {"supercurta": 6, "intern": 7, "curta": 8, "super": 9, "longa": 10, "media": 11},
        }
    sec_idx = (sec_map.get(group, {}) or {}).get(kind)
    sec_list = []
    if sec_idx is not None and st.session_state.get("orders") and sec_idx < len(st.session_state.orders):
        sec_list = st.session_state.orders[sec_idx] or []
    pos_lookup = {str(f): i for i, f in enumerate(sec_list, start=1)}
    data = []
    for idx, f in enumerate(queue_list, start=1):
        f_str = str(f)
        destaque = "⭐" if f_str in st.session_state.frotas_destacadas else ""
        data.append({
            "Posição geral": pos_lookup.get(f_str, ""),
            "Posição": idx,
            "Frota": f_str,
            "★": destaque,
        })
    df = pd.DataFrame(data)
    st.dataframe(df, hide_index=True, use_container_width=True)


def main():
    st.set_page_config(page_title="Gerenciador de Filas – Web", layout="wide")
    st.markdown(CSS, unsafe_allow_html=True)

    if "orders" not in st.session_state:
        st.session_state.orders = []
        st.session_state.filial = None
        st.session_state.queue_super_longa = []
        st.session_state.queue_longa = []
        st.session_state.queue_media = []
        st.session_state.queue_curta = []
        st.session_state.queue_internacional = []
        st.session_state.queue_super_curta = []
        st.session_state.queue_super_longa_500 = []
        st.session_state.queue_longa_500 = []
        st.session_state.queue_media_500 = []
        st.session_state.queue_curta_500 = []
        st.session_state.queue_internacional_500 = []
        st.session_state.queue_super_curta_500 = []
        st.session_state.selected_fleets = []
        st.session_state.selected_fleets_500 = []
        st.session_state.frotas_destacadas = []
        st.session_state.frotas_removidas = set()
        st.session_state.registro_pegaram_carga = []
        st.session_state.registro_excluidas = []
        st.session_state.meta = {}

    ensure_admin_user()
    user = auth_screen()
    touch_lock(user, get_session_id())

    st.sidebar.markdown("## 👤 Sessão")
    st.sidebar.write(f"Usuário: **{user}**")
    if st.sidebar.button("Sair"):
        unlock_user(user, get_session_id())
        st.session_state.pop("auth_user", None)
        st.rerun()

    st.title("🚛 Gerenciador de Filas")
    st.markdown('<p>RJ e SJP • acesso controlado • histórico por usuário • operação em tempo real</p>', unsafe_allow_html=True)

    st.sidebar.markdown("## 👥 Multiusuário")
    st.session_state.mode_shared = st.sidebar.toggle("Fila compartilhada por filial", value=st.session_state.get("mode_shared", True))

    if st.session_state.filial is None:
        st.write("Selecione abaixo qual fila deseja utilizar (fluxo igual ao programa desktop).")
        col_a, col_b = st.columns(2)
        with col_a:
            if st.button("➡️ Iniciar Fila RJ", use_container_width=True):
                st.session_state = {**st.session_state}
                st.session_state.filial = "RJ"
                if st.session_state.mode_shared:
                    load_from_shared("RJ")
                st.rerun()
        with col_b:
            if st.button("➡️ Iniciar Fila SJP", use_container_width=True):
                st.session_state = {**st.session_state}
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

    tabs = ["📄 Arquivo", "🔎 Consulta", "🧾 Selecionar & Montar", "✔ Gestão & Relatório", "🕓 Histórico"]
    is_admin = user in ADMIN_USERS
    if is_admin:
        tabs.append("👥 Usuários")
    tab_list = st.tabs(tabs)
    tab_arquivo, tab_consulta, tab_select, tab_ops, tab_hist = tab_list[:5]
    tab_users = tab_list[5] if is_admin else None

    # --- Aba Arquivo ---
    with tab_arquivo:
        st.subheader("Leitura do PDF")
        uploaded_pdf = st.file_uploader("Selecione o PDF da fila", type=["pdf"], key="pdf_uploader")
        if st.button("Ler PDF", type="primary"):
            if not uploaded_pdf:
                st.warning("Selecione um arquivo PDF primeiro.")
            else:
                if filial == "RJ":
                    orders, meta = extract_rj_from_uploaded_pdf(uploaded_pdf)
                    section_labels = SECTION_TITLES_RJ
                else:
                    orders, meta = extract_sjp_from_uploaded_pdf(uploaded_pdf)
                    section_labels = SECTION_LABELS_SJP

                if not orders or all(len(o) == 0 for o in orders):
                    st.error("Não foi possível ler o arquivo (nenhuma frota identificada).")
                else:
                    st.session_state.orders = orders
                    st.session_state.meta = meta
                    # reset de filas/seleções
                    st.session_state.queue_super_longa = []
                    st.session_state.queue_longa = []
                    st.session_state.queue_media = []
                    st.session_state.queue_curta = []
                    st.session_state.queue_internacional = []
                    st.session_state.queue_super_curta = []
                    st.session_state.queue_super_longa_500 = []
                    st.session_state.queue_longa_500 = []
                    st.session_state.queue_media_500 = []
                    st.session_state.queue_curta_500 = []
                    st.session_state.queue_internacional_500 = []
                    st.session_state.queue_super_curta_500 = []
                    st.session_state.selected_fleets = []
                    st.session_state.selected_fleets_500 = []
                    st.session_state.frotas_destacadas = []
                    st.session_state.registro_pegaram_carga = []
                    st.session_state.registro_excluidas = []
                    st.success("Arquivo lido com sucesso.")
                    history_append({"ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "user": user, "filial": filial, "action": "ler_pdf", "detail": "PDF carregado"})
                    if st.session_state.mode_shared:
                        persist_to_shared(filial)

                    # Exibe tabela simples das ordens
                    rows = []
                    for sec_idx, sec_list in enumerate(orders):
                        sec_name = section_labels[sec_idx] if sec_idx < len(section_labels) else f"Seção {sec_idx}"
                        for pos, frota in enumerate(sec_list, start=1):
                            rows.append({"Seção": sec_name, "Posição": pos, "Frota": frota})
                    if rows:
                        st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)

    # --- Aba Consulta ---
    with tab_consulta:
        st.subheader("Consulta")
        if not st.session_state.get("orders") or all(len(o) == 0 for o in st.session_state.orders):
            st.info("Primeiro leia o PDF na aba **Arquivo**.")
        else:
            orders = st.session_state.orders
            meta = st.session_state.get("meta", {}) or {}

            # índice rápido de posição por seção
            pos_index = []
            for sec in orders:
                pos_index.append({str(f): i for i, f in enumerate(sec or [], start=1)})

            if filial == "RJ":
                map_main = {"SUPER LONGA": 1, "LONGA": 2, "MÉDIA": 3, "CURTA": 4, "INTERNACIONAL": 0}
                map_500  = {"SUPER LONGA": 6, "LONGA": 7, "MÉDIA": 8, "CURTA": 9, "INTERNACIONAL": 5}
            else:
                map_main = {"SUPER LONGA": 2, "LONGA": 0, "MÉDIA": 3, "CURTA": 4, "INTERNACIONAL": 5}
                map_500  = {"SUPER LONGA": 9, "LONGA": 10, "MÉDIA": 11, "CURTA": 8, "INTERNACIONAL": 7}

            q_raw = st.text_input("Consultar frotas (separadas por vírgula)", value="").strip()
            q_list = normalize_fleet_list(q_raw) if q_raw else []

            def _pos(sec_idx: int | None, frota: str) -> str:
                if sec_idx is None or sec_idx >= len(pos_index):
                    return ""
                return pos_index[sec_idx].get(frota, "")

            def _choose_map_for_frota(frota: str) -> dict:
                try:
                    n = int(re.sub(r"\D", "", frota) or "0")
                except Exception:
                    n = 0
                if 501 <= n <= 576:
                    return map_500
                return map_main

            if not q_list:
                st.info("Digite uma ou mais frotas para consultar (ex.: 203,250,314,504).")
            else:
                rows = []
                for frota in q_list:
                    fmap = _choose_map_for_frota(frota)
                    rec = meta.get(str(frota), {}) or {}
                    # ✅ Agora 'Ult. Vg' é a data MAIS RECENTE consolidada (vinda de extract_meta_from_text)
                    ult = rec.get("ult_viag", "NA")
                    mot = rec.get("motorista", "NA")
                    row = {
                        "FROTA": str(frota),
                        "SUPER LONGA": _pos(fmap.get("SUPER LONGA"), str(frota)),
                        "LONGA":        _pos(fmap.get("LONGA"), str(frota)),
                        "MÉDIA":        _pos(fmap.get("MÉDIA"), str(frota)),
                        "CURTA":        _pos(fmap.get("CURTA"), str(frota)),
                        "INTERNACIONAL":_pos(fmap.get("INTERNACIONAL"), str(frota)),
                        "Ult. Vg": ult,
                        "Motorista": mot,
                    }
                    rows.append(row)
                dfc = pd.DataFrame(rows)
                sty = dfc.style.set_properties(subset=["Ult. Vg"], **{"font-weight": "900", "border": "2px solid rgba(255,255,255,.25)"})
                st.dataframe(sty, hide_index=True, use_container_width=True)
                st.download_button("Baixar consulta (CSV)", data=dfc.to_csv(index=False).encode("utf-8"), file_name="consulta.csv", mime="text/csv")

    # --- Aba Selecionar & Montar (mantida) ---
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
                rebuild_queues_all(filial, normalized)
                history_append({"ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "user": user, "filial": filial,
                                "action": "montar_filas",
                                "detail": f"{len(st.session_state.selected_fleets)} principais + {len(st.session_state.get('selected_fleets_500', []))} extras"})
                if st.session_state.mode_shared:
                    persist_to_shared(filial)
                st.success("Filas montadas (ordem do PDF).")

        st.markdown("---")
        st.subheader("Destaque de Frotas")
        destacar_input = st.text_input("Destacar frotas (separadas por vírgula, após montar as filas)")
        if st.button("Atualizar Destaques"):
            parts = normalize_fleet_list(destacar_input)
            for f in parts:
                if (f not in st.session_state.selected_fleets) and (f not in st.session_state.get('selected_fleets_500', [])):
                    continue
                if f in st.session_state.frotas_destacadas:
                    st.session_state.frotas_destacadas.remove(f)
                else:
                    st.session_state.frotas_destacadas.append(f)
            history_append({"ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "user": user, "filial": filial,
                            "action": "destaques", "detail": ", ".join(parts) if parts else ""})
            if st.session_state.mode_shared:
                persist_to_shared(filial)
            st.success("Frotas destacadas atualizadas.")

        st.markdown("---")
        st.subheader("Resumo rápido")
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Super Longa", len(st.session_state.queue_super_longa))
        m2.metric("Longa", len(st.session_state.queue_longa))
        m3.metric("Média", len(st.session_state.queue_media))
        m4.metric("Curta", len(st.session_state.queue_curta))

        st.subheader("Visualização das Filas")
        st.session_state.include_rest = st.toggle(
            "Incluir filas extras (Super Curta / Internacional)",
            value=st.session_state.get("include_rest", False),
            help="Mostra também as filas que não são as 4 principais, separadas por tipo de frota.",
        )

        st.markdown("### Frotas Principais")
        col1, col2 = st.columns(2)
        with col1:
            show_queue("1 - SUPER LONGA", st.session_state.queue_super_longa, "super", filial, "main", "super")
            show_queue("3 - MÉDIA",       st.session_state.queue_media,       "media", filial, "main", "media")
        with col2:
            show_queue("2 - LONGA",       st.session_state.queue_longa,       "longa", filial, "main", "longa")
            show_queue("4 - CURTA",       st.session_state.queue_curta,       "curta", filial, "main", "curta")

        if st.session_state.include_rest:
            st.markdown("#### Filas extras – Principais")
            if filial == "RJ":
                show_queue("INTERNACIONAL", st.session_state.get("queue_internacional", []), "intern", filial, "main", "intern")
            else:
                cA, cB = st.columns(2)
                with cA:
                    show_queue("SUPER CURTA", st.session_state.get("queue_super_curta", []), "supercurta", filial, "main", "supercurta")
                with cB:
                    show_queue("INTERNACIONAL", st.session_state.get("queue_internacional", []), "intern", filial, "main", "intern")

        st.markdown("---")
        st.markdown("### Frotas Extras")
        col3, col4 = st.columns(2)
        with col3:
            show_queue("1 - SUPER LONGA (500)", st.session_state.get("queue_super_longa_500", []), "super", filial, "extra", "super")
            show_queue("3 - MÉDIA (500)",       st.session_state.get("queue_media_500", []),       "media", filial, "extra", "media")
        with col4:
            show_queue("2 - LONGA (500)",       st.session_state.get("queue_longa_500", []),       "longa", filial, "extra", "longa")
            show_queue("4 - CURTA (500)",       st.session_state.get("queue_curta_500", []),       "curta", filial, "extra", "curta")

        if st.session_state.include_rest:
            st.markdown("#### Filas extras – 500")
            if filial == "RJ":
                show_queue("INTERNACIONAL (500)", st.session_state.get("queue_internacional_500", []), "intern", filial, "extra", "intern")
            else:
                cC, cD = st.columns(2)
                with cC:
                    show_queue("SUPER CURTA (500)", st.session_state.get("queue_super_curta_500", []), "supercurta", filial, "extra", "supercurta")
                with cD:
                    show_queue("INTERNACIONAL (500)", st.session_state.get("queue_internacional_500", []), "intern", filial, "extra", "intern")

        if st.session_state.get("mode_shared") and st.session_state.get("orders"):
            persist_to_shared(filial)

    # --- Aba Gestão & Relatório (mantida) ---
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
                    history_append({"ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "user": user, "filial": filial, "action": "gerar_pdf", "detail": filename})
                    st.success("PDF gerado. Use o botão abaixo para baixar.")
        if st.session_state.get("generated_pdf_bytes"):
            st.download_button(
                label="Baixar PDF do Registro",
                data=st.session_state.generated_pdf_bytes,
                file_name=st.session_state.generated_pdf_filename,
                mime="application/pdf",
            )

    # --- Aba Histórico (mantida) ---
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
        st.download_button("Baixar histórico (CSV)", data=dfh.to_csv(index=False).encode("utf-8"), file_name="historico.csv", mime="text/csv")

    # --- Aba Usuários (mantida) ---
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
            safe_users = [u for u in users_list if u != "mateus.souza"]
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
            st.markdown("### 🧾 Log do Admin")
            log = _load_json(ADMIN_LOG_PATH, {"events": []}).get("events", [])
            df_log = pd.DataFrame(log) if log else pd.DataFrame(columns=["ts","actor","action","detail"])
            if not df_log.empty:
                df_log = df_log.sort_values("ts", ascending=False)
            st.dataframe(df_log, hide_index=True, use_container_width=True)
            st.download_button("Baixar log admin (CSV)", data=df_log.to_csv(index=False).encode("utf-8"),
                               file_name="admin_log.csv", mime="text/csv")
            st.caption("⚠️ As senhas não são exibidas (ficam armazenadas apenas como hash).")


if __name__ == "__main__":
    main()
