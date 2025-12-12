import os
import re
import tempfile
from datetime import datetime
from io import BytesIO

import streamlit as st
import pandas as pd
from pdfminer.high_level import extract_text

# reportlab para gerar PDF
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph,
    Spacer,
)

# =============================================================================
#                           CONSTANTES E LÓGICA COMPARTILHADA
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

# =============================================================================
#                               LÓGICA - RIO DE JANEIRO (RJ)
# =============================================================================

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
            continue

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

# =============================================================================
#                           LÓGICA - SÃO JOSÉ DOS PINHAIS (SJP)
# =============================================================================

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
        block = text[start:end]
        sections.append((idx, block))

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

    orders = []
    for blk in blocks:
        if blk:
            orders.append(extract_fleets_from_block_sjp(blk))
        else:
            orders.append([])
    return orders


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

# =============================================================================
#                              FUNÇÕES AUXILIARES WEB
# =============================================================================

def normalize_fleet_list(raw: str):
    partes = [p.strip() for p in raw.split(",") if p.strip()]
    normalized = []
    for p in partes:
        digits = re.sub(r"\D", "", p)
        if digits:
            normalized.append(str(int(digits)))
        else:
            normalized.append(p)
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
        "registro_pegaram_carga": [],
        "registro_excluidas": [],
        "generated_pdf_bytes": None,
        "generated_pdf_filename": None,
    }
    for k, v in defaults.items():
        st.session_state[k] = v


def show_queue(label: str, queue_list):
    st.subheader(f"Fila {label}")
    if not queue_list:
        st.info("Fila vazia.")
        return

    data = []
    for idx, f in enumerate(queue_list, start=1):
        destaque = "⭐" if f in st.session_state.frotas_destacadas else ""
        data.append({"Posição": idx, "Frota": f, "Destaque": destaque})

    df = pd.DataFrame(data)
    st.table(df)


def handle_remove_frota(raw: str, is_carga: bool, fila_sel: str | None = None):
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

    for name in ["selected_fleets", "queue_longa", "queue_super_longa",
                 "queue_media", "queue_curta"]:
        lst = st.session_state.get(name, [])
        if f_norm in lst:
            lst.remove(f_norm)
            removed_any = True

    if removed_any:
        ts = datetime.now().strftime("%d/%m %H:%M")
        if is_carga:
            st.session_state.registro_pegaram_carga.append(
                {"frota": f_norm, "fila": fila_sel, "ts": ts}
            )
            st.success(f"Frota {f_norm} removida (pegou carga).")
        else:
            st.session_state.registro_excluidas.append(
                {"frota": f_norm, "ts": ts}
            )
            st.success(f"Frota {f_norm} excluída.")

        if f_norm in st.session_state.frotas_destacadas:
            st.session_state.frotas_destacadas.remove(f_norm)
    else:
        st.info(f"{f_norm} não encontrada nas filas.")


def generate_pdf_registro(suffix: str):
    if not (st.session_state.registro_pegaram_carga or st.session_state.registro_excluidas):
        return None, None

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
    )
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
        t = Table(data, colWidths=[100, 80, 150])
        t.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#4b5563")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                ]
            )
        )
        elems.append(t)
        elems.append(Spacer(1, 18))

    if st.session_state.registro_excluidas:
        elems.append(Paragraph("FROTAS EXCLUÍDAS", styles["Heading2"]))
        data2 = [["Data/Hora", "Frota"]]
        for r in st.session_state.registro_excluidas:
            data2.append([r["ts"], r["frota"]])
        t2 = Table(data2, colWidths=[120, 80])
        t2.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#4b5563")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                ]
            )
        )
        elems.append(t2)

    doc.build(elems)
    buffer.seek(0)
    filename = f"registro_{suffix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    return buffer.getvalue(), filename

# =============================================================================
#                                  APP STREAMLIT
# =============================================================================

def main():
    st.set_page_config(
        page_title="Gerenciador de Filas – Web",
        layout="wide",
    )

    st.title("🚛 Gerenciador de Filas – Versão Web")

    if "orders" not in st.session_state:
        reset_state_preserve_filial()

    if "filial" not in st.session_state:
        st.session_state.filial = "RJ"
    if "prev_filial" not in st.session_state:
        st.session_state.prev_filial = st.session_state.filial

    st.write("Selecione abaixo qual fila deseja utilizar (fluxo igual ao programa desktop).")

    col_a, col_b = st.columns(2)
    with col_a:
        if st.button("Iniciar Fila RJ"):
            st.session_state.filial = "RJ"
    with col_b:
        if st.button("Iniciar Fila SJP"):
            st.session_state.filial = "SJP"

    filial = st.session_state.filial

    if st.session_state.filial != st.session_state.prev_filial:
        reset_state_preserve_filial()
        st.session_state.prev_filial = st.session_state.filial

    st.markdown(f"### Filial selecionada: **{filial}**")

    tab_arquivo, tab_select, tab_ops = st.tabs(
        ["📄 Arquivo", "🧾 Selecionar & Montar", "✔ Gestão & Relatório"]
    )

    with tab_arquivo:
        st.subheader("Leitura do PDF")

        uploaded_pdf = st.file_uploader(
            "Selecione o PDF da fila",
            type=["pdf"],
            key="pdf_uploader",
        )

        if st.button("Ler PDF"):
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

                    rows = []
                    for sec_idx, sec_list in enumerate(orders):
                        sec_name = (
                            section_labels[sec_idx]
                            if sec_idx < len(section_labels)
                            else f"Seção {sec_idx}"
                        )
                        for pos, frota in enumerate(sec_list, start=1):
                            rows.append(
                                {"Seção": sec_name, "Posição": pos, "Frota": frota}
                            )
                    if rows:
                        df = pd.DataFrame(rows)
                        st.dataframe(df, use_container_width=True)

    with tab_select:
        st.subheader("Montagem das Filas")

        fleets_input = st.text_input("Digite as frotas separadas por vírgula")

        if st.button("Montar Filas"):
            if not st.session_state.orders or all(
                len(o) == 0 for o in st.session_state.orders
            ):
                st.warning("Leia primeiro o arquivo PDF na aba 'Arquivo'.")
            elif not fleets_input.strip():
                st.warning("Digite as frotas desejadas.")
            else:
                normalized = normalize_fleet_list(fleets_input)

                if filial == "RJ":
                    mapping = {"super_longa": 1, "longa": 2, "media": 3, "curta": 4}
                else:
                    mapping = {"super_longa": 2, "longa": 0, "media": 3, "curta": 4}

                present_in_sections = set()
                for _, sec_idx in mapping.items():
                    if sec_idx < len(st.session_state.orders):
                        present_in_sections.update(st.session_state.orders[sec_idx])

                ignoradas = [f for f in normalized if f not in present_in_sections]

                def build_queue_from_pdf(order_idx):
                    if order_idx >= len(st.session_state.orders):
                        return []
                    return [
                        f
                        for f in st.session_state.orders[order_idx]
                        if f in normalized
                    ]

                st.session_state.queue_super_longa = build_queue_from_pdf(
                    mapping["super_longa"]
                )
                st.session_state.queue_longa = build_queue_from_pdf(mapping["longa"])
                st.session_state.queue_media = build_queue_from_pdf(mapping["media"])
                st.session_state.queue_curta = build_queue_from_pdf(mapping["curta"])
                st.session_state.selected_fleets = [
                    f for f in normalized if f in present_in_sections
                ]

                st.session_state.frotas_destacadas = [
                    f
                    for f in st.session_state.frotas_destacadas
                    if f in st.session_state.selected_fleets
                ]

                if ignoradas:
                    st.warning(
                        "As seguintes frotas não foram encontradas nas seções consideradas:\n"
                        + ", ".join(ignoradas)
                    )
                st.success("Filas montadas (ordem do PDF).")

        st.markdown("---")
        st.subheader("Destaque de Frotas")

        destacar_input = st.text_input(
            "Destacar frotas (separadas por vírgula, após montar as filas)"
        )

        if st.button("Atualizar Destaques"):
            parts = [p.strip() for p in destacar_input.split(",") if p.strip()]
            normalized = []
            for p in parts:
                digits = re.sub(r"\D", "", p)
                if digits:
                    normalized.append(str(int(digits)))
                else:
                    normalized.append(p)

            for f in normalized:
                if f not in st.session_state.selected_fleets:
                    continue
                if f in st.session_state.frotas_destacadas:
                    st.session_state.frotas_destacadas.remove(f)
                else:
                    st.session_state.frotas_destacadas.append(f)

            st.success("Frotas destacadas atualizadas.")

        st.markdown("---")
        st.subheader("Visualização das Filas")

        col1, col2 = st.columns(2)
        with col1:
            show_queue("Super Longa", st.session_state.queue_super_longa)
            show_queue("Média", st.session_state.queue_media)
        with col2:
            show_queue("Longa", st.session_state.queue_longa)
            show_queue("Curta", st.session_state.queue_curta)

    with tab_ops:
        st.subheader("Gestão das Filas")

        col1, col2 = st.columns(2)

        with col1:
            frota_pego = st.text_input("Frota que pegou carga", key="frota_pego")
            fila_sel = st.selectbox(
                "Fila da qual saiu",
                ["Super Longa", "Longa", "Média", "Curta"],
                key="fila_sel",
            )
            if st.button("Remover (Pegou Carga)"):
                handle_remove_frota(frota_pego, is_carga=True, fila_sel=fila_sel)

        with col2:
            frota_exc = st.text_input("Frota excluída", key="frota_excluida")
            if st.button("Excluir Frota"):
                handle_remove_frota(frota_exc, is_carga=False, fila_sel=None)

        st.markdown("---")
        st.subheader("Registros atuais")

        if st.session_state.registro_pegaram_carga:
            st.markdown("### Frotas que pegaram carga")
            df_pc = pd.DataFrame(st.session_state.registro_pegaram_carga)
            st.table(df_pc)

        if st.session_state.registro_excluidas:
            st.markdown("### Frotas excluídas")
            df_ex = pd.DataFrame(st.session_state.registro_excluidas)
            st.table(df_ex)

        st.markdown("---")
        st.subheader("Gerar PDF de Registro")

        if st.button("Gerar PDF (Registro)"):
            if not (
                st.session_state.registro_pegaram_carga
                or st.session_state.registro_excluidas
            ):
                st.info("Sem dados para gerar PDF.")
            else:
                pdf_bytes, filename = generate_pdf_registro(filial)
                if pdf_bytes:
                    st.session_state.generated_pdf_bytes = pdf_bytes
                    st.session_state.generated_pdf_filename = filename
                    st.success("PDF gerado. Use o botão abaixo para baixar.")

        if st.session_state.get("generated_pdf_bytes"):
            st.download_button(
                label="Baixar PDF do Registro",
                data=st.session_state.generated_pdf_bytes,
                file_name=st.session_state.generated_pdf_filename,
                mime="application/pdf",
            )


if __name__ == "__main__":
    main()
