import os,re,json,tempfile
from datetime import datetime
from io import BytesIO
import streamlit as st
import pandas as pd
from pdfminer.high_level import extract_text
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate,Table,TableStyle,Paragraph,Spacer

CSS="""
<style>
.block-container{padding-top:1rem;}
.small-muted{color:#6b7280;font-size:.9rem;}
.stButton>button{border-radius:12px;}
</style>
"""

APP_DIR=os.path.dirname(os.path.abspath(__file__))
def _safe_path(fn:str)->str:
    p=os.path.join(APP_DIR,fn)
    try:
        with open(p,"a",encoding="utf-8"): pass
        return p
    except Exception:
        return os.path.join(tempfile.gettempdir(),fn)

HISTORY_PATH=_safe_path("history.json")
SHARED_STATE_PATH=_safe_path("shared_state.json")

def _load_json(path,default):
    try:
        if not os.path.exists(path): return default
        with open(path,"r",encoding="utf-8") as f: return json.load(f)
    except Exception:
        return default

def _atomic_write_json(path,obj):
    tmp=path+".tmp"
    with open(tmp,"w",encoding="utf-8") as f:
        json.dump(obj,f,ensure_ascii=False,indent=2)
    os.replace(tmp,path)

def history_append(event:dict):
    data=_load_json(HISTORY_PATH,{"events":[]})
    data["events"].append(event)
    data["events"]=data["events"][-5000:]
    _atomic_write_json(HISTORY_PATH,data)

def history_df(user=None,filial=None)->pd.DataFrame:
    data=_load_json(HISTORY_PATH,{"events":[]})
    rows=data.get("events",[])
    if user: rows=[r for r in rows if r.get("user")==user]
    if filial: rows=[r for r in rows if r.get("filial")==filial]
    if not rows:
        return pd.DataFrame(columns=["ts","user","filial","action","detail"])
    df=pd.DataFrame(rows)
    if "ts" in df.columns: df=df.sort_values("ts",ascending=False)
    return df[["ts","user","filial","action","detail"]]

def shared_load()->dict:
    return _load_json(SHARED_STATE_PATH,{"RJ":{},"SJP":{}})

def shared_save(state:dict):
    _atomic_write_json(SHARED_STATE_PATH,state)

def persist_to_shared(filial:str):
    state=shared_load()
    state[filial]={
        "orders":st.session_state.orders,
        "queue_super_longa":st.session_state.queue_super_longa,
        "queue_longa":st.session_state.queue_longa,
        "queue_media":st.session_state.queue_media,
        "queue_curta":st.session_state.queue_curta,
        "selected_fleets":st.session_state.selected_fleets,
        "frotas_destacadas":st.session_state.frotas_destacadas,
        "frotas_removidas":sorted(list(st.session_state.frotas_removidas)),
        "registro_pegaram_carga":st.session_state.registro_pegaram_carga,
        "registro_excluidas":st.session_state.registro_excluidas,
    }
    shared_save(state)

def load_from_shared(filial:str):
    state=shared_load().get(filial,{})
    if not state: return
    st.session_state.orders=state.get("orders",[])
    st.session_state.queue_super_longa=state.get("queue_super_longa",[])
    st.session_state.queue_longa=state.get("queue_longa",[])
    st.session_state.queue_media=state.get("queue_media",[])
    st.session_state.queue_curta=state.get("queue_curta",[])
    st.session_state.selected_fleets=state.get("selected_fleets",[])
    st.session_state.frotas_destacadas=state.get("frotas_destacadas",[])
    st.session_state.frotas_removidas=set(state.get("frotas_removidas",[]))
    st.session_state.registro_pegaram_carga=state.get("registro_pegaram_carga",[])
    st.session_state.registro_excluidas=state.get("registro_excluidas",[])

def require_login():
    st.sidebar.markdown("## 🔐 Acesso")

    # 1️⃣ tenta Secrets do Streamlit Cloud
    users = st.secrets.get("users", None)
    single_pw = st.secrets.get("APP_PASSWORD", None)

    # 2️⃣ fallback para variáveis de ambiente (Codespaces / local)
    if not users and not single_pw:
        env_pw = os.environ.get("APP_PASSWORD")
        env_users = os.environ.get("USERS_JSON")

        if env_users:
            import json
            users = json.loads(env_users)
        elif env_pw:
            single_pw = env_pw

    if st.session_state.get("auth_user"):
        u = st.session_state["auth_user"]
        st.sidebar.success(f"Logado: {u}")
        if st.sidebar.button("Sair"):
            st.session_state.clear()
            st.rerun()
        return u

    if not users and not single_pw:
        st.warning("Senha não configurada (Secrets ou variáveis de ambiente).")
        st.stop()

    username = st.sidebar.text_input("Usuário")
    password = st.sidebar.text_input("Senha", type="password")

    if st.sidebar.button("Entrar"):
        ok = False
        u = username or "usuario"

        if users:
            ok = u in users and users[u] == password
        else:
            ok = password == single_pw

        if ok:
            st.session_state["auth_user"] = u
            st.rerun()
        else:
            st.sidebar.error("Usuário ou senha inválidos")

    st.stop()

FROTAS_VALIDAS={203,205,207,208,211,212,215,218,219,222,223,226,227,228,229,230,231,232,233,234,235,236,237,238,239,240,241,242,243,244,245,246,247,248,249,250,251,252,253,267,301,302,303,304,305,306,307,308,309,310,311,312,313,314,315,316,317,318,319,320,321,322,323,324,325,326,327,328,329,330,331,332,333,334,335,336,401,402,403,404,405,406,407,408,409,410,411,412,413,414,415,416,417,418,419,420,421,422,423,424,425,426,427,428,429,430,431,432,433,434,435,436,437,438,439,440,451,452,453,454,455,456,457,458,459,460,461,462,463,464,466,467,468,469,470}
FROTAS_VALIDAS_STR={str(x) for x in FROTAS_VALIDAS}

SECTION_TITLES_RJ=["INTER - RESENDE","SUPER LONGA - RESENDE","LONGA - RESENDE","MEDIA RESENDE","CURTA - RESENDE"]
SEC_PATTERNS_RJ=[(re.compile(r"INTER\s*-\s*RESENDE",re.I),0),(re.compile(r"SUPER\s*LONGA\s*-\s*RESENDE",re.I),1),(re.compile(r"LONGA\s*-\s*RESENDE",re.I),2),(re.compile(r"MEDIA\s*RESENDE",re.I),3),(re.compile(r"CURTA\s*-\s*RESENDE",re.I),4)]
PATTERN_SEQ_INTERNO_FROTA_RJ=re.compile(r'(?:\bSIM\b\s+)?\b\d+\b\s+\b\d+\.\d+\b\s+(\d{2,3})\b',re.I)
PATTERN_ISOLATED_NUM_RJ=re.compile(r'(?<!\.)\b\d{2,6}\b(?!\.)')

def extract_orders_rj_from_text(text:str):
    if not text: return [[] for _ in range(5)]
    lines=[l.strip() for l in text.splitlines() if l.strip()]
    sections=[[] for _ in range(5)]
    current=None
    for line in lines:
        for pat,idx in SEC_PATTERNS_RJ:
            if pat.search(line): current=idx; break
        if current is None: continue
        m=PATTERN_SEQ_INTERNO_FROTA_RJ.search(line)
        if m:
            n=str(int(m.group(1)))
            if n in FROTAS_VALIDAS_STR and n not in sections[current]: sections[current].append(n)
            continue
        nums=PATTERN_ISOLATED_NUM_RJ.findall(line)
        if nums:
            chosen=None
            for n in nums:
                try: nn=str(int(n))
                except Exception: continue
                if nn in FROTAS_VALIDAS_STR: chosen=nn; break
            if chosen and chosen not in sections[current]: sections[current].append(chosen)
    return sections

def extract_rj_from_uploaded_pdf(uploaded_pdf):
    with tempfile.NamedTemporaryFile(delete=False,suffix=".pdf") as tmp:
        tmp.write(uploaded_pdf.read()); tmp_path=tmp.name
    try: text=extract_text(tmp_path)
    finally:
        try: os.remove(tmp_path)
        except Exception: pass
    return extract_orders_rj_from_text(text)

SECTION_LABELS_SJP=["LONGA MT-GO-DF-TO","SUPER CURTA","SUPER-LONGA MA-PA-AC-RO","MEDIA SP - RJ - MS","CURTA - PR - PORTO","INTERNACIONAL"]
SECTION_TITLES_SJP_REGEX=[r"LONGA\s+MT-?GO-?DF-?TO",r"SUPER\s+CURTA",r"SUPER[-\s]*LONGA\s+MA-?PA-?AC-?RO",r"MEDIA\s+SP\s*-\s*RJ\s*-\s*MS",r"CURTA\s*-\s*PR\s*-\s*PORTO",r"INTERNACIONAL"]
SECTION_PATTERNS_SJP=[re.compile(p,re.I) for p in SECTION_TITLES_SJP_REGEX]
PATTERN_SEQ_INTERNO_FROTA_SJP=re.compile(r'(?:\bSIM\b\s+)?\b\d+\b\s+\b\d+\.\d+\b\s+(\d{2,6})\b',re.I)
PATTERN_ISOLATED_NUM_SJP=re.compile(r'(?<!\.)\b\d{2,6}\b(?!\.)')

def split_text_into_sections_sjp(text:str):
    pos=[]
    for pat in SECTION_PATTERNS_SJP:
        m=pat.search(text); pos.append(m.start() if m else -1)
    if all(p==-1 for p in pos): return []
    found=[(p,i) for i,p in enumerate(pos) if p!=-1]; found.sort(key=lambda x:x[0])
    sections=[]
    for i,(p,idx) in enumerate(found):
        start=p; end=found[i+1][0] if i+1<len(found) else len(text)
        sections.append((idx,text[start:end]))
    blocks=[""]*len(SECTION_LABELS_SJP)
    for idx,blk in sections: blocks[idx]=blk
    return blocks

def extract_fleets_from_block_sjp(block_text:str):
    ordered=[]; seen=set()
    for line in block_text.splitlines():
        line=line.strip()
        if not line: continue
        m=PATTERN_SEQ_INTERNO_FROTA_SJP.search(line)
        if m:
            try: nn=str(int(m.group(1)))
            except Exception: nn=None
            if nn and nn in FROTAS_VALIDAS_STR and nn not in seen:
                seen.add(nn); ordered.append(nn)
            continue
        nums=PATTERN_ISOLATED_NUM_SJP.findall(line)
        if nums:
            chosen=None
            for n in nums:
                try: nn=str(int(n))
                except Exception: continue
                if nn in FROTAS_VALIDAS_STR: chosen=nn; break
            if chosen and chosen not in seen:
                seen.add(chosen); ordered.append(chosen)
    return ordered

def extract_orders_sjp_from_text(text:str):
    if not text or len(text.strip())<5: return [[] for _ in SECTION_LABELS_SJP]
    blocks=split_text_into_sections_sjp(text)
    if not blocks:
        fb=[]; seen=set()
        for line in text.splitlines():
            nums=PATTERN_ISOLATED_NUM_SJP.findall(line)
            for n in nums:
                nn=str(int(n))
                if nn in FROTAS_VALIDAS_STR and nn not in seen:
                    seen.add(nn); fb.append(nn)
        return [fb for _ in range(len(SECTION_LABELS_SJP))]
    return [extract_fleets_from_block_sjp(b) if b else [] for b in blocks]

def extract_sjp_from_uploaded_pdf(uploaded_pdf):
    with tempfile.NamedTemporaryFile(delete=False,suffix=".pdf") as tmp:
        tmp.write(uploaded_pdf.read()); tmp_path=tmp.name
    try: text=extract_text(tmp_path)
    finally:
        try: os.remove(tmp_path)
        except Exception: pass
    return extract_orders_sjp_from_text(text)

def normalize_fleet_list(raw:str):
    partes=[p.strip() for p in (raw or "").split(",") if p.strip()]
    out=[]
    for p in partes:
        d=re.sub(r"\D","",p)
        out.append(str(int(d)) if d else p)
    return out

def reset_state():
    st.session_state.orders=[]
    st.session_state.queue_super_longa=[]
    st.session_state.queue_longa=[]
    st.session_state.queue_media=[]
    st.session_state.queue_curta=[]
    st.session_state.selected_fleets=[]
    st.session_state.frotas_destacadas=[]
    st.session_state.frotas_removidas=set()  # ✅ persistente
    st.session_state.registro_pegaram_carga=[]
    st.session_state.registro_excluidas=[]
    st.session_state.generated_pdf_bytes=None
    st.session_state.generated_pdf_filename=None
    st.session_state.mode_shared=True

def show_queue(title:str, queue_list):
    st.subheader(title)
    if not queue_list:
        st.info("Fila vazia."); return
    data=[{"Posição":i,"Frota":f,"Destaque":"⭐" if f in st.session_state.frotas_destacadas else ""} for i,f in enumerate(queue_list,1)]
    st.dataframe(pd.DataFrame(data),hide_index=True,use_container_width=True)

def rebuild_queues(filial:str, normalized:list[str]):
    mapping={"super_longa":1,"longa":2,"media":3,"curta":4} if filial=="RJ" else {"super_longa":2,"longa":0,"media":3,"curta":4}
    removidas=st.session_state.get("frotas_removidas",set())
    present=set()
    for _,sec in mapping.items():
        if sec < len(st.session_state.orders): present.update(st.session_state.orders[sec])
    def build(sec):
        if sec>=len(st.session_state.orders): return []
        return [f for f in st.session_state.orders[sec] if (f in normalized) and (f not in removidas)]
    st.session_state.queue_super_longa=build(mapping["super_longa"])
    st.session_state.queue_longa=build(mapping["longa"])
    st.session_state.queue_media=build(mapping["media"])
    st.session_state.queue_curta=build(mapping["curta"])
    st.session_state.selected_fleets=[f for f in normalized if (f in present) and (f not in removidas)]
    st.session_state.frotas_destacadas=[f for f in st.session_state.frotas_destacadas if f in st.session_state.selected_fleets]

def handle_remove_frota(user,filial,raw,is_carga,fila_sel=None):
    if not st.session_state.orders or all(len(o)==0 for o in st.session_state.orders):
        st.warning("Leia primeiro o PDF."); return
    raw=(raw or "").strip()
    if not raw: st.warning("Digite a frota."); return
    if "," in raw: st.warning("Digite apenas UMA frota."); return
    d=re.sub(r"\D","",raw)
    if not d: st.warning("Frota inválida."); return
    f_norm=str(int(d))
    removed_any=False
    for name in ["selected_fleets","queue_longa","queue_super_longa","queue_media","queue_curta"]:
        lst=st.session_state.get(name,[])
        if f_norm in lst:
            lst.remove(f_norm); removed_any=True
    if removed_any:
        st.session_state.frotas_removidas.add(f_norm)  # ✅ some de TODAS e não volta
        ts_h=datetime.now().strftime("%d/%m %H:%M")
        ts=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if is_carga:
            st.session_state.registro_pegaram_carga.append({"frota":f_norm,"fila":fila_sel,"ts":ts_h})
            history_append({"ts":ts,"user":user,"filial":filial,"action":"pegou_carga","detail":f"{f_norm} ({fila_sel})"})
            st.success(f"Frota {f_norm} removida (pegou carga).")
        else:
            st.session_state.registro_excluidas.append({"frota":f_norm,"ts":ts_h})
            history_append({"ts":ts,"user":user,"filial":filial,"action":"excluida","detail":f_norm})
            st.success(f"Frota {f_norm} excluída.")
        if f_norm in st.session_state.frotas_destacadas: st.session_state.frotas_destacadas.remove(f_norm)
        if st.session_state.get("mode_shared"): persist_to_shared(filial)
    else:
        st.info(f"{f_norm} não encontrada nas filas.")

def generate_pdf_registro(suffix:str):
    if not (st.session_state.registro_pegaram_carga or st.session_state.registro_excluidas):
        return None,None
    buf=BytesIO()
    doc=SimpleDocTemplate(buf,pagesize=A4,leftMargin=36,rightMargin=36,topMargin=36,bottomMargin=36)
    styles=getSampleStyleSheet()
    elems=[]
    elems.append(Paragraph(f"RELATÓRIO DE MOVIMENTAÇÕES - {suffix}",styles["Heading1"]))
    elems.append(Paragraph(datetime.now().strftime("%d/%m/%Y %H:%M"),styles["Normal"]))
    elems.append(Spacer(1,12))
    if st.session_state.registro_pegaram_carga:
        elems.append(Paragraph("FROTAS QUE PEGARAM CARGA",styles["Heading2"]))
        data=[["Data/Hora","Frota","Fila"]]+[[r["ts"],r["frota"],r.get("fila","")] for r in st.session_state.registro_pegaram_carga]
        t=Table(data,colWidths=[110,80,170])
        t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#111827")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),0.5,colors.black)]))
        elems+= [t, Spacer(1,18)]
    if st.session_state.registro_excluidas:
        elems.append(Paragraph("FROTAS EXCLUÍDAS",styles["Heading2"]))
        data2=[["Data/Hora","Frota"]]+[[r["ts"],r["frota"]] for r in st.session_state.registro_excluidas]
        t2=Table(data2,colWidths=[140,80])
        t2.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#111827")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),0.5,colors.black)]))
        elems.append(t2)
    doc.build(elems)
    buf.seek(0)
    fn=f"registro_{suffix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    return buf.getvalue(),fn

def main():
    st.set_page_config(page_title="Gerenciador de Filas – Web",layout="wide")
    st.markdown(CSS,unsafe_allow_html=True)
    user=require_login()
    st.title("🚛 Gerenciador de Filas – Versão Web")
    st.markdown('<div class="small-muted">com senha, histórico e multiusuário</div>',unsafe_allow_html=True)

    if "orders" not in st.session_state: reset_state()
    st.sidebar.markdown("## 👥 Multiusuário")
    st.session_state.mode_shared=st.sidebar.toggle("Fila compartilhada por filial",value=st.session_state.get("mode_shared",True))
    st.sidebar.markdown("## 📌 Navegação")
    if st.sidebar.button("Voltar ao início"):
        st.session_state.filial=None; st.rerun()

    if "filial" not in st.session_state: st.session_state.filial=None
    if st.session_state.filial is None:
        st.write("Selecione abaixo qual fila deseja utilizar (fluxo igual ao programa desktop).")
        a,b=st.columns(2)
        with a:
            if st.button("Iniciar Fila RJ",use_container_width=True):
                st.session_state.filial="RJ"; reset_state()
                if st.session_state.mode_shared: load_from_shared("RJ")
                st.rerun()
        with b:
            if st.button("Iniciar Fila SJP",use_container_width=True):
                st.session_state.filial="SJP"; reset_state()
                if st.session_state.mode_shared: load_from_shared("SJP")
                st.rerun()
        st.info("Dica: a opção de fila compartilhada fica na barra lateral.")
        return

    filial=st.session_state.filial
    st.markdown(f"### Filial selecionada: **{filial}**")

    tab_arquivo,tab_select,tab_ops,tab_hist=st.tabs(["📄 Arquivo","🧾 Selecionar & Montar","✔ Gestão & Relatório","🕓 Histórico"])

    with tab_arquivo:
        st.subheader("Leitura do PDF")
        uploaded=st.file_uploader("Selecione o PDF da fila",type=["pdf"],key="pdf_uploader")
        if st.button("Ler PDF",type="primary"):
            if not uploaded: st.warning("Selecione um arquivo PDF primeiro.")
            else:
                orders=extract_rj_from_uploaded_pdf(uploaded) if filial=="RJ" else extract_sjp_from_uploaded_pdf(uploaded)
                if not orders or all(len(o)==0 for o in orders):
                    st.error("Não foi possível ler o arquivo (nenhuma frota identificada).")
                else:
                    st.session_state.orders=orders
                    st.session_state.queue_super_longa=[]
                    st.session_state.queue_longa=[]
                    st.session_state.queue_media=[]
                    st.session_state.queue_curta=[]
                    st.session_state.selected_fleets=[]
                    st.session_state.frotas_destacadas=[]
                    st.session_state.registro_pegaram_carga=[]
                    st.session_state.registro_excluidas=[]
                    st.success("Arquivo lido com sucesso.")
                    history_append({"ts":datetime.now().strftime("%Y-%m-%d %H:%M:%S"),"user":user,"filial":filial,"action":"ler_pdf","detail":"PDF carregado"})
                    if st.session_state.mode_shared: persist_to_shared(filial)
                    # Mostrar o que foi lido (seção/posição/frota)
                    labels = SECTION_TITLES_RJ if filial=="RJ" else SECTION_LABELS_SJP
                    rows=[]
                    for sec_idx, sec_list in enumerate(orders):
                        sec_name = labels[sec_idx] if sec_idx < len(labels) else f"Seção {sec_idx}"
                        for pos, frota in enumerate(sec_list, start=1):
                            rows.append({"Seção": sec_name, "Posição": pos, "Frota": frota})
                    if rows:
                        st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)

    with tab_select:
        st.subheader("Montagem das Filas")
        fleets_input=st.text_input("Digite as frotas separadas por vírgula")
        if st.button("Montar Filas"):
            if not st.session_state.orders or all(len(o)==0 for o in st.session_state.orders):
                st.warning("Leia primeiro o PDF na aba 'Arquivo'.")
            elif not fleets_input.strip():
                st.warning("Digite as frotas desejadas.")
            else:
                normalized=normalize_fleet_list(fleets_input)
                # Aviso de frotas ignoradas (não encontradas nas seções consideradas)
                mapping={"super_longa":1,"longa":2,"media":3,"curta":4} if filial=="RJ" else {"super_longa":2,"longa":0,"media":3,"curta":4}
                present=set()
                for _,sec_idx in mapping.items():
                    if sec_idx < len(st.session_state.orders):
                        present.update(st.session_state.orders[sec_idx])
                ignoradas=[f for f in normalized if f not in present]

                rebuild_queues(filial,normalized)
                history_append({"ts":datetime.now().strftime("%Y-%m-%d %H:%M:%S"),"user":user,"filial":filial,"action":"montar_filas","detail":f"{len(st.session_state.selected_fleets)} frotas"})
                if ignoradas:
                    st.warning("As seguintes frotas não foram encontradas nas seções consideradas: " + ", ".join(ignoradas))
                if st.session_state.mode_shared: persist_to_shared(filial)
                st.success("Filas montadas (ordem do PDF).")

        st.markdown("---")
        st.subheader("Destaque de Frotas")
        destacar=st.text_input("Destacar frotas (separadas por vírgula)")
        if st.button("Atualizar Destaques"):
            parts=normalize_fleet_list(destacar)
            for f in parts:
                if f not in st.session_state.selected_fleets: continue
                if f in st.session_state.frotas_destacadas: st.session_state.frotas_destacadas.remove(f)
                else: st.session_state.frotas_destacadas.append(f)
            history_append({"ts":datetime.now().strftime("%Y-%m-%d %H:%M:%S"),"user":user,"filial":filial,"action":"destaques","detail":", ".join(parts)})
            if st.session_state.mode_shared: persist_to_shared(filial)
            st.success("Destaques atualizados.")

        st.markdown("---")
        st.subheader("Visualização das Filas")
        # ✅ AJUSTE 1 (ordem mobile): Super Longa, Longa, Média, Curta
        c1,c2=st.columns(2)
        with c1:
            show_queue("1 - SUPER LONGA",st.session_state.queue_super_longa)
            show_queue("2 - LONGA",st.session_state.queue_longa)
        with c2:
            show_queue("3 - MÉDIA",st.session_state.queue_media)
            show_queue("4 - CURTA",st.session_state.queue_curta)

    with tab_ops:
        st.subheader("Gestão das Filas")
        c1,c2=st.columns(2)
        with c1:
            st.markdown("#### ✅ Frota que pegou carga")
            frota_pego=st.text_input("Frota",key="frota_pego")
            fila_sel=st.selectbox("Fila da qual saiu",["Super Longa","Longa","Média","Curta"],key="fila_sel")
            if st.button("Remover (Pegou Carga)",type="primary"):
                handle_remove_frota(user,filial,frota_pego,True,fila_sel)
        with c2:
            st.markdown("#### ❌ Frota excluída")
            frota_exc=st.text_input("Frota",key="frota_excluida")
            if st.button("Excluir Frota"):
                handle_remove_frota(user,filial,frota_exc,False,None)

        st.markdown("---")
        st.subheader("Registros atuais")
        if st.session_state.registro_pegaram_carga:
            st.markdown("### Frotas que pegaram carga")
            st.dataframe(pd.DataFrame(st.session_state.registro_pegaram_carga),hide_index=True,use_container_width=True)
        if st.session_state.registro_excluidas:
            st.markdown("### Frotas excluídas")
            st.dataframe(pd.DataFrame(st.session_state.registro_excluidas),hide_index=True,use_container_width=True)

        st.markdown("---")
        st.subheader("Gerar PDF de Registro")
        if st.button("Gerar PDF (Registro)"):
            if not (st.session_state.registro_pegaram_carga or st.session_state.registro_excluidas):
                st.info("Sem dados para gerar PDF.")
            else:
                pdf_bytes,fn=generate_pdf_registro(filial)
                if pdf_bytes:
                    st.session_state.generated_pdf_bytes=pdf_bytes
                    st.session_state.generated_pdf_filename=fn
                    history_append({"ts":datetime.now().strftime("%Y-%m-%d %H:%M:%S"),"user":user,"filial":filial,"action":"gerar_pdf","detail":fn})
                    st.success("PDF gerado.")
        if st.session_state.get("generated_pdf_bytes"):
            st.download_button("Baixar PDF do Registro",data=st.session_state.generated_pdf_bytes,file_name=st.session_state.generated_pdf_filename,mime="application/pdf")

    with tab_hist:
        st.subheader("Histórico (ações)")
        fuser=st.selectbox("Usuário",["Todos",user],index=1)
        ffil=st.selectbox("Filial",["Todas","RJ","SJP"],index=0)
        dfh=history_df(None if fuser=="Todos" else user, None if ffil=="Todas" else ffil)
        st.dataframe(dfh,hide_index=True,use_container_width=True)
        st.download_button("Baixar histórico (CSV)",data=dfh.to_csv(index=False).encode("utf-8"),file_name="historico.csv",mime="text/csv")
        st.info("Para histórico 100% permanente (reinícios), dá pra ligar em Supabase/Sheets depois.")

if __name__=="__main__":
    main()
