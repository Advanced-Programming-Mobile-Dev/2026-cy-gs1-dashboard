import streamlit as st
import pandas as pd
import numpy as np

st.set_page_config(
    page_title="Ares-7 SIEM",
    layout="wide",
    initial_sidebar_state="expanded",
)


def generate_traffic_data(scenario):
    np.random.seed(42)
    base_time = pd.date_range(start="2026-06-09 10:00", periods=50, freq="min")

    if scenario == "Operação Normal":
        reqs = np.random.normal(500, 50, 50)
    elif scenario == "Cenário B (DoS CommLink)":
        reqs = np.concatenate(
            [np.random.normal(500, 50, 40), np.random.normal(5000, 500, 10)]
        )
    else:  # Cenário A (Movimentação Lateral)
        reqs = np.random.normal(500, 50, 50)

    return pd.DataFrame({"Tráfego (Req/s)": reqs}, index=base_time)


# --- Interface Principal ---
st.title("🛡️ Ares-7 Zero Trust Security Dashboard")
st.markdown("Monitoramento de Telemetria e Políticas de Acesso (SIEM)")

# --- Barra Lateral (Controle da Simulação) ---
st.sidebar.header("Painel de Simulação")
cenario_atual = st.sidebar.radio(
    "Estado da Rede:",
    ("Operação Normal", "Cenário A (Movimentação Lateral)", "Cenário B (DoS CommLink)"),
)

st.sidebar.markdown("---")
st.sidebar.write("**Status do Policy Engine (PDP):** 🟢 Online")
st.sidebar.write("**Identity Provider (IdP):** 🟢 Online")

if cenario_atual == "Operação Normal":
    risk_score = "Baixo"
    risk_color = "normal"
    blocked_reqs = 12
    alert_log = [
        {
            "Hora": "10:45",
            "Módulo": "Access Hub",
            "Evento": "Login Bem-sucedido (Comandante)",
            "Severidade": "Info",
        },
        {
            "Hora": "10:48",
            "Módulo": "Logistics Bay",
            "Evento": "Sincronização de Estoque",
            "Severidade": "Info",
        },
    ]
    status_commlink = "🟢 Operacional"
    status_life = "🟢 Air-Gapped"

elif cenario_atual == "Cenário A (Movimentação Lateral)":
    risk_score = "CRÍTICO"
    risk_color = "inverse"
    blocked_reqs = 345
    alert_log = [
        {
            "Hora": "10:50",
            "Módulo": "Life Support",
            "Evento": "Violação RBAC (Perfil Cientista)",
            "Severidade": "Crítico",
        },
        {
            "Hora": "10:50",
            "Módulo": "PEP-Gateway",
            "Evento": "Tráfego Dropado (Policy 1)",
            "Severidade": "Alerta",
        },
        {
            "Hora": "10:51",
            "Módulo": "IdP",
            "Evento": "Token Cientista Revogado",
            "Severidade": "Alerta",
        },
    ]
    status_commlink = "🟢 Operacional"
    status_life = "🔴 Isolamento Ativo"

else:
    risk_score = "ALTO"
    risk_color = "off"
    blocked_reqs = 8943
    alert_log = [
        {
            "Hora": "10:55",
            "Módulo": "CommLink",
            "Evento": "Pico Anômalo de Tráfego Externo",
            "Severidade": "Crítico",
        },
        {
            "Hora": "10:56",
            "Módulo": "PEP-Gateway",
            "Evento": "Rate Limiting Aplicado",
            "Severidade": "Alerta",
        },
        {
            "Hora": "10:57",
            "Módulo": "CommLink",
            "Evento": "Degradação Graciosa Ativada",
            "Severidade": "Alerta",
        },
    ]
    status_commlink = "🟡 Contingência"
    status_life = "🟢 Air-Gapped"

col1, col2, col3, col4 = st.columns(4)
col1.metric("Nível de Risco Global", risk_score, delta=None, delta_color=risk_color)
col2.metric(
    "Conexões Ativas (mTLS)",
    "142",
    "-3" if cenario_atual != "Operação Normal" else "+2",
)
col3.metric(
    "Requisições Bloqueadas",
    f"{blocked_reqs}",
    delta="Alta Atividade" if blocked_reqs > 100 else "Estável",
    delta_color="inverse",
)
col4.metric("Latência do Motor Zero Trust", "12ms", "Normal")

st.markdown("---")

col5, col6 = st.columns([2, 1])

with col5:
    st.subheader("Tráfego de Rede (CommLink Gateway)")
    chart_data = generate_traffic_data(cenario_atual)
    st.line_chart(chart_data)

with col6:
    st.subheader("Status de Integração (Data Plane)")
    st.markdown("**Energy Core:** 🟢 Air-Gapped")
    st.markdown(f"**Life Support:** {status_life}")
    st.markdown(f"**CommLink:** {status_commlink}")
    st.markdown("**Research Lab:** 🟢 Operacional")
    st.markdown("**Access Hub:** 🟢 Operacional")
    st.markdown("**Logistics Bay:** 🟢 Operacional")

st.markdown("---")

st.subheader("Logs de Auditoria e Resposta a Incidentes (SIEM)")
df_alerts = pd.DataFrame(alert_log)


def color_severity(val):
    color = "#ff4b4b" if val == "Crítico" else "#ffa421" if val == "Alerta" else ""
    return f"color: {color}"


st.dataframe(
    df_alerts.style.map(color_severity, subset=["Severidade"]),
    use_container_width=True,
    hide_index=True,
)
