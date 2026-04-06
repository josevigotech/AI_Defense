import streamlit as st
import pandas as pd
import plotly.express as px
import os

# Configuración de la página (esto siempre debe ir primero)
st.set_page_config(page_title="SOC - IA Defensiva", layout="wide", page_icon="🛡️")

# Estilo de título y subtítulo
st.title(" SOC Dashboard - Inteligencia de Amenazas")
st.markdown("""
Análisis de anomalías en tiempo real mediante **Isolation Forest**. 
Este sistema detecta patrones sospechosos en logs de acceso y reglas de Firewall.
""")

# Verificar si el archivo generado por la IA existe
if os.path.exists('dashboard_datos.csv'):
    df = pd.read_csv('dashboard_datos.csv')
    
    # ---------------------------------------------------------
    # 1. MÉTRICAS PRINCIPALES KPIs
    # ---------------------------------------------------------
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Anomalías", len(df), delta_color="inverse")
    with col2:
        # Contar fallos de login (Tipo 1)
        logins = len(df[df['tipo'] == 1])
        st.metric("Alertas de Login", logins)
    with col3:
        # Contar bloqueos de Firewall (Tipo 2)
        firewall = len(df[df['tipo'] == 2])
        st.metric("Bloqueos Firewall", firewall)
    with col4:
        # Países diferentes identificados
        paises_unicos = df['pais'].nunique() if 'pais' in df.columns else 0
        st.metric("Países Origen", paises_unicos)

    st.divider()

    # ---------------------------------------------------------
    # 2. GEOLOCALIZACIÓN (MAPA MUNDIAL)
    # ---------------------------------------------------------
    if 'pais' in df.columns:
        st.subheader(" Origen Global de los Ataques")
        conteo_paises = df['pais'].value_counts().reset_index()
        conteo_paises.columns = ['pais', 'ataques']
        
        fig_mapa = px.choropleth(
            conteo_paises, 
            locations="pais", 
            locationmode='country names',
            color="ataques", 
            hover_name="pais", 
            color_continuous_scale=px.colors.sequential.Reds,
            template="plotly_dark"
        )
        fig_mapa.update_layout(margin={"r":0,"t":0,"l":0,"b":0})
        st.plotly_chart(fig_mapa, use_container_width=True)
    
    st.divider()

    # ---------------------------------------------------------
    # 3. GRÁFICAS TEMPORALES Y DETALLES
    # ---------------------------------------------------------
    fila_graficas_col1, fila_graficas_col2 = st.columns(2)

    with fila_graficas_col1:
        st.subheader(" Distribución por Hora")
        fig_hora = px.histogram(
            df, x="hora", nbins=24, color="tipo",
            labels={'tipo': 'Tipo de Evento (1:Login, 2:FW)'},
            color_discrete_map={1: '#EF553B', 2: '#636EFA'},
            template="plotly_dark"
        )
        st.plotly_chart(fig_hora, use_container_width=True)

    with fila_graficas_col2:
        st.subheader(" Gravedad de Eventos (Score)")
        # Cuanto más bajo el score, más "anómalo" es
        fig_score = px.scatter(
            df, x="fecha_registro", y="score", 
            color="tipo", size="hora",
            hover_data=['ip', 'pais'] if 'ip' in df.columns else ['hora'],
            template="plotly_dark"
        )
        st.plotly_chart(fig_score, use_container_width=True)

    # ---------------------------------------------------------
    # 4. TABLA DE REGISTROS CRUDOS
    # ---------------------------------------------------------
    st.divider()
    st.subheader(" Registro Detallado de Amenazas")
    
    # Seleccionamos las columnas que queremos mostrar
    columnas_mostrar = ['fecha_registro', 'hora', 'tipo', 'score']
    if 'ip' in df.columns: columnas_mostrar.append('ip')
    if 'pais' in df.columns: columnas_mostrar.append('pais')
    if 'puerto' in df.columns: columnas_mostrar.append('puerto')

    st.dataframe(
        df[columnas_mostrar].sort_values(by='score', ascending=True), 
        use_container_width=True
    )

else:
    # Mensaje en caso de que no existan datos todavía
    st.info(" ¡Bienvenido! Aún no hay datos para mostrar.")
    st.warning("Asegúrate de ejecutar **python ia_defensiva.py** para procesar los logs y generar el archivo 'dashboard_datos.csv'.")
