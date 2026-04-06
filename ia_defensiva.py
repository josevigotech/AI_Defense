import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
import joblib
import os
import re
import datetime
import requests  # Necesario para los países

# ---------------------------------------------------------
# 0. Configuración
# ---------------------------------------------------------
ARCHIVO_DASHBOARD = 'dashboard_datos.csv'

def obtener_pais(ip):
    if ip == "0.0.0.0" or not ip: return "Desconocido"
    try:
        # Consultamos una API gratuita de geolocalización
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=country", timeout=3).json()
        return response.get("country", "Desconocido")
    except: return "Error API"

def extraer_datos_logs():
    eventos = []
    ruta = 'log_analyzer/log_analyzer/' if os.path.exists('log_analyzer/log_analyzer/') else 'log_analyzer/'
    
    # 1. Leer auth.log (Buscando IPs de origen)
    p_auth = os.path.join(ruta, 'auth.log')
    if os.path.exists(p_auth):
        with open(p_auth, 'r', encoding='utf-8', errors='ignore') as f:
            for l in f:
                if "authentication failure" in l:
                    try:
                        h = int(l.split()[2].split(':')[0])
                        ip_match = re.search(r'rhost=([\d\.]+)', l)
                        ip = ip_match.group(1) if ip_match else "0.0.0.0"
                        eventos.append({'hora': h, 'tipo': 1, 'critico': 1 if "root" in l else 0, 'puerto': 0, 'ip': ip})
                    except: continue

    # 2. Leer ufw.log (Buscando IPs de origen)
    p_ufw = os.path.join(ruta, 'ufw.log')
    if os.path.exists(p_ufw):
        with open(p_ufw, 'r', encoding='utf-8', errors='ignore') as f:
            for l in f:
                if "[UFW BLOCK]" in l:
                    try:
                        h = int(l.split()[2].split(':')[0])
                        pt = int(re.search(r'DPT=(\d+)', l).group(1)) if re.search(r'DPT=(\d+)', l) else 0
                        ip_match = re.search(r'SRC=([\d\.]+)', l)
                        ip = ip_match.group(1) if ip_match else "0.0.0.0"
                        eventos.append({'hora': h, 'tipo': 2, 'critico': 0, 'puerto': pt, 'ip': ip})
                    except: continue
    
    return pd.DataFrame(eventos)

# ---------------------------------------------------------
# 1. Ejecución de la IA
# ---------------------------------------------------------
data = extraer_datos_logs()

if not data.empty:
    print(f"--- Procesando {len(data)} eventos con IA ---")
    
    scaler = StandardScaler()
    feats = ['hora', 'tipo', 'critico', 'puerto']
    scaled = scaler.fit_transform(data[feats])
    
    model = IsolationForest(contamination=0.05, random_state=42)
    data['anomaly'] = model.fit_predict(scaled)
    data['score'] = model.decision_function(scaled)

    # Filtramos anomalías (ajusta el score si quieres más o menos resultados)
    anomalias = data[(data['anomaly'] == -1) & (data['score'] < 0.00)].copy()
    
    if not anomalias.empty:
        print(f" Detectadas {len(anomalias)} anomalías. Buscando países...")
        
        # Enriquecer datos
        anomalias['pais'] = anomalias['ip'].apply(obtener_pais)
        anomalias['fecha_registro'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Guardar en el histórico para el Dashboard
        es_nuevo = not os.path.exists(ARCHIVO_DASHBOARD)
        anomalias.to_csv(ARCHIVO_DASHBOARD, mode='a', index=False, header=es_nuevo)
        
        print(f" Dashboard actualizado con {len(anomalias)} eventos.")
        print(anomalias[['hora', 'ip', 'pais', 'score']].head())

    joblib.dump(model, "ia_defensiva_real.pkl")
else:
    print("No hay datos en los logs.")