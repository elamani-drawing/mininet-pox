import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
TMP_DIR =  "/tmp/pox/"
# Charger le dataset
df = pd.read_csv(TMP_DIR+"pox_features.csv")

# Supprimer les colonnes inutiles (timestamp, src_ip)
features = df.drop(["timestamp", "src_ip"], axis=1)

# Normalisation
scaler = StandardScaler()
X_scaled = scaler.fit_transform(features)

# Entraîner Isolation Forest (100 % de trafic normal)
model = IsolationForest(
    n_estimators=200,
    contamination=0.01,  # taux d'anomalies attendu
    random_state=42
)

model.fit(X_scaled)

# Sauvegarder modèle + scaler
joblib.dump(model, TMP_DIR+"iforest_model.pkl")
joblib.dump(scaler, TMP_DIR+"scaler.pkl")

print(f"Model sauvegardé dans le dossier {TMP_DIR}.")