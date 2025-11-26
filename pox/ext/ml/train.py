import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib 
DIR_TMP = "/tmp/pox/"
DIR_FEATURES = DIR_TMP+ "features/"
DIR_MODELS = DIR_TMP+ "models/"
# Charger le dataset
df = pd.read_csv(DIR_FEATURES+"pox_features.csv")

# Supprimer les colonnes inutiles (timestamp, src_ip)
features = df.drop(["timestamp", "src_ip"], axis=1)
# features = df.values

# Normalisation
scaler = StandardScaler()
X_scaled = scaler.fit_transform(features)

# Entraîner Isolation Forest
model = IsolationForest(
    n_estimators=300,
    contamination=0.001,  # taux d'anomalies attendu
    random_state=42
)

model.fit(X_scaled)

y_pred = model.predict(X_scaled)  
anom_count = (y_pred == -1).sum()
print(f"Faux positifs sur trafic normal : {anom_count}/{len(X_scaled)}")

# Sauvegarder modèle + scaler
joblib.dump(model, DIR_MODELS+"iforest_model.pkl")
joblib.dump(scaler, DIR_MODELS+"scaler.pkl")

print(f"Model sauvegardé dans le dossier {DIR_MODELS}.")