"""
EdgeShield MLP threat classifier training script.

Usage:
    pip install scikit-learn numpy pandas
    python scripts/train_model.py

Outputs model/weights.json — upload to KV with:
    npx wrangler kv key put --namespace-id=<ID> --remote "model:mlp-v1" --path=model/weights.json
"""

import json, numpy as np
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

np.random.seed(42)
N = 10000

def generate_dataset(n):
    """
    Features (12):
      0  botScore          1-uaScore  (0-1)
      1  ruleMatchCount    matches/10
      2  ruleScoreSum      score/300
      3  hasBlockAction    0/1
      4  ipRepScore        0-1
      5  cfThreatScore     /100
      6  isKnownBadUA      0/1
      7  isDatacenter      0/1
      8  headerAnomalyScore 0-1
      9  pathDepth         /10
      10 queryParamCount   /20
      11 methodRisk        GET=0,POST=0.3,DELETE=0.7
    """
    X, y = [], []

    # Clean legit traffic (60%)
    n_clean = int(n * 0.6)
    for _ in range(n_clean):
        X.append([
            np.random.uniform(0, 0.15),   # low bot score
            0, 0, 0,                       # no rule hits
            np.random.uniform(0, 0.1),    # low ip rep
            np.random.uniform(0, 5) / 100,# low cf score
            0, 0, 0,                       # clean signals
            np.random.uniform(0, 0.3),    # shallow path
            np.random.uniform(0, 0.2),    # few params
            np.random.choice([0, 0.3]),    # GET or POST
        ])
        y.append(0)

    # Scanners without rule hits (15%)
    n_scan = int(n * 0.15)
    for _ in range(n_scan):
        X.append([
            np.random.uniform(0.7, 1.0),  # high bot score
            0, 0, 0,
            np.random.uniform(0, 0.3),
            np.random.uniform(0, 10) / 100,
            np.random.choice([0, 1], p=[0.3, 0.7]),
            np.random.choice([0, 1], p=[0.4, 0.6]),
            np.random.uniform(0.5, 1.0),
            np.random.uniform(0.1, 0.6),
            np.random.uniform(0.1, 0.5),
            np.random.choice([0, 0.3, 0.7]),
        ])
        y.append(1)

    # Attacks with rule hits (25%)
    n_attack = n - n_clean - n_scan
    for _ in range(n_attack):
        matches = np.random.randint(1, 5)
        score_sum = min(matches * np.random.uniform(40, 90), 300)
        X.append([
            np.random.uniform(0.4, 1.0),
            min(matches, 10) / 10,
            score_sum / 300,
            1,
            np.random.uniform(0.1, 0.8),
            np.random.uniform(0, 30) / 100,
            np.random.choice([0, 1]),
            np.random.choice([0, 1]),
            np.random.uniform(0.3, 1.0),
            np.random.uniform(0, 0.5),
            np.random.uniform(0.1, 0.8),
            np.random.choice([0, 0.3, 0.7]),
        ])
        y.append(1)

    return np.array(X), np.array(y)

X, y = generate_dataset(N)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = MLPClassifier(
    hidden_layer_sizes=(8, 4),
    activation="relu",
    max_iter=500,
    random_state=42,
)
model.fit(X_train, y_train)

print(classification_report(y_test, model.predict(X_test)))

# Export weights to JSON (no framework needed at inference time)
weights = {
    "architecture": "MLP-12-8-4-1",
    "version": "1.0.0",
    "trained_samples": N,
    "accuracy": float(model.score(X_test, y_test)),
    "W": [layer.tolist() for layer in model.coefs_],
    "b": [bias.tolist() for bias in model.intercepts_],
}

with open("model/weights.json", "w") as f:
    json.dump(weights, f, indent=2)

print("Saved to model/weights.json")
print("Upload with:")
print("  npx wrangler kv key put --namespace-id=c9d04c1148d246e3a6f1a2038c7fca92 --remote 'model:mlp-v1' --path=model/weights.json")
