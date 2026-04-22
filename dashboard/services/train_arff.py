"""
train_arff.py
─────────────
Defines MODEL_PATH and provides a train_model() utility.
The model is loaded in views.py at startup via MODEL_PATH.

Dataset: UCI Phishing Websites (30 features, label = -1/phishing, 1/legitimate)
"""

import os
import joblib

# ─── Paths ────────────────────────────────────────────────────────────────────
# dashboard/services/train_arff.py  →  go up 3 levels to reach project root
_SERVICE_DIR = os.path.dirname(os.path.abspath(__file__))   # .../dashboard/services/
_APP_DIR     = os.path.dirname(_SERVICE_DIR)                 # .../dashboard/
_PROJECT_DIR = os.path.dirname(_APP_DIR)                     # .../Sentinel 2/

MODEL_PATH = os.path.join(_PROJECT_DIR, 'data', 'phish_model.pkl')
ARFF_PATH  = os.path.join(_PROJECT_DIR, 'data', 'Training Data.arff')


# ─── Training Utility ─────────────────────────────────────────────────────────
def train_model():
    """
    Train a RandomForest classifier on the ARFF dataset and save it.
    Call this once from manage.py shell or a management command if
    phish_model.pkl doesn't exist yet.

    Usage:
        from dashboard.services.train_arff import train_model
        train_model()
    """
    try:
        import numpy as np
        import pandas as pd
        from scipy.io import arff
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import accuracy_score
    except ImportError as e:
        raise ImportError(
            f"Missing dependency: {e}\n"
            "Install with: pip install scikit-learn scipy pandas"
        )

    print(f"📂 Loading ARFF from: {ARFF_PATH}")
    data, meta = arff.loadarff(ARFF_PATH)
    df = pd.DataFrame(data)

    # ARFF bytes → int
    for col in df.columns:
        df[col] = df[col].apply(
            lambda x: int(x.decode()) if isinstance(x, bytes) else int(x)
        )

    X = df.iloc[:, :-1].values   # 30 features
    y = df.iloc[:, -1].values    # label: -1 (phishing) or 1 (legit)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)

    acc = accuracy_score(y_test, clf.predict(X_test))
    print(f"✅ Model trained — Test Accuracy: {acc * 100:.2f}%")

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    print(f"💾 Model saved to: {MODEL_PATH}")
    return clf


# ─── Auto-train if model missing ──────────────────────────────────────────────
if not os.path.exists(MODEL_PATH):
    if os.path.exists(ARFF_PATH):
        print("⚠️  phish_model.pkl not found. Training now...")
        try:
            train_model()
        except Exception as e:
            print(f"❌ Auto-training failed: {e}")
    else:
        print(
            f"⚠️  Neither model ({MODEL_PATH}) nor ARFF ({ARFF_PATH}) found.\n"
            "    Place 'Training Data.arff' in the /data/ folder and run train_model()."
        )
