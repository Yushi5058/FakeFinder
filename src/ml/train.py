"""
Training script for the FakeFinder phishing detection model.

Dataset expected
----------------
Kaggle "Phishing Email Detection" by Subhalaxmi Rout
  https://www.kaggle.com/datasets/subhajournal/phishingemails
  File: Phishing_Email.csv
  Columns: "Email Text", "Email Type"  (Phishing Email / Safe Email)

Usage
-----
From the src/ directory (where manage.py lives):

    python ml/train.py --data ml/Phishing_Email.csv

Optional flags:
    --out   ml/model.joblib   (default output path)
    --trees 200               (number of Random Forest trees, default 200)
"""

import argparse
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split

# Make sure the project root is on sys.path so `ml.features` is importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ml.features import CombinedFeatureTransformer, prepare_email_text  # noqa: E402


def _csv_row_to_text(raw_text: str) -> str:
    """
    Wrap a raw CSV email body in the same dict structure that parse_eml_in_memory()
    produces, then pass it through prepare_email_text().

    This ensures the feature distribution at training time matches inference time,
    fixing the mismatch that caused legitimate emails (e.g. GitHub notifications)
    to be misclassified.
    """
    return prepare_email_text({
        "subject":       "",
        "sender_email":  "",
        "sender_domain": "",
        "body_text":     str(raw_text),
        "urls":          [],
    })


# ── Dataset loading ───────────────────────────────────────────────────────────

def load_dataset(csv_path: str):
    """
    Load the Kaggle Phishing Email CSV.
    Returns X (array of prepared email strings) and y (array of 0/1 labels).
    """
    df = pd.read_csv(csv_path)
    print(f"Loaded {len(df)} rows. Columns: {list(df.columns)}")

    # Auto-detect text column and label column
    text_col = next(
        (c for c in df.columns if "text" in c.lower() or
         ("email" in c.lower() and "type" not in c.lower())),
        df.columns[0],
    )
    label_col = next(
        (c for c in df.columns if "type" in c.lower() or
         "label" in c.lower() or "class" in c.lower()),
        df.columns[1],
    )
    print(f"  text column  : '{text_col}'")
    print(f"  label column : '{label_col}'")

    df = df[[text_col, label_col]].dropna()
    df.columns = ["text", "label"]

    # Normalise labels → 1 = phishing, 0 = safe
    df["label"] = df["label"].str.strip().str.lower().map(
        lambda x: 1 if "phish" in x or "spam" in x else 0
    )

    n_phish = int(df["label"].sum())
    n_safe  = int((df["label"] == 0).sum())
    print(f"  {n_phish} phishing emails, {n_safe} safe emails\n")

    # Apply the same text preparation as inference so train/predict distributions match.
    # dtype=object avoids the massive fixed-width Unicode allocation that np.array()
    # would attempt when strings vary wildly in length.
    print("Preprocessing text (matching inference pipeline)…")
    X_prepared = np.array([_csv_row_to_text(t) for t in df["text"].values], dtype=object)
    return X_prepared, df["label"].values


# ── Training ──────────────────────────────────────────────────────────────────

def train(csv_path: str, output_path: str, n_trees: int):
    X, y = load_dataset(csv_path)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"Train: {len(X_train)} samples  |  Test: {len(X_test)} samples\n")

    # ── Build and fit the feature transformer ────────────────────────────────
    print("Building features (TF-IDF + structural)…")
    transformer = CombinedFeatureTransformer(max_features=20_000, ngram_range=(1, 2))

    X_train_feat = transformer.fit_transform(X_train)
    X_test_feat  = transformer.transform(X_test)
    print(f"Feature matrix shape: {X_train_feat.shape}\n")

    # ── Train Random Forest ───────────────────────────────────────────────────
    print(f"Training Random Forest ({n_trees} trees) + probability calibration…")
    base_clf = RandomForestClassifier(
        n_estimators=n_trees,
        class_weight="balanced",
        random_state=42,
        n_jobs=1,
    )
    # CalibratedClassifierCV corrects RF probability bias (tendency to cluster near 0.5)
    # isotonic regression works well for large datasets (>1000 samples)
    clf = CalibratedClassifierCV(base_clf, method="isotonic", cv=5)
    clf.fit(X_train_feat, y_train)

    # ── Evaluate ──────────────────────────────────────────────────────────────
    y_pred  = clf.predict(X_test_feat)
    y_proba = clf.predict_proba(X_test_feat)[:, 1]

    print("\n-- Evaluation results -----------------------------------------")
    print(classification_report(y_test, y_pred, target_names=["Safe", "Phishing"]))
    print(f"ROC-AUC : {roc_auc_score(y_test, y_proba):.4f}")
    print("---------------------------------------------------------------\n")

    # ── Save model bundle ─────────────────────────────────────────────────────
    bundle = {
        "transformer": transformer,
        "classifier":  clf,
    }
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, out)
    print(f"Model saved → {out.resolve()}")
    print("Done. You can now run the Django server and upload .eml files.\n")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Train the FakeFinder phishing detection model."
    )
    parser.add_argument(
        "--data",
        required=True,
        help="Path to Phishing_Email.csv",
    )
    parser.add_argument(
        "--out",
        default="ml/model.joblib",
        help="Output path for the saved model (default: ml/model.joblib)",
    )
    parser.add_argument(
        "--trees",
        type=int,
        default=200,
        help="Number of Random Forest trees (default: 200)",
    )
    args = parser.parse_args()
    train(args.data, args.out, args.trees)
