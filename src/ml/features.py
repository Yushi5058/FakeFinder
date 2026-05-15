"""
Feature extraction for phishing email detection.

Two types of features are combined:
  - TF-IDF on the full email text (subject + body + sender)
  - Structural features (URL count, urgency keywords, HTML presence, etc.)

The CombinedFeatureTransformer class must stay in this file so that
joblib can re-import it correctly when loading a saved model.
"""

import re

import numpy as np
import scipy.sparse as sp
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer


# Keywords strongly associated with phishing emails
PHISHING_KEYWORDS = [
    "verify", "account", "update", "confirm", "click here", "urgent",
    "immediately", "suspended", "limited", "expires", "login", "password",
    "bank", "credit", "debit", "security", "alert", "winner",
    "congratulations", "free", "prize", "claim", "offer",
    "dear customer", "valued customer", "paypal", "amazon",
    "24 hours", "48 hours", "act now", "validate",
    "unusual activity", "suspicious", "blocked", "restricted",
    "your account", "reset", "temporary", "reactivate",
    "crypto", "wallet", "metamask", "ledger", "binance", "coinbase",
    "ethereum", "bitcoin", "nft", "airdrop", "seed phrase", "private key",
    "authorize", "connect wallet", "pancakeswap", "uniswap", "token",
]

# Common URL shortener domains used in phishing
SHORT_URL_PATTERN = re.compile(
    r"bit\.ly|tinyurl\.com|goo\.gl|t\.co|ow\.ly|short\.link|rb\.gy|cutt\.ly",
    re.IGNORECASE,
)

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


class StructuralFeatureExtractor(BaseEstimator, TransformerMixin):
    """
    Extracts hand-crafted numerical features from raw email text.
    Output is a sparse CSR matrix (one row per email, 10 columns).
    """

    FEATURE_NAMES = [
        "url_count",
        "html_link_count",
        "has_short_url",
        "exclamation_count",
        "dollar_count",
        "phishing_keyword_score",
        "has_html_tags",
        "has_email_in_body",
        "normalized_length",
        "caps_word_count",
    ]

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        rows = []
        for text in X:
            t = text.lower()
            words = text.split()

            urls = URL_PATTERN.findall(t)
            html_links = len(re.findall(r"href=", t))
            has_short = int(bool(SHORT_URL_PATTERN.search(t)))
            exclamations = min(text.count("!"), 20)
            dollars = min(text.count("$"), 10)
            keyword_score = sum(1 for kw in PHISHING_KEYWORDS if kw in t)
            has_html = int("<html" in t or "<body" in t or "<div" in t)
            has_email_body = int(bool(re.search(r"[\w.+-]+@[\w-]+\.[a-z]{2,}", t)))
            norm_len = min(len(words), 3000) / 3000
            caps_words = sum(1 for w in words[:60] if len(w) > 2 and w.isupper())

            rows.append([
                len(urls),
                html_links,
                has_short,
                exclamations,
                dollars,
                keyword_score,
                has_html,
                has_email_body,
                norm_len,
                caps_words,
            ])

        return sp.csr_matrix(np.array(rows, dtype=float))


class CombinedFeatureTransformer:
    """
    Combines TF-IDF text features with structural features into one matrix.

    Must live in ml/features.py (not train.py) so joblib can
    deserialise it correctly when loading a saved model bundle.
    """

    def __init__(self, max_features: int = 20_000, ngram_range: tuple = (1, 2)):
        self.tfidf = TfidfVectorizer(
            max_features=max_features,
            ngram_range=ngram_range,
            sublinear_tf=True,
            strip_accents="unicode",
            analyzer="word",
            token_pattern=r"\w{2,}",
            min_df=2,
        )
        self.structural = StructuralFeatureExtractor()

    def fit(self, X, y=None):
        self.tfidf.fit(X)
        return self

    def transform(self, X):
        return sp.hstack([
            self.tfidf.transform(X),
            self.structural.transform(X),
        ])

    def fit_transform(self, X, y=None):
        return sp.hstack([
            self.tfidf.fit_transform(X),
            self.structural.transform(X),
        ])


# ── Helpers used by views.py ─────────────────────────────────────────────────

def prepare_email_text(parsed: dict) -> str:
    """
    Concatenate all email fields into one string for the transformer.
    `parsed` is the dict returned by parse_eml_in_memory().
    """
    parts = [
        str(parsed.get("subject", "") or ""),
        str(parsed.get("sender_email", "") or ""),
        str(parsed.get("sender_domain", "") or ""),
        str(parsed.get("body_text", "") or ""),
        " ".join(str(u) for u in parsed.get("urls", [])),
    ]
    return " ".join(p for p in parts if p)


def probability_to_verdict(proba: float) -> tuple:
    """
    Convert a phishing probability (0.0–1.0) to a risk label and 0-100 score.

    Thresholds are intentionally conservative on the HIGH end:
      - LOW    < 0.30  → clearly safe
      - MEDIUM 0.30–0.72 → ambiguous, needs review
      - HIGH   ≥ 0.72  → strong phishing signal

    Returns:
        (risk_score: str, score: int)
        risk_score is one of: 'LOW', 'MEDIUM', 'HIGH'
    """
    score = round(proba * 100)
    if proba < 0.30:
        return "LOW", score
    elif proba < 0.72:
        return "MEDIUM", score
    else:
        return "HIGH", score
