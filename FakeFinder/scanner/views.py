import time
from pathlib import Path

import joblib
from django.conf import settings
from django.http import HttpResponseBadRequest
from django.shortcuts import get_object_or_404, redirect, render

from .models import ScanReport
from .utils import parse_eml_in_memory

# ── ML model — loaded once on first use ──────────────────────────────────────

_model_bundle = None
MODEL_PATH = Path(settings.BASE_DIR) / "ml" / "model.joblib"


def _get_model():
    """Load the model bundle from disk the first time it is needed."""
    global _model_bundle
    if _model_bundle is None and MODEL_PATH.exists():
        _model_bundle = joblib.load(MODEL_PATH)
    return _model_bundle


def _predict(parsed_data: dict) -> tuple:
    """
    Run the ML model on the parsed email data.

    Returns (risk_score: str, score: int).
    Falls back to 'MEDIUM' / 50 if the model is not yet trained.
    """
    bundle = _get_model()
    if bundle is None:
        # Model not trained yet — neutral fallback
        return "MEDIUM", 50

    from ml.features import prepare_email_text, probability_to_verdict

    text = prepare_email_text(parsed_data)
    transformer = bundle["transformer"]
    classifier  = bundle["classifier"]

    features = transformer.transform([text])
    proba = classifier.predict_proba(features)[0][1]   # P(phishing)
    return probability_to_verdict(proba)


# ── Views ─────────────────────────────────────────────────────────────────────

def upload_email(request):
    if request.method == "POST":
        eml_file = request.FILES.get("eml_file")

        if not eml_file or not eml_file.name.lower().endswith(".eml"):
            return HttpResponseBadRequest("Veuillez téléverser un fichier .eml valide.")

        pipeline_start = time.perf_counter()

        try:
            parsed_data = parse_eml_in_memory(eml_file)
        except ValueError as e:
            return HttpResponseBadRequest(str(e))

        risk_score, score = _predict(parsed_data)

        report = ScanReport.objects.create(
            user=request.user if request.user.is_authenticated else None,
            risk_score=risk_score,
            score=score,
            suspicious_urls=parsed_data["urls"],
            header_anomalies=[{
                "sender_domain": parsed_data["sender_domain"],
                "sender_email":  parsed_data.get("sender_email", ""),
                "subject":       parsed_data.get("subject", ""),
                "filename":      eml_file.name,
            }],
        )

        elapsed = time.perf_counter() - pipeline_start
        print(f"[Benchmark] Parse + ML + Save: {elapsed:.3f}s")

        return redirect("report_detail", report_id=report.id)

    return render(request, "scanner/upload.html")


def report_detail(request, report_id):
    report = get_object_or_404(ScanReport, id=report_id)
    return render(request, "scanner/report.html", {"report": report})
