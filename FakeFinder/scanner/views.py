from django.shortcuts import render, redirect, get_object_or_404
from .models import ScanReport

# Placeholder for Scikit-learn model integration
# import joblib
# ml_model = joblib.load('path/to/your/model.pkl')


def upload_email(request):
    """
    Handles the web interface for dropping .eml files.
    """
    if request.method == "POST":
        eml_file = request.FILES.get("eml_file")

        if eml_file:
            # TODO: Implement the parsing logic here to extract URLs and headers.
            # TODO: Pass the extracted features to the Scikit-learn ML model.

            # Mocking the creation of a report for the prototype
            report = ScanReport.objects.create(
                user=request.user if request.user.is_authenticated else None,
                risk_score="HIGH",
                suspicious_urls=["http://example-phishing-link.com/login"],
                header_anomalies=["Spoofed Sender Domain: Mismatched Return-Path"],
            )

            # Redirecting directly to the report satisfies the < 3 clicks requirement.
            return redirect("report_detail", report_id=report.id)

    return render(request, "fakefinder/upload.html")


def report_detail(request, report_id):
    """
    Generates a detailed report explaining the assigned risk score.
    """
    report = get_object_or_404(ScanReport, id=report_id)

    # The template 'fakefinder/report.html' will handle the visual alert formatting (Green/Orange/Red).
    return render(request, "fakefinder/report.html", {"report": report})
