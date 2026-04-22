from django.shortcuts import redirect, render, get_object_or_404

from .utils import parse_eml_in_memory
from .models import ScanReport
from django.http import HttpResponseBadRequest
# Placeholder for Scikit-learn model integration
# import joblib
# ml_model = joblib.load('path/to/your/model.pkl')


def report_detail(request, report_id):
    report = get_object_or_404(ScanReport, id=report_id)
    return render(request, "scanner/report.html", {"report": report})


def upload_email(request):
    """
    Handles the web interface for dropping .eml files.
    """
    if request.method == "POST":
        eml_file = request.FILES.get("eml_file")

        if not eml_file or not eml_file.name.endswith(".eml"):
            return HttpResponseBadRequest("Please upload a valid .eml file")
        parsed_data = parse_eml_in_memory(eml_file)
        # TODO : Machine learning goes here later
        report = ScanReport.objects.create(
            user=request.user if request.user.is_authenticated else None,
            risk_score="MEDIUM",
            suspicious_urls=parsed_data["urls"],
            header_anomalies=[{"sender_domain": parsed_data["sender_domain"]}],
        )
        return redirect("report_detail", report_id=report.id)

    return render(request, "scanner/upload.html")


def report_detail(request, report_id):
    """
    Generates a detailed report explaining the assigned risk score.
    """
    report = get_object_or_404(ScanReport, id=report_id)

    # The template 'fakefinder/report.html' will handle the visual alert formatting (Green/Orange/Red).
    return render(request, "scanner/report.html", {"report": report})
