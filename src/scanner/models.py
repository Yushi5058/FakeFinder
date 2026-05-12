from django.db import models
from django.contrib.auth.models import User


class ScanReport(models.Model):
    """
    Stores the results of the email analysis without saving the raw .eml content.
    """

    # Risk scores and visual color codes
    RISK_CHOICES = [
        ("LOW", "Low (Green)"),
        ("MEDIUM", "Medium (Orange)"),
        ("HIGH", "High (Red)"),
    ]

    # User who submitted the scan (Admin/User)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    # Overall risk assessment
    risk_score = models.CharField(max_length=10, choices=RISK_CHOICES, default="LOW")

    # Numeric score 0–100 produced by the ML model (0 = safe, 100 = phishing)
    score = models.IntegerField(default=0)

    # Storing identified suspicious elements in JSON format
    # This accommodates automatic URL extraction and header anomaly checks
    suspicious_urls = models.JSONField(default=list, blank=True)
    header_anomalies = models.JSONField(default=list, blank=True)

    def __str__(self):
        return f"Report #{self.id} - Score: {self.get_risk_score_display()} - {self.created_at.strftime('%Y-%m-%d %H:%M')}"
