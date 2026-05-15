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


class Signature(models.Model):
    """
    Stores cryptographic hashes of known phishing indicators (URLs or file content).
    Used for fast lookup before running the ML model.
    """
    TYPE_CHOICES = [
        ('URL', 'URL Hash'),
        ('MD5', 'File MD5'),
        ('SHA256', 'File SHA256'),
    ]

    indicator_hash = models.CharField(max_length=64, unique=True, db_index=True)
    indicator_type = models.CharField(max_length=10, choices=TYPE_CHOICES)
    description = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.indicator_type}: {self.indicator_hash[:16]}..."


class TrustedDomain(models.Model):
    """
    Domains that are considered safe (e.g., github.com, google.com).
    Emails from these domains receive a risk score reduction.
    """
    domain = models.CharField(max_length=255, unique=True, db_index=True)
    description = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.domain
