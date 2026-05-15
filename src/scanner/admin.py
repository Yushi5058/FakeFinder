from django.contrib import admin
from .models import ScanReport, Signature, TrustedDomain

@admin.register(ScanReport)
class ScanReportAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'risk_score', 'score', 'created_at')
    list_filter = ('risk_score', 'created_at')
    search_fields = ('user__username', 'id')
    readonly_fields = ('created_at',)

@admin.register(Signature)
class SignatureAdmin(admin.ModelAdmin):
    list_display = ('indicator_type', 'indicator_hash', 'description', 'created_at')
    list_filter = ('indicator_type',)
    search_fields = ('indicator_hash', 'description')

@admin.register(TrustedDomain)
class TrustedDomainAdmin(admin.ModelAdmin):
    list_display = ('domain', 'description', 'created_at')
    search_fields = ('domain', 'description')
