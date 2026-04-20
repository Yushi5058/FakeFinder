from django.urls import path
from . import views

urlpatterns = [
    # Route for the main responsive upload interface
    path("", views.upload_email, name="upload_email"),
    # Route to view the generated detailed report
    path("report/<int:report_id>/", views.report_detail, name="report_detail"),
]
