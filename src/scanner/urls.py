from django.urls import path
from . import views

urlpatterns = [
    path("", views.upload_email, name="upload_email"),
    path("report/<int:report_id>/", views.report_detail, name="report_detail"),
    path("report/<int:report_id>/delete/", views.delete_report, name="delete_report"),
    path("history/delete/", views.delete_all_reports, name="delete_all_reports"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("register/", views.register_view, name="register"),
]
