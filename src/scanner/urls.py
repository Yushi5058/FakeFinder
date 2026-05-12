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

    # Admin routes
    path("admin-panel/", views.admin_dashboard, name="admin_dashboard"),
    path("admin-panel/users/", views.admin_user_list, name="admin_user_list"),
    path("admin-panel/report/<int:report_id>/delete/", views.admin_delete_report, name="admin_delete_report"),
    path("admin-panel/train-model/", views.admin_train_model, name="admin_train_model"),
]
