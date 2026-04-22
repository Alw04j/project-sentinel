from django.urls import path
from . import views

urlpatterns = [
    path('', views.home_dashboard, name='home'),
    path('scan/', views.phish_scan, name='phish_scan'),
    path('network-scan/', views.network_scanner_view, name='network_scan'),
    path('history/', views.scan_history, name='history'),
    path('remediate/smb/', views.remediate_smb, name='remediate_smb'),
    path('login/', views.login_view, name='login'),
    path('signup/', views.signup_view, name='signup'),
    path('logout/', views.logout_view, name='logout'),
    path('vulnerabilities/', views.vulnerability_report, name='vuln_report'),
]