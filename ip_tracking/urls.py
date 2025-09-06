from django.urls import path
from . import views

app_name = 'ip_tracking'

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('api/status/', views.api_status, name='api_status'),
]
