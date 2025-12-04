"""
BancABC Dashboard URLs
"""
from django.urls import path
from . import bancabc_views

app_name = 'bancabc'

urlpatterns = [
    # Dashboard views
    path('dashboard/', bancabc_views.bancabc_dashboard, name='dashboard'),
    path('transactions/', bancabc_views.bancabc_transactions, name='transactions'),
    path('transactions/<int:transaction_id>/', bancabc_views.bancabc_transaction_detail, name='transaction_detail'),
    path('reports/', bancabc_views.bancabc_reports, name='reports'),
    
    # Export
    path('export/csv/', bancabc_views.bancabc_export_csv, name='export_csv'),
    
    # API endpoints
    path('api/stats/', bancabc_views.bancabc_api_stats, name='api_stats'),
    path('api/verify/<int:transaction_id>/', bancabc_views.bancabc_verify_transaction, name='verify_transaction'),
]
