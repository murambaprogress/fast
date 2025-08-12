from django.urls import path
from . import views

urlpatterns = [
    path('points/', views.get_user_points, name='get_user_points'),
    path('transactions/', views.get_user_transactions, name='get_user_transactions'),
    path('redemptions/', views.redemption_view, name='redemption_view'),
    path('admin/redemptions/', views.admin_redemptions, name='admin_redemptions'),
    path('admin/redemptions/<int:redemption_id>/action/', views.admin_redemption_action, name='admin_redemption_action'),
]