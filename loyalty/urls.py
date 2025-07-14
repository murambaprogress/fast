from django.urls import path
from .views import (
    get_user_points,
    get_user_transactions,
    redemption_view,
    admin_redemptions,
    admin_redemption_action,
)

urlpatterns = [
    path('points/', get_user_points, name='user-points'),
    path('transactions/', get_user_transactions, name='user-transactions'),
    path('redemptions/', redemption_view, name='redemptions'),
    path('admin/redemptions/', admin_redemptions, name='admin-redemptions'),
    path('admin/redemptions/<int:redemption_id>/', admin_redemption_action, name='admin-redemption-action'),
]
