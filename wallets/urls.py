from django.urls import path
from .views import top_up_balance, get_wallet_by_user_id, deduct_balance, UserWalletView

urlpatterns = [
    path('currencies/', get_wallet_by_user_id, name='get_wallet_by_user_id'),
    path('<int:user_id>/deduct/<str:currency_code>/', deduct_balance, name='deduct_balance'),
    path('<int:user_id>/topup/<str:currency_code>/', top_up_balance, name='top_up_balance'),
    path('<int:user_id>/wallet/', UserWalletView.as_view(), name='user_wallet'),
]
