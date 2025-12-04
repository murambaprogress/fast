from django.urls import path
from .views import (
    top_up_balance, 
    get_wallet_by_user_id, 
    deduct_balance, 
    UserWalletView, 
    bancabc_payment_success, 
    bancabc_payment_failure, 
    bancabc_account_update, 
    bancabc_initiate_payment, 
    bancabc_payment_status,
    bancabc_wallet_validation,
    bancabc_credit_push,
    bancabc_transaction_report,
    bancabc_payment_notification,
    innbucks_generate_code,
    innbucks_check_payment_status,
    innbucks_simulate_scan
)
from .views_ecocash import (
    ecocash_initiate_payment,
    ecocash_refund_payment,
    ecocash_transaction_status,
    ecocash_webhook,
    ecocash_transactions,
    ecocash_notify_handler
)
from .views_ecocash_history import ecocash_transaction_history
from .views_payment_history import innbucks_transaction_history, omari_transaction_history

urlpatterns = [
    path('currencies/', get_wallet_by_user_id, name='get_wallet_by_user_id'),
    path('<int:user_id>/deduct/<str:currency_code>/', deduct_balance, name='deduct_balance'),
    path('<int:user_id>/topup/<str:currency_code>/', top_up_balance, name='top_up_balance'),
    path('<int:user_id>/wallet/', UserWalletView.as_view(), name='user_wallet'),
    
    # BANCABC Payment Integration Endpoints
    path('bancabc/payment/success/', bancabc_payment_success, name='bancabc_payment_success'),
    path('bancabc/payment/failure/', bancabc_payment_failure, name='bancabc_payment_failure'),
    path('bancabc/account/update/', bancabc_account_update, name='bancabc_account_update'),
    path('bancabc/initiate-payment/', bancabc_initiate_payment, name='bancabc_initiate_payment'),
    path('bancabc/payment-status/<str:transaction_id>/', bancabc_payment_status, name='bancabc_payment_status'),
    
    # BANCABC New Integration APIs (Dec 2025) - For BancABC to push credits to customer wallets
    path('bancabc/wallet/validate/', bancabc_wallet_validation, name='bancabc_wallet_validation'),
    path('bancabc/payment/notify/', bancabc_payment_notification, name='bancabc_payment_notification'),
    path('bancabc/wallet/credit/', bancabc_credit_push, name='bancabc_credit_push'),
    path('bancabc/transactions/report/', bancabc_transaction_report, name='bancabc_transaction_report'),
    
    # InnBucks Payment Integration Endpoints
    path('innbucks/generate-code/', innbucks_generate_code, name='innbucks_generate_code'),
    path('innbucks/check-status/', innbucks_check_payment_status, name='innbucks_check_payment_status'),
    path('innbucks/simulate-scan/<str:innbucks_code>/<str:transaction_id>/', innbucks_simulate_scan, name='innbucks-simulate-scan'),
    
    # EcoCash Payment Integration Endpoints
    path('ecocash/initiate-payment/', ecocash_initiate_payment, name='ecocash_initiate_payment'),
    path('ecocash/refund-payment/', ecocash_refund_payment, name='ecocash_refund_payment'),
    path('ecocash/transaction-status/<str:client_correlator>/', ecocash_transaction_status, name='ecocash_transaction_status'),
    path('ecocash/webhook/', ecocash_webhook, name='ecocash_webhook'),
    path('ecocash/transactions/', ecocash_transactions, name='ecocash_transactions'),
    path('ecocash/notify/<int:transaction_id>/', ecocash_notify_handler, name='ecocash_notify_handler'),
    path('ecocash/history/', ecocash_transaction_history, name='ecocash_transaction_history'),
    
    # Payment History Endpoints
    path('innbucks/history/', innbucks_transaction_history, name='innbucks_transaction_history'),
    path('omari/history/', omari_transaction_history, name='omari_transaction_history'),
]
