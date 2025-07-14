from django.urls import path
from .views import (
    RegisterView,
    LoginView,
    VerifyEmailView,
    ResendVerificationView,
    AdminOTPVerificationView,
    ResendAdminOTPView,
    get_users,
    user_detail,
    update_user_wallet,
    top_up_wallet,
    check_verification_status,
    get_logged_in_user
)

urlpatterns = [
    # Authentication endpoints
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    
    # Email verification endpoints
    path('verify-email/', VerifyEmailView.as_view(), name='verify-email'),
    path('resend-verification/', ResendVerificationView.as_view(), name='resend-verification'),
    
    # Admin OTP endpoints
    path('admin/verify-otp/', AdminOTPVerificationView.as_view(), name='admin-verify-otp'),
    path('admin/resend-otp/', ResendAdminOTPView.as_view(), name='admin-resend-otp'),
    
    # User management endpoints
    path('users/', get_users, name='get_users'), 
    path('users/<int:pk>/', user_detail, name='user_detail'),
    path('users/<int:pk>/wallet/', update_user_wallet, name='update_user_wallet'),

    # Currency-specific wallet top-up endpoint
    path('users/<int:user_id>/top-up/<str:currency_code>/', top_up_wallet, name='top_up_wallet'),
    
    # Verification status check
    path('check-verification/<str:email>/', check_verification_status, name='check-verification-status'),
    path('me/', get_logged_in_user, name='get_logged_in_user'),
]