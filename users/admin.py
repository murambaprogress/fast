from django.contrib import admin
from .models import User, EmailVerificationLog, PendingUser, AdminOTP

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('email', 'phone_number', 'first_name', 'last_name', 'user_type', 'email_verified', 'is_approved', 'date_joined')
    list_filter = ('user_type', 'email_verified', 'is_approved', 'is_staff', 'is_active')
    search_fields = ('email', 'phone_number', 'first_name', 'last_name')
    readonly_fields = ('date_joined', 'last_login')

@admin.register(PendingUser)
class PendingUserAdmin(admin.ModelAdmin):
    list_display = ('email', 'phone_number', 'first_name', 'last_name', 'user_type', 'created_at', 'verification_code_expires')
    list_filter = ('user_type', 'created_at')
    search_fields = ('email', 'phone_number', 'first_name', 'last_name')
    readonly_fields = ('created_at', 'password_hash', 'email_verification_code')

@admin.register(EmailVerificationLog)
class EmailVerificationLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'verification_code', 'created_at', 'verified_at', 'ip_address')
    list_filter = ('created_at', 'verified_at')
    search_fields = ('user__email', 'user__phone_number', 'ip_address')
    readonly_fields = ('created_at', 'verified_at')

@admin.register(AdminOTP)
class AdminOTPAdmin(admin.ModelAdmin):
    list_display = ('user', 'otp_code', 'created_at', 'expires_at', 'attempts', 'is_expired')
    list_filter = ('created_at', 'expires_at', 'attempts')
    search_fields = ('user__email', 'user__phone_number')
    readonly_fields = ('created_at',)
    
    def is_expired(self, obj):
        return obj.is_expired()
    is_expired.boolean = True
    is_expired.short_description = 'Expired'
