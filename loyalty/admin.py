from django.contrib import admin
from .models import LoyaltyAccount, LoyaltyTransaction, PointRedemption

@admin.register(LoyaltyAccount)
class LoyaltyAccountAdmin(admin.ModelAdmin):
    list_display = ['user', 'points', 'lifetime_points', 'tier', 'created_at']
    list_filter = ['tier', 'created_at']
    search_fields = ['user__phone_number', 'user__email']
    readonly_fields = ['created_at', 'updated_at']

@admin.register(LoyaltyTransaction)
class LoyaltyTransactionAdmin(admin.ModelAdmin):
    list_display = ['user', 'points', 'transaction_type', 'description', 'created_at']
    list_filter = ['transaction_type', 'created_at']
    search_fields = ['user__phone_number', 'description']
    readonly_fields = ['created_at']

@admin.register(PointRedemption)
class PointRedemptionAdmin(admin.ModelAdmin):
    list_display = ['user', 'redemption_type', 'points_required', 'status', 'created_at']
    list_filter = ['redemption_type', 'status', 'created_at']
    search_fields = ['user__phone_number', 'flight_route']
    readonly_fields = ['created_at', 'updated_at']
    
    actions = ['approve_redemptions', 'reject_redemptions']
    
    def approve_redemptions(self, request, queryset):
        for redemption in queryset.filter(status='pending'):
            redemption.approve(request.user, "Bulk approved by admin")
        self.message_user(request, f"Approved {queryset.count()} redemptions")
    
    def reject_redemptions(self, request, queryset):
        for redemption in queryset.filter(status='pending'):
            redemption.reject(request.user, "Bulk rejected by admin")
        self.message_user(request, f"Rejected {queryset.count()} redemptions")
