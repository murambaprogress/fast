from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe
from django.conf import settings
from .models import Wallet, WalletBalance, WalletTransaction, ProcessedTransaction, EcoCashTransaction
import json

# Register your models here.

@admin.register(Wallet)
class WalletAdmin(admin.ModelAdmin):
    list_display = ['user', 'created_at']
    list_filter = ['created_at']
    search_fields = ['user__phone_number', 'user__email']
    readonly_fields = ['created_at']

@admin.register(WalletBalance)
class WalletBalanceAdmin(admin.ModelAdmin):
    list_display = ['wallet', 'currency', 'balance']
    list_filter = ['currency', 'wallet__created_at']
    search_fields = ['wallet__user__phone_number', 'currency__code']

@admin.register(WalletTransaction)
class WalletTransactionAdmin(admin.ModelAdmin):
    list_display = ['wallet', 'transaction_type', 'amount', 'currency', 'created_at']
    list_filter = ['transaction_type', 'currency', 'created_at']
    search_fields = ['wallet__user__phone_number', 'reference']
    readonly_fields = ['created_at']
    date_hierarchy = 'created_at'

@admin.register(ProcessedTransaction)
class ProcessedTransactionAdmin(admin.ModelAdmin):
    list_display = ['transaction_id', 'status', 'created_at']
    list_filter = ['status', 'created_at']
    search_fields = ['transaction_id']
    readonly_fields = ['created_at', 'processed_at']

@admin.register(EcoCashTransaction)
class EcoCashTransactionAdmin(admin.ModelAdmin):
    list_display = [
        'get_user_phone', 'transaction_type', 'amount', 'currency_code', 
        'status', 'ecocash_reference', 'get_notify_url_status', 'created_at'
    ]
    list_filter = [
        'transaction_type', 'status', 'currency_code', 'created_at',
        ('notify_url', admin.EmptyFieldListFilter)
    ]
    search_fields = [
        'end_user_id', 'reference_code', 'ecocash_reference', 
        'server_reference_code', 'user__phone_number'
    ]
    readonly_fields = [
        'created_at', 'updated_at', 'get_formatted_request', 
        'get_formatted_response', 'get_notify_url_info'
    ]
    
    fieldsets = (
        ('Basic Information', {
            'fields': (
                'user', 'wallet', 'amount', 'currency_code', 
                'transaction_type', 'status'
            )
        }),
        ('EcoCash Details', {
            'fields': (
                'client_correlator', 'reference_code', 'server_reference_code',
                'ecocash_reference', 'end_user_id', 'remarks'
            )
        }),
        ('Notification Configuration', {
            'fields': ('notify_url', 'get_notify_url_info'),
            'description': 'Configure the URL where EcoCash will send transaction status updates'
        }),
        ('Refund Information', {
            'fields': ('original_ecocash_reference',),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
        ('Debug Information', {
            'fields': ('get_formatted_request', 'get_formatted_response'),
            'classes': ('collapse',)
        })
    )
    
    actions = ['configure_notify_url', 'test_notify_url', 'regenerate_notify_url']
    
    def get_user_phone(self, obj):
        return obj.user.phone_number if hasattr(obj.user, 'phone_number') else obj.user.username
    get_user_phone.short_description = 'User Phone'
    get_user_phone.admin_order_field = 'user__phone_number'
    
    def get_notify_url_status(self, obj):
        if obj.notify_url:
            return format_html(
                '<span style="color: green;">✓ Configured</span>'
            )
        else:
            return format_html(
                '<span style="color: red;">✗ Not Set</span>'
            )
    get_notify_url_status.short_description = 'Notify URL'
    
    def get_notify_url_info(self, obj):
        if obj.notify_url:
            return format_html(
                '<div style="background: #f0f8ff; padding: 10px; border-radius: 5px;">'
                '<strong>Current Notify URL:</strong><br/>'
                '<code>{}</code><br/><br/>'
                '<strong>Usage:</strong><br/>'
                'This URL will receive POST notifications from EcoCash when the transaction status changes.<br/>'
                'Expected statuses: COMPLETED, FAILED<br/><br/>'
                '<strong>Example Payload:</strong><br/>'
                '<pre style="font-size: 11px;">{}</pre>'
                '</div>',
                obj.notify_url,
                json.dumps({
                    "clientCorrelator": obj.client_correlator,
                    "transactionOperationStatus": "COMPLETED",
                    "ecocashReference": "MP230214.1236.A93451",
                    "serverReferenceCode": obj.server_reference_code,
                    "referenceCode": obj.reference_code,
                    "endUserId": obj.end_user_id
                }, indent=2)
            )
        else:
            base_url = getattr(settings, 'BASE_URL', 'https://yourdomain.com')
            suggested_url = f"{base_url}/api/ecocash/notify/{obj.id}/"
            return format_html(
                '<div style="background: #fff8dc; padding: 10px; border-radius: 5px;">'
                '<strong>⚠️ Notify URL not configured</strong><br/><br/>'
                '<strong>Suggested URL:</strong><br/>'
                '<code>{}</code><br/><br/>'
                '<em>Configure this URL to receive automatic status updates from EcoCash</em>'
                '</div>',
                suggested_url
            )
    get_notify_url_info.short_description = 'Notify URL Configuration'
    
    def get_formatted_request(self, obj):
        if obj.raw_request:
            return format_html(
                '<pre style="background: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto;">{}</pre>',
                json.dumps(obj.raw_request, indent=2)
            )
        return "No request data available"
    get_formatted_request.short_description = 'Raw Request Data'
    
    def get_formatted_response(self, obj):
        if obj.raw_response:
            return format_html(
                '<pre style="background: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto;">{}</pre>',
                json.dumps(obj.raw_response, indent=2)
            )
        return "No response data available"
    get_formatted_response.short_description = 'Raw Response Data'
    
    def configure_notify_url(self, request, queryset):
        """Configure notify URL for selected transactions"""
        base_url = getattr(settings, 'BASE_URL', 'https://yourdomain.com')
        updated_count = 0
        
        for transaction in queryset:
            if not transaction.notify_url:
                transaction.notify_url = f"{base_url}/api/ecocash/notify/{transaction.id}/"
                transaction.save()
                updated_count += 1
        
        self.message_user(
            request,
            f"Successfully configured notify URL for {updated_count} transactions."
        )
    configure_notify_url.short_description = "Configure notify URL for selected transactions"
    
    def test_notify_url(self, request, queryset):
        """Test notify URL connectivity for selected transactions"""
        import requests
        from django.contrib import messages
        
        results = []
        for transaction in queryset:
            if transaction.notify_url:
                try:
                    # Test with a HEAD request to check connectivity
                    response = requests.head(transaction.notify_url, timeout=10)
                    if response.status_code < 400:
                        results.append(f"✓ {transaction.reference_code}: OK")
                    else:
                        results.append(f"✗ {transaction.reference_code}: HTTP {response.status_code}")
                except Exception as e:
                    results.append(f"✗ {transaction.reference_code}: {str(e)[:50]}")
            else:
                results.append(f"⚠️ {transaction.reference_code}: No notify URL configured")
        
        self.message_user(
            request,
            mark_safe("<br/>".join(results)),
            level=messages.INFO
        )
    test_notify_url.short_description = "Test notify URL connectivity"
    
    def regenerate_notify_url(self, request, queryset):
        """Regenerate notify URLs for selected transactions"""
        base_url = getattr(settings, 'BASE_URL', 'https://yourdomain.com')
        updated_count = 0
        
        for transaction in queryset:
            transaction.notify_url = f"{base_url}/api/ecocash/notify/{transaction.id}/"
            transaction.save()
            updated_count += 1
        
        self.message_user(
            request,
            f"Successfully regenerated notify URL for {updated_count} transactions."
        )
    regenerate_notify_url.short_description = "Regenerate notify URL for selected transactions"
