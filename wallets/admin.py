from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe
from django.conf import settings
from django.db import models
from .models import Wallet, WalletBalance, WalletTransaction, ProcessedTransaction, EcoCashTransaction, BancABCAPILog
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
    """
    BancABC Transaction Admin Interface
    Comprehensive admin for monitoring, reporting, and managing BancABC transactions
    """
    list_display = [
        'get_bancabc_ref_display', 'get_customer_info', 'get_amount_display',
        'get_payment_status_badge', 'payment_method', 'branch_code',
        'get_verification_status', 'created_at', 'get_actions'
    ]
    
    list_filter = [
        'payment_status', 'payment_verified', 'payment_method', 
        'payment_channel', 'status', 'branch_code', 'created_at',
        ('payment_date', admin.DateFieldListFilter),
    ]
    
    search_fields = [
        'transaction_id', 'bancabc_reference', 'bancabc_transaction_id',
        'user__phone_number', 'user__email', 'user__first_name', 'user__last_name',
        'customer_account', 'operator_id', 'branch_code'
    ]
    
    readonly_fields = [
        'created_at', 'processed_at', 'notified_at', 'get_formatted_payment_details',
        'get_formatted_response', 'get_transaction_timeline', 'get_wallet_impact'
    ]
    
    date_hierarchy = 'created_at'
    
    fieldsets = (
        ('BancABC Transaction Details', {
            'fields': (
                'bancabc_reference', 'bancabc_transaction_id', 'transaction_id',
                'idempotency_key'
            )
        }),
        ('Customer Information', {
            'fields': (
                'user', 'customer_account', 'amount', 'currency'
            )
        }),
        ('Payment Status', {
            'fields': (
                'payment_status', 'payment_verified', 'status', 
                'payment_method', 'payment_channel'
            )
        }),
        ('BancABC Channel Details', {
            'fields': (
                'branch_code', 'operator_id', 'payment_date'
            )
        }),
        ('Failure Information', {
            'fields': ('failure_reason',),
            'classes': ('collapse',)
        }),
        ('Additional Information', {
            'fields': ('remarks', 'get_formatted_payment_details'),
            'classes': ('collapse',)
        }),
        ('Transaction Timeline', {
            'fields': ('get_transaction_timeline',),
        }),
        ('Wallet Impact', {
            'fields': ('get_wallet_impact',),
        }),
        ('Timestamps', {
            'fields': ('created_at', 'notified_at', 'processed_at'),
            'classes': ('collapse',)
        }),
        ('Debug Information', {
            'fields': ('get_formatted_response',),
            'classes': ('collapse',)
        })
    )
    
    actions = [
        'export_to_csv', 'mark_as_reconciled', 'generate_branch_report',
        'send_status_notification', 'verify_payment_manually'
    ]
    
    # Custom display methods
    def get_bancabc_ref_display(self, obj):
        ref = obj.bancabc_reference or obj.transaction_id
        if obj.payment_verified:
            return format_html(
                '<strong>{}</strong><br/>'
                '<span style="font-size: 10px; color: #28a745;">✓ Verified</span>',
                ref
            )
        return format_html('<strong>{}</strong>', ref)
    get_bancabc_ref_display.short_description = 'BancABC Reference'
    get_bancabc_ref_display.admin_order_field = 'bancabc_reference'
    
    def get_customer_info(self, obj):
        user = obj.user
        phone = getattr(user, 'phone_number', 'N/A')
        name = f"{user.first_name} {user.last_name}".strip() or user.username
        
        return format_html(
            '<strong>{}</strong><br/>'
            '<span style="font-size: 10px; color: #666;">{}</span>',
            name, phone
        )
    get_customer_info.short_description = 'Customer'
    get_customer_info.admin_order_field = 'user__phone_number'
    
    def get_amount_display(self, obj):
        return format_html(
            '<strong style="font-size: 14px; color: #007bff;">{} {}</strong>',
            obj.currency.code, obj.amount
        )
    get_amount_display.short_description = 'Amount'
    get_amount_display.admin_order_field = 'amount'
    
    def get_payment_status_badge(self, obj):
        status = obj.payment_status or obj.status
        colors = {
            'SUCCESS': '#28a745',
            'completed': '#28a745',
            'FAILED': '#dc3545',
            'failed': '#dc3545',
            'PENDING': '#ffc107',
            'pending': '#ffc107',
            'CANCELLED': '#6c757d',
            'processing': '#17a2b8',
        }
        color = colors.get(status, '#6c757d')
        
        return format_html(
            '<span style="background-color: {}; color: white; padding: 4px 8px; '
            'border-radius: 4px; font-weight: bold; font-size: 11px;">{}</span>',
            color, status.upper()
        )
    get_payment_status_badge.short_description = 'Status'
    get_payment_status_badge.admin_order_field = 'payment_status'
    
    def get_verification_status(self, obj):
        if obj.payment_verified:
            return format_html(
                '<span style="color: #28a745; font-weight: bold;">✓ Verified</span>'
            )
        elif obj.payment_status == 'SUCCESS':
            return format_html(
                '<span style="color: #ffc107; font-weight: bold;">⚠ Pending Verification</span>'
            )
        return format_html(
            '<span style="color: #6c757d;">—</span>'
        )
    get_verification_status.short_description = 'Verification'
    get_verification_status.admin_order_field = 'payment_verified'
    
    def get_actions(self, obj):
        actions = []
        
        if not obj.payment_verified and obj.payment_status == 'SUCCESS':
            actions.append(
                '<a href="#" style="color: #007bff;">Verify</a>'
            )
        
        actions.append(
            '<a href="#" style="color: #17a2b8;">Details</a>'
        )
        
        if obj.payment_status in ['FAILED', 'CANCELLED']:
            actions.append(
                '<a href="#" style="color: #dc3545;">Review</a>'
            )
        
        return format_html(' | '.join(actions))
    get_actions.short_description = 'Actions'
    
    def get_transaction_timeline(self, obj):
        timeline_html = '<div style="background: #f8f9fa; padding: 15px; border-radius: 5px;">'
        timeline_html += '<h4 style="margin-top: 0;">Transaction Timeline</h4>'
        timeline_html += '<ul style="list-style: none; padding: 0;">'
        
        # Created
        timeline_html += f'''
        <li style="margin-bottom: 10px;">
            <strong style="color: #007bff;">●</strong> 
            <strong>Created:</strong> {obj.created_at.strftime("%Y-%m-%d %H:%M:%S")}
            <br/><span style="margin-left: 20px; font-size: 12px; color: #666;">
            Transaction initiated
            </span>
        </li>
        '''
        
        # Payment Notification
        if obj.notified_at:
            timeline_html += f'''
            <li style="margin-bottom: 10px;">
                <strong style="color: #28a745;">●</strong> 
                <strong>Payment Notified:</strong> {obj.notified_at.strftime("%Y-%m-%d %H:%M:%S")}
                <br/><span style="margin-left: 20px; font-size: 12px; color: #666;">
                Payment status: {obj.payment_status}
                </span>
            </li>
            '''
        
        # Processed
        if obj.processed_at:
            timeline_html += f'''
            <li style="margin-bottom: 10px;">
                <strong style="color: #17a2b8;">●</strong> 
                <strong>Processed:</strong> {obj.processed_at.strftime("%Y-%m-%d %H:%M:%S")}
                <br/><span style="margin-left: 20px; font-size: 12px; color: #666;">
                Wallet credited
                </span>
            </li>
            '''
        
        timeline_html += '</ul></div>'
        return format_html(timeline_html)
    get_transaction_timeline.short_description = 'Timeline'
    
    def get_wallet_impact(self, obj):
        if obj.payment_verified and obj.status == 'completed':
            # Get related wallet transaction
            wallet_txn = WalletTransaction.objects.filter(
                wallet__user=obj.user,
                amount=obj.amount,
                currency=obj.currency,
                created_at__gte=obj.created_at
            ).first()
            
            if wallet_txn:
                try:
                    wallet_balance = WalletBalance.objects.get(
                        wallet=wallet_txn.wallet,
                        currency=obj.currency
                    )
                    
                    return format_html(
                        '<div style="background: #d4edda; padding: 15px; border-radius: 5px; border-left: 4px solid #28a745;">'
                        '<h4 style="margin-top: 0; color: #155724;">✓ Wallet Credited</h4>'
                        '<p style="margin: 5px 0;"><strong>Amount:</strong> {} {}</p>'
                        '<p style="margin: 5px 0;"><strong>Current Balance:</strong> {} {}</p>'
                        '<p style="margin: 5px 0;"><strong>Loyalty Points:</strong> +{} points</p>'
                        '<p style="margin: 5px 0; font-size: 11px; color: #666;">'
                        '<strong>Transaction Ref:</strong> {}</p>'
                        '</div>',
                        obj.currency.code, obj.amount,
                        obj.currency.code, wallet_balance.balance,
                        int(obj.amount / 10),  # 10% loyalty points
                        wallet_txn.reference
                    )
                except WalletBalance.DoesNotExist:
                    pass
        
        elif obj.payment_status == 'FAILED':
            return format_html(
                '<div style="background: #f8d7da; padding: 15px; border-radius: 5px; border-left: 4px solid #dc3545;">'
                '<h4 style="margin-top: 0; color: #721c24;">✗ Payment Failed</h4>'
                '<p style="margin: 5px 0;"><strong>Reason:</strong> {}</p>'
                '<p style="margin: 5px 0; font-size: 11px; color: #666;">Wallet was not credited</p>'
                '</div>',
                obj.failure_reason or 'Not specified'
            )
        
        return format_html(
            '<div style="background: #fff3cd; padding: 15px; border-radius: 5px; border-left: 4px solid #ffc107;">'
            '<p style="margin: 0;">⚠ Wallet not yet credited - awaiting payment verification</p>'
            '</div>'
        )
    get_wallet_impact.short_description = 'Wallet Impact'
    
    def get_formatted_payment_details(self, obj):
        if obj.payment_details:
            return format_html(
                '<pre style="background: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto;">{}</pre>',
                json.dumps(obj.payment_details, indent=2)
            )
        return "No additional payment details"
    get_formatted_payment_details.short_description = 'Payment Details'
    
    def get_formatted_response(self, obj):
        if obj.response_data:
            return format_html(
                '<pre style="background: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto;">{}</pre>',
                json.dumps(obj.response_data, indent=2)
            )
        return "No response data available"
    get_formatted_response.short_description = 'API Response Data'
    
    # Admin actions
    def export_to_csv(self, request, queryset):
        """Export selected transactions to CSV"""
        import csv
        from django.http import HttpResponse
        from datetime import datetime
        
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="bancabc_transactions_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"'
        
        writer = csv.writer(response)
        writer.writerow([
            'BancABC Reference', 'Transaction ID', 'Customer Name', 'Phone Number',
            'Amount', 'Currency', 'Payment Status', 'Payment Method', 'Branch Code',
            'Operator ID', 'Verified', 'Created Date', 'Payment Date', 'Remarks'
        ])
        
        for obj in queryset:
            writer.writerow([
                obj.bancabc_reference or obj.transaction_id,
                obj.bancabc_transaction_id or '',
                f"{obj.user.first_name} {obj.user.last_name}".strip() or obj.user.username,
                getattr(obj.user, 'phone_number', 'N/A'),
                obj.amount,
                obj.currency.code,
                obj.payment_status or obj.status,
                obj.payment_method or '',
                obj.branch_code or '',
                obj.operator_id or '',
                'Yes' if obj.payment_verified else 'No',
                obj.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                obj.payment_date.strftime("%Y-%m-%d %H:%M:%S") if obj.payment_date else '',
                obj.remarks or ''
            ])
        
        self.message_user(request, f"Exported {queryset.count()} transactions to CSV")
        return response
    export_to_csv.short_description = "Export selected transactions to CSV"
    
    def generate_branch_report(self, request, queryset):
        """Generate summary report by branch"""
        from django.db.models import Sum, Count
        from django.contrib import messages
        
        report = queryset.values('branch_code').annotate(
            total_transactions=Count('id'),
            total_amount=Sum('amount'),
            successful=Count('id', filter=models.Q(payment_status='SUCCESS')),
            failed=Count('id', filter=models.Q(payment_status='FAILED'))
        ).order_by('-total_amount')
        
        report_html = '<div style="font-family: monospace;"><h3>Branch Performance Report</h3><table border="1" cellpadding="5">'
        report_html += '<tr><th>Branch</th><th>Transactions</th><th>Total Amount (USD)</th><th>Success</th><th>Failed</th><th>Success Rate</th></tr>'
        
        for row in report:
            branch = row['branch_code'] or 'Unknown'
            total = row['total_transactions']
            amount = row['total_amount'] or 0
            success = row['successful']
            failed = row['failed']
            rate = (success / total * 100) if total > 0 else 0
            
            report_html += f'<tr><td>{branch}</td><td>{total}</td><td>${amount:.2f}</td><td>{success}</td><td>{failed}</td><td>{rate:.1f}%</td></tr>'
        
        report_html += '</table></div>'
        
        self.message_user(request, mark_safe(report_html), level=messages.INFO)
    generate_branch_report.short_description = "Generate branch performance report"
    
    def verify_payment_manually(self, request, queryset):
        """Manually verify selected payments"""
        updated = queryset.filter(
            payment_status='SUCCESS',
            payment_verified=False
        ).update(payment_verified=True)
        
        self.message_user(
            request,
            f"Manually verified {updated} transactions"
        )
    verify_payment_manually.short_description = "Manually verify selected payments"
    
    def send_status_notification(self, request, queryset):
        """Send status notifications for selected transactions"""
        # Placeholder for email/SMS notification functionality
        count = queryset.count()
        self.message_user(
            request,
            f"Status notifications queued for {count} transactions"
        )
    send_status_notification.short_description = "Send status notifications"
    
    def mark_as_reconciled(self, request, queryset):
        """Mark transactions as reconciled"""
        from django.utils import timezone
        
        updated = queryset.filter(
            payment_verified=True,
            status='completed'
        ).update(processed_at=timezone.now())
        
        self.message_user(
            request,
            f"Marked {updated} transactions as reconciled"
        )
    mark_as_reconciled.short_description = "Mark as reconciled"

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


# =============================================================================
# BancABC API Log Admin - Track ALL API Hits from BancABC
# =============================================================================
@admin.register(BancABCAPILog)
class BancABCAPILogAdmin(admin.ModelAdmin):
    """
    BancABC API Log Admin Dashboard
    Monitors all incoming API requests from BancABC with real-time status tracking.
    """
    list_display = [
        'get_timestamp', 'get_endpoint_badge', 'get_status_badge', 
        'phone_number', 'get_amount_display', 'transaction_reference',
        'get_auto_credit_status', 'response_time_ms', 'get_actions'
    ]
    
    list_filter = [
        'endpoint', 'status', 'auto_credited', 'created_at',
        ('created_at', admin.DateFieldListFilter),
    ]
    
    search_fields = [
        'phone_number', 'transaction_reference', 'ip_address',
        'error_message', 'credit_transaction_id'
    ]
    
    readonly_fields = [
        'created_at', 'get_request_details', 'get_response_details',
        'get_full_timeline'
    ]
    
    date_hierarchy = 'created_at'
    list_per_page = 50
    
    fieldsets = (
        ('📡 Request Information', {
            'fields': (
                'endpoint', 'request_method', 'request_url',
                'get_request_details'
            )
        }),
        ('📤 Response Information', {
            'fields': (
                'response_status_code', 'status', 'response_time_ms',
                'get_response_details', 'error_message'
            )
        }),
        ('👤 Customer & Transaction', {
            'fields': (
                'phone_number', 'customer_id', 'transaction_reference',
                'amount', 'currency'
            )
        }),
        ('💰 Auto-Credit Status', {
            'fields': (
                'auto_credited', 'credit_transaction_id'
            ),
            'classes': ('collapse',)
        }),
        ('🌐 Source Information', {
            'fields': (
                'ip_address', 'user_agent', 'created_at'
            ),
            'classes': ('collapse',)
        }),
    )
    
    def get_timestamp(self, obj):
        return obj.created_at.strftime('%Y-%m-%d %H:%M:%S')
    get_timestamp.short_description = 'Timestamp'
    get_timestamp.admin_order_field = 'created_at'
    
    def get_endpoint_badge(self, obj):
        colors = {
            'wallet_validate': '#3498db',
            'payment_notify': '#9b59b6',
            'wallet_credit': '#27ae60',
            'transaction_report': '#f39c12',
            'other': '#95a5a6',
        }
        labels = {
            'wallet_validate': '🔍 Validate',
            'payment_notify': '📩 Notify',
            'wallet_credit': '💰 Credit',
            'transaction_report': '📊 Report',
            'other': '❓ Other',
        }
        color = colors.get(obj.endpoint, '#95a5a6')
        label = labels.get(obj.endpoint, obj.endpoint)
        return format_html(
            '<span style="background-color:{}; color:white; padding:3px 8px; '
            'border-radius:4px; font-size:11px; font-weight:bold;">{}</span>',
            color, label
        )
    get_endpoint_badge.short_description = 'Endpoint'
    get_endpoint_badge.admin_order_field = 'endpoint'
    
    def get_status_badge(self, obj):
        colors = {
            'success': '#27ae60',
            'failed': '#e74c3c',
            'error': '#c0392b',
            'validation_error': '#f39c12',
            'auth_error': '#8e44ad',
        }
        icons = {
            'success': '✅',
            'failed': '❌',
            'error': '🔴',
            'validation_error': '⚠️',
            'auth_error': '🔒',
        }
        color = colors.get(obj.status, '#95a5a6')
        icon = icons.get(obj.status, '❓')
        return format_html(
            '<span style="background-color:{}; color:white; padding:3px 8px; '
            'border-radius:4px; font-size:11px;">{} {}</span>',
            color, icon, obj.status.upper()
        )
    get_status_badge.short_description = 'Status'
    get_status_badge.admin_order_field = 'status'
    
    def get_amount_display(self, obj):
        if obj.amount:
            return format_html(
                '<span style="font-weight:bold; color:#27ae60;">${:,.2f}</span>',
                obj.amount
            )
        return '-'
    get_amount_display.short_description = 'Amount'
    
    def get_auto_credit_status(self, obj):
        if obj.auto_credited:
            return format_html(
                '<span style="color:#27ae60; font-weight:bold;">✅ Credited</span>'
                '<br/><small style="color:#666;">{}</small>',
                obj.credit_transaction_id[:20] + '...' if obj.credit_transaction_id and len(obj.credit_transaction_id) > 20 else obj.credit_transaction_id or ''
            )
        elif obj.endpoint == 'payment_notify' and obj.status == 'success':
            return format_html(
                '<span style="color:#f39c12;">⏳ Pending Credit</span>'
            )
        return format_html('<span style="color:#95a5a6;">-</span>')
    get_auto_credit_status.short_description = 'Auto Credit'
    
    def get_request_details(self, obj):
        if obj.request_body:
            try:
                formatted = json.dumps(obj.request_body, indent=2)
                return format_html(
                    '<pre style="background:#f8f9fa; padding:10px; border-radius:4px; '
                    'max-height:300px; overflow:auto; font-size:12px;">{}</pre>',
                    formatted
                )
            except:
                return str(obj.request_body)
        return '-'
    get_request_details.short_description = 'Request Body'
    
    def get_response_details(self, obj):
        if obj.response_body:
            try:
                formatted = json.dumps(obj.response_body, indent=2)
                return format_html(
                    '<pre style="background:#f8f9fa; padding:10px; border-radius:4px; '
                    'max-height:300px; overflow:auto; font-size:12px;">{}</pre>',
                    formatted
                )
            except:
                return str(obj.response_body)
        return '-'
    get_response_details.short_description = 'Response Body'
    
    def get_full_timeline(self, obj):
        return format_html(
            '<div style="background:#f8f9fa; padding:15px; border-radius:8px;">'
            '<p><strong>📅 Received:</strong> {}</p>'
            '<p><strong>⏱️ Response Time:</strong> {}ms</p>'
            '<p><strong>🌐 IP Address:</strong> {}</p>'
            '</div>',
            obj.created_at.strftime('%Y-%m-%d %H:%M:%S.%f'),
            obj.response_time_ms,
            obj.ip_address or 'Unknown'
        )
    get_full_timeline.short_description = 'Timeline'
    
    def get_actions(self, obj):
        actions = []
        if obj.phone_number:
            actions.append(format_html(
                '<a href="/admin/users/customuser/?q={}" style="color:#3498db;" '
                'title="View Customer">👤</a>',
                obj.phone_number
            ))
        if obj.endpoint == 'payment_notify' and obj.status == 'success' and not obj.auto_credited:
            actions.append(format_html(
                '<a href="#" onclick="alert(\'Manual credit pending\'); return false;" '
                'style="color:#27ae60;" title="Trigger Manual Credit">💰</a>'
            ))
        return format_html(' '.join(actions)) if actions else '-'
    get_actions.short_description = 'Actions'
    
    def changelist_view(self, request, extra_context=None):
        """Add summary stats to the changelist view"""
        extra_context = extra_context or {}
        
        from django.db.models import Count, Sum, Avg
        from datetime import timedelta
        from django.utils import timezone
        
        # Get stats for last 24 hours
        last_24h = timezone.now() - timedelta(hours=24)
        recent_logs = BancABCAPILog.objects.filter(created_at__gte=last_24h)
        
        extra_context['api_stats'] = {
            'total_requests_24h': recent_logs.count(),
            'success_count': recent_logs.filter(status='success').count(),
            'failed_count': recent_logs.filter(status__in=['failed', 'error']).count(),
            'avg_response_time': recent_logs.aggregate(Avg('response_time_ms'))['response_time_ms__avg'] or 0,
            'total_credited': recent_logs.filter(auto_credited=True).count(),
            'pending_credits': recent_logs.filter(
                endpoint='payment_notify', 
                status='success', 
                auto_credited=False
            ).count(),
        }
        
        return super().changelist_view(request, extra_context=extra_context)
