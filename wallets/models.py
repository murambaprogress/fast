# wallets/models.py
from django.db import models
from django.conf import settings
from currency.models import Currency

class Wallet(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name='wallet'
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.phone_number}'s Wallet"  # Use phone_number instead of username if applicable

    class Meta:
        db_table = 'wallets_wallet'  # optional, if your DB already has this name


class WalletBalance(models.Model):
    wallet = models.ForeignKey(
        Wallet,
        related_name='balances',
        on_delete=models.CASCADE
    )
    currency = models.ForeignKey(Currency, on_delete=models.CASCADE)
    balance = models.DecimalField(max_digits=12, decimal_places=2, default=0.00)

    class Meta:
        unique_together = ('wallet', 'currency')
        db_table = 'wallets_walletbalance'  # optional

    def __str__(self):
        return f"{self.wallet.user.phone_number} - {self.currency.code}: {self.balance}"


class WalletTransaction(models.Model):
    TRANSACTION_TYPES = [
        ('deposit', 'Deposit'),
        ('withdrawal', 'Withdrawal'),
        ('transfer', 'Transfer'),
        ('payment', 'Payment'),
        ('refund', 'Refund'),
        ('conversion', 'Currency Conversion'),
    ]

    wallet = models.ForeignKey(Wallet, related_name='transactions', on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    currency = models.ForeignKey(Currency, on_delete=models.CASCADE)
    transaction_type = models.CharField(max_length=20, choices=TRANSACTION_TYPES)
    description = models.CharField(max_length=255)
    reference = models.CharField(max_length=100, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    # If this transaction is related to a booking
    booking_id = models.IntegerField(null=True, blank=True)
    
    # For tracking currency conversions
    converted_from_currency = models.ForeignKey(
        Currency, 
        related_name='conversions_from', 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True
    )
    converted_amount = models.DecimalField(max_digits=12, decimal_places=2, null=True, blank=True)
    exchange_rate = models.DecimalField(max_digits=10, decimal_places=4, null=True, blank=True)

    class Meta:
        db_table = 'wallets_wallettransaction'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.wallet.user.phone_number} - {self.transaction_type} - {self.amount} {self.currency.code}"


class ProcessedTransaction(models.Model):
    """
    Model to track processed BANCABC transactions for idempotency.
    Prevents duplicate processing of the same transaction.
    """
    PAYMENT_STATUS_CHOICES = [
        ('SUCCESS', 'Success'),
        ('FAILED', 'Failed'),
        ('PENDING', 'Pending'),
        ('CANCELLED', 'Cancelled'),
    ]
    
    PAYMENT_METHOD_CHOICES = [
        ('branch', 'Branch'),
        ('digital', 'Digital Banking'),
        ('kiosk', 'Kiosk'),
        ('agent', 'Agent'),
        ('mobile_app', 'Mobile App'),
        ('internet_banking', 'Internet Banking'),
    ]
    
    idempotency_key = models.CharField(max_length=255, unique=True)
    transaction_id = models.CharField(max_length=255, db_index=True)
    bancabc_reference = models.CharField(max_length=255, db_index=True, blank=True, null=True)
    bancabc_transaction_id = models.CharField(max_length=255, blank=True, null=True)
    
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, blank=True, null=True)
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    currency = models.ForeignKey(Currency, on_delete=models.CASCADE)
    
    status = models.CharField(max_length=20, choices=[
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ], default='processing')
    
    # Payment details
    payment_status = models.CharField(max_length=20, choices=PAYMENT_STATUS_CHOICES, blank=True, null=True)
    payment_verified = models.BooleanField(default=False)
    payment_method = models.CharField(max_length=50, choices=PAYMENT_METHOD_CHOICES, blank=True, null=True)
    payment_channel = models.CharField(max_length=50, blank=True, null=True)
    
    # BancABC operator/branch details
    operator_id = models.CharField(max_length=100, blank=True, null=True)
    branch_code = models.CharField(max_length=100, blank=True, null=True)
    customer_account = models.CharField(max_length=100, blank=True, null=True)
    
    # Failure information
    failure_reason = models.TextField(blank=True, null=True)
    
    # Additional metadata
    remarks = models.TextField(blank=True, null=True)
    payment_details = models.JSONField(blank=True, null=True)
    response_data = models.JSONField(blank=True, null=True)
    
    # Timestamps
    payment_date = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(blank=True, null=True)
    notified_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        db_table = 'wallets_processedtransaction'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['bancabc_reference']),
            models.Index(fields=['payment_status']),
            models.Index(fields=['payment_verified']),
            models.Index(fields=['created_at']),
            models.Index(fields=['branch_code']),
        ]
        
    def __str__(self):
        return f"BANCABC: {self.bancabc_reference or self.transaction_id} - {self.payment_status or self.status}"


class BancABCAPILog(models.Model):
    """
    Model to track ALL BancABC API hits for monitoring and debugging.
    Records every incoming request from BancABC with status and response.
    """
    API_ENDPOINTS = [
        ('wallet_validate', 'Wallet Validation'),
        ('payment_notify', 'Payment Notification'),
        ('wallet_credit', 'Wallet Credit (Credit Push)'),
        ('transaction_report', 'Transaction Report'),
        ('other', 'Other'),
    ]
    
    REQUEST_STATUS = [
        ('success', 'Success'),
        ('failed', 'Failed'),
        ('error', 'Error'),
        ('validation_error', 'Validation Error'),
        ('auth_error', 'Authentication Error'),
    ]
    
    # Request tracking
    endpoint = models.CharField(max_length=50, choices=API_ENDPOINTS)
    request_method = models.CharField(max_length=10, default='POST')
    request_url = models.CharField(max_length=500)
    request_headers = models.JSONField(blank=True, null=True)
    request_body = models.JSONField(blank=True, null=True)
    
    # Response tracking
    response_status_code = models.IntegerField()
    response_body = models.JSONField(blank=True, null=True)
    response_time_ms = models.IntegerField(default=0)  # Response time in milliseconds
    
    # Status and processing
    status = models.CharField(max_length=20, choices=REQUEST_STATUS, default='success')
    error_message = models.TextField(blank=True, null=True)
    
    # Customer/Transaction linking
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    customer_id = models.IntegerField(blank=True, null=True)
    transaction_reference = models.CharField(max_length=255, blank=True, null=True)
    amount = models.DecimalField(max_digits=12, decimal_places=2, blank=True, null=True)
    currency = models.CharField(max_length=10, blank=True, null=True)
    
    # Auto-credit tracking
    auto_credited = models.BooleanField(default=False)
    auto_credit_amount = models.DecimalField(max_digits=12, decimal_places=2, blank=True, null=True)
    points_awarded = models.IntegerField(default=0, blank=True, null=True)
    credit_transaction_id = models.CharField(max_length=255, blank=True, null=True)
    
    # Source info
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    user_agent = models.CharField(max_length=500, blank=True, null=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'wallets_bancabc_api_log'
        ordering = ['-created_at']
        verbose_name = 'BancABC API Log'
        verbose_name_plural = 'BancABC API Logs'
        indexes = [
            models.Index(fields=['endpoint']),
            models.Index(fields=['status']),
            models.Index(fields=['created_at']),
            models.Index(fields=['phone_number']),
            models.Index(fields=['transaction_reference']),
        ]
    
    def __str__(self):
        return f"{self.endpoint} - {self.status} - {self.created_at.strftime('%Y-%m-%d %H:%M:%S')}"


class EcoCashTransaction(models.Model):
    """
    Model to track EcoCash transactions for top-ups and refunds.
    Implements the idempotency pattern recommended in the integration plan.
    """
    TRANSACTION_TYPES = [
        ('MER', 'Merchant Payment'),
        ('REF', 'Refund'),
    ]
    
    TRANSACTION_STATUS = [
        ('initiated', 'Initiated'),
        ('pending_subscriber', 'Pending Subscriber Validation'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('refunded', 'Refunded'),
    ]
    
    # Core transaction fields
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    wallet = models.ForeignKey(Wallet, on_delete=models.CASCADE, related_name='ecocash_transactions')
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    currency_code = models.CharField(max_length=5)  # ZWG or USD
    
    # EcoCash specific fields
    client_correlator = models.CharField(max_length=255, unique=True, db_index=True)  # For idempotency
    reference_code = models.CharField(max_length=255, db_index=True)  # Merchant reference
    server_reference_code = models.CharField(max_length=255, blank=True, null=True)  # EcoCash server reference
    ecocash_reference = models.CharField(max_length=255, blank=True, null=True)  # EcoCash transaction reference
    end_user_id = models.CharField(max_length=20)  # Customer phone number
    
    # Transaction metadata
    transaction_type = models.CharField(max_length=5, choices=TRANSACTION_TYPES, default='MER')
    status = models.CharField(max_length=20, choices=TRANSACTION_STATUS, default='initiated')
    remarks = models.CharField(max_length=255, blank=True, null=True)  # Transaction description
    
    # For refund transactions
    original_ecocash_reference = models.CharField(max_length=255, blank=True, null=True)
    
    # Processing metadata
    notify_url = models.URLField(blank=True, null=True)
    timeout_at = models.DateTimeField(blank=True, null=True)  # When the transaction will timeout
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    raw_request = models.JSONField(blank=True, null=True)  # Store raw request for debugging
    raw_response = models.JSONField(blank=True, null=True)  # Store raw response for debugging
    
    class Meta:
        db_table = 'wallets_ecocashtransaction'
        ordering = ['-created_at']
        
    def __str__(self):
        return f"{self.end_user_id} - {self.transaction_type} - {self.amount} {self.currency_code} - {self.status}"
        indexes = [
            models.Index(fields=['transaction_id', 'status']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return f"BANCABC Transaction: {self.transaction_id} - {self.status}"
