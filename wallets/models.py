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
    idempotency_key = models.CharField(max_length=255, unique=True)
    transaction_id = models.CharField(max_length=255, db_index=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    currency = models.ForeignKey(Currency, on_delete=models.CASCADE)
    status = models.CharField(max_length=20, choices=[
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ], default='processing')
    bancabc_transaction_id = models.CharField(max_length=255, blank=True, null=True)
    response_data = models.JSONField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        db_table = 'wallets_processedtransaction'


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
