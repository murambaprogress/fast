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
