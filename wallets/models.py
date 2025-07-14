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
