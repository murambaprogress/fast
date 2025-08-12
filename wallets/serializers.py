from rest_framework import serializers
from .models import Wallet, WalletBalance
from currency.models import Currency

class WalletBalanceSerializer(serializers.ModelSerializer):
    currency = serializers.SerializerMethodField()

    class Meta:
        model = WalletBalance
        fields = ['currency', 'balance']

    def get_currency(self, obj):
        return {
            'code': obj.currency.code,
            'name': obj.currency.name if hasattr(obj.currency, 'name') else obj.currency.code
        }

class WalletSerializer(serializers.ModelSerializer):
    balances = WalletBalanceSerializer(many=True, read_only=True)

    class Meta:
        model = Wallet
        fields = ['user', 'balances', 'created_at']
        read_only_fields = ['created_at']

