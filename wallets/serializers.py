from rest_framework import serializers
from .models import Wallet, WalletBalance, EcoCashTransaction
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


class EcoCashTransactionSerializer(serializers.ModelSerializer):
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    transaction_type_display = serializers.CharField(source='get_transaction_type_display', read_only=True)
    
    class Meta:
        model = EcoCashTransaction
        fields = [
            'id', 'user', 'wallet', 'amount', 'currency_code', 'client_correlator',
            'reference_code', 'server_reference_code', 'ecocash_reference',
            'end_user_id', 'transaction_type', 'transaction_type_display',
            'status', 'status_display', 'remarks', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'client_correlator', 'reference_code', 'server_reference_code',
            'ecocash_reference', 'status', 'created_at', 'updated_at'
        ]

