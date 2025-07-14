from rest_framework import serializers
from .models import Wallet, WalletBalance
from currency.serializers import CurrencySerializer

class WalletBalanceSerializer(serializers.ModelSerializer):
    currency = CurrencySerializer(read_only=True)

    class Meta:
        model = WalletBalance
        fields = ['currency', 'balance']


class WalletSerializer(serializers.ModelSerializer):
    user_id = serializers.IntegerField(source='user.id', read_only=True)
    first_name = serializers.CharField(source='user.first_name', read_only=True)
    last_name = serializers.CharField(source='user.last_name', read_only=True)
    phone_number = serializers.CharField(source='user.phone_number', read_only=True)
    balances = WalletBalanceSerializer(many=True, read_only=True)

    class Meta:
        model = Wallet
        fields = [
            'user_id',
            'first_name',
            'last_name',
            'phone_number',
            'created_at',
            'balances'
        ]
