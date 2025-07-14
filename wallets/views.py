from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view
from django.shortcuts import get_object_or_404
from .models import Wallet,Currency
from .serializers import WalletSerializer,WalletBalance
from django.contrib.auth import get_user_model

User = get_user_model()

@api_view(['GET'])
def get_wallet_by_user_id(request, user_id):
    """
    Returns wallet info (with balances) for a given user_id.
    """
    user = get_object_or_404(User, pk=user_id)

    if not hasattr(user, 'wallet'):
        return Response({'error': 'Wallet does not exist for this user.'}, status=status.HTTP_404_NOT_FOUND)

    wallet = user.wallet  # because OneToOneField, you can use `user.wallet`
    serializer = WalletSerializer(wallet)
    return Response(serializer.data)


# wallets/views.py
@api_view(['POST'])
def top_up_balance(request, user_id, currency_code):
    amount = request.data.get('amount')
    currency = get_object_or_404(Currency, code=currency_code)
    wallet = get_object_or_404(Wallet, pk=user_id)
    wallet_balance, _ = WalletBalance.objects.get_or_create(wallet=wallet, currency=currency)
    wallet_balance.balance += float(amount)
    wallet_balance.save()
    return Response({"message": f"{currency.code} balance updated."})


from decimal import Decimal, InvalidOperation

@api_view(['POST'])
def deduct_balance(request, user_id, currency_code):
    try:
        amount_raw = request.data.get('amount')
        amount = Decimal(str(amount_raw))  # safer conversion
        if amount <= 0:
            return Response({"error": "Amount must be greater than zero."}, status=status.HTTP_400_BAD_REQUEST)

        user = get_object_or_404(User, pk=user_id)
        wallet = get_object_or_404(Wallet, user=user)
        currency = get_object_or_404(Currency, code=currency_code)
        wallet_balance = get_object_or_404(WalletBalance, wallet=wallet, currency=currency)

        if wallet_balance.balance < amount:
            return Response({"error": "Insufficient balance."}, status=status.HTTP_400_BAD_REQUEST)

        wallet_balance.balance -= amount
        wallet_balance.save()

        return Response({
            "message": f"Deducted {amount:.2f} {currency.code} from wallet.",
            "new_balance": str(wallet_balance.balance)
        }, status=status.HTTP_200_OK)

    except (ValueError, TypeError, InvalidOperation):
        print("DEBUG WALLET DEDUCT request.data =", request.data)
        return Response({"error": "Invalid or missing amount."}, status=status.HTTP_400_BAD_REQUEST)

    

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from decimal import Decimal
from .models import Wallet, WalletBalance
from currency.models import Currency
from .serializers import WalletBalanceSerializer


class UserWalletView(APIView):
    """
    GET    -> fetch all balances by user
    POST   -> deduct balance (expects currency & amount)
    PATCH  -> top up balance (expects currency & amount)
    """

    def get(self, request, user_id):
        wallet = get_object_or_404(Wallet, user_id=user_id)
        balances = WalletBalance.objects.filter(wallet=wallet)
        serializer = WalletBalanceSerializer(balances, many=True)
        return Response({"balances": serializer.data}, status=status.HTTP_200_OK)

    def post(self, request, user_id):
        currency_code = request.data.get("currency")
        amount = Decimal(request.data.get("amount", "0"))

        wallet = get_object_or_404(Wallet, user_id=user_id)
        currency = get_object_or_404(Currency, code=currency_code)
        balance_obj = get_object_or_404(WalletBalance, wallet=wallet, currency=currency)

        if balance_obj.balance < amount:
            return Response({"error": "Insufficient balance"}, status=status.HTTP_400_BAD_REQUEST)

        balance_obj.balance -= amount
        balance_obj.save()

        return Response({
            "message": f"{amount} {currency.code} deducted successfully",
            "balance": balance_obj.balance
        }, status=status.HTTP_200_OK)

    def patch(self, request, user_id):
        currency_code = request.data.get("currency")
        amount = Decimal(request.data.get("amount", "0"))

        wallet = get_object_or_404(Wallet, user_id=user_id)
        currency = get_object_or_404(Currency, code=currency_code)
        balance_obj, _ = WalletBalance.objects.get_or_create(wallet=wallet, currency=currency)

        balance_obj.balance += amount
        balance_obj.save()

        return Response({
            "message": f"{amount} {currency.code} added successfully",
            "balance": balance_obj.balance
        }, status=status.HTTP_200_OK)
