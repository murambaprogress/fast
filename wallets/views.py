from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404
from .models import Wallet, Currency, WalletBalance, WalletTransaction
from .serializers import WalletSerializer, WalletBalanceSerializer
from django.contrib.auth import get_user_model
from decimal import Decimal, InvalidOperation

User = get_user_model()

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_wallet_by_user_id(request):
    """
    Returns wallet info (with balances) for a given user_id passed as query parameter.
    """
    user_id = request.GET.get('user_id')
    if not user_id:
        return Response({'error': 'user_id query parameter is required.'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Allow users to only access their own wallet, unless they're admin
    if not request.user.is_staff and str(request.user.id) != str(user_id):
        return Response({'error': 'Permission denied.'}, status=status.HTTP_403_FORBIDDEN)
    
    user = get_object_or_404(User, pk=user_id)

    if not hasattr(user, 'wallet'):
        # Create wallet if it doesn't exist
        Wallet.objects.create(user=user)

    wallet = user.wallet
    serializer = WalletSerializer(wallet)
    return Response(serializer.data)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def top_up_balance(request, user_id, currency_code):
    """Top up wallet balance and award loyalty points"""
    try:
        # Allow users to only top up their own wallet, unless they're admin
        if not request.user.is_staff and str(request.user.id) != str(user_id):
            return Response({'error': 'Permission denied.'}, status=status.HTTP_403_FORBIDDEN)

        amount_raw = request.data.get('amount')
        phone_number = request.data.get('phone_number')
        method = request.data.get('method')
        
        amount = Decimal(str(amount_raw))
        
        if amount <= 0:
            return Response({"error": "Amount must be greater than zero."}, status=status.HTTP_400_BAD_REQUEST)

        user = get_object_or_404(User, pk=user_id)
        currency = get_object_or_404(Currency, code=currency_code.upper())
        wallet, _ = Wallet.objects.get_or_create(user=user)
        wallet_balance, _ = WalletBalance.objects.get_or_create(wallet=wallet, currency=currency)
        
        # Add amount to wallet
        wallet_balance.balance += amount
        wallet_balance.save()
        
        # Award 10 loyalty points for wallet top-up
        from loyalty.models import LoyaltyAccount
        loyalty_account, _ = LoyaltyAccount.objects.get_or_create(user=user)
        loyalty_account.add_points(10, f"Reward: Wallet Top-Up Bonus (10 points) - {currency.code} {amount} via {method}")
        
        return Response({
            "message": f"{currency.code} {amount} added successfully via {method}. Earned 10 loyalty points!",
            "new_balance": str(wallet_balance.balance),
            "points_earned": 10,
            "method_used": method,
            "phone_number": phone_number
        }, status=status.HTTP_200_OK)
        
    except (ValueError, TypeError, InvalidOperation):
        return Response({"error": "Invalid amount provided."}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def deduct_balance(request, user_id, currency_code):
    try:
        # Allow users to only deduct from their own wallet, unless they're admin
        if not request.user.is_staff and str(request.user.id) != str(user_id):
            return Response({'error': 'Permission denied.'}, status=status.HTTP_403_FORBIDDEN)

        amount_raw = request.data.get('amount')
        amount = Decimal(str(amount_raw))
        if amount <= 0:
            return Response({"error": "Amount must be greater than zero."}, status=status.HTTP_400_BAD_REQUEST)

        user = get_object_or_404(User, pk=user_id)
        wallet = get_object_or_404(Wallet, user=user)
        currency = get_object_or_404(Currency, code=currency_code.upper())
        
        # Try to get balance for the specified currency
        try:
            wallet_balance = WalletBalance.objects.get(wallet=wallet, currency=currency)
        except WalletBalance.DoesNotExist:
            # If the user doesn't have a balance in this currency, check if they have balance in other currencies
            if currency_code.upper() == 'USD':
                # Check for ZAR balance and convert
                try:
                    zar_currency = Currency.objects.get(code='ZAR')
                    zar_balance = WalletBalance.objects.get(wallet=wallet, currency=zar_currency)
                    
                    # Convert ZAR to USD (USD = ZAR / rate)
                    exchange_rate = Decimal('18.05')  # Example rate
                    usd_equivalent = zar_balance.balance / exchange_rate
                    
                    if usd_equivalent < amount:
                        return Response({
                            "error": f"Insufficient balance. You need ${amount} but only have ${usd_equivalent:.2f} equivalent in ZAR."
                        }, status=status.HTTP_400_BAD_REQUEST)
                    
                    # Deduct the equivalent amount from ZAR wallet
                    zar_amount = amount * exchange_rate
                    zar_balance.balance -= zar_amount
                    zar_balance.save()
                    
                    # Record transaction
                    WalletTransaction.objects.create(
                        wallet=wallet,
                        currency=zar_currency,
                        amount='-' + str(zar_amount),
                        transaction_type='deduct',
                        description=f'Booking payment in USD (converted from ZAR)',
                        status='completed'
                    )
                    
                    return Response({
                        "message": f"Deducted ZAR {zar_amount:.2f} (USD {amount:.2f} equivalent) from wallet.",
                        "new_balance": str(zar_balance.balance),
                        "currency": "ZAR",
                        "deducted_amount": str(zar_amount),
                        "equivalent_amount": str(amount),
                        "equivalent_currency": "USD"
                    }, status=status.HTTP_200_OK)
                except (WalletBalance.DoesNotExist, Currency.DoesNotExist):
                    pass
            
            elif currency_code.upper() == 'ZAR':
                # Check for USD balance and convert
                try:
                    usd_currency = Currency.objects.get(code='USD')
                    usd_balance = WalletBalance.objects.get(wallet=wallet, currency=usd_currency)
                    
                    # Convert USD to ZAR (ZAR = USD * rate)
                    exchange_rate = Decimal('18.05')  # Example rate
                    zar_equivalent = usd_balance.balance * exchange_rate
                    
                    if zar_equivalent < amount:
                        return Response({
                            "error": f"Insufficient balance. You need R{amount} but only have R{zar_equivalent:.2f} equivalent in USD."
                        }, status=status.HTTP_400_BAD_REQUEST)
                    
                    # Deduct the equivalent amount from USD wallet
                    usd_amount = amount / exchange_rate
                    usd_balance.balance -= usd_amount
                    usd_balance.save()
                    
                    # Record transaction
                    WalletTransaction.objects.create(
                        wallet=wallet,
                        currency=usd_currency,
                        amount='-' + str(usd_amount),
                        transaction_type='deduct',
                        description=f'Booking payment in ZAR (converted from USD)',
                        status='completed'
                    )
                    
                    return Response({
                        "message": f"Deducted USD {usd_amount:.2f} (ZAR {amount:.2f} equivalent) from wallet.",
                        "new_balance": str(usd_balance.balance),
                        "currency": "USD",
                        "deducted_amount": str(usd_amount),
                        "equivalent_amount": str(amount),
                        "equivalent_currency": "ZAR"
                    }, status=status.HTTP_200_OK)
                except (WalletBalance.DoesNotExist, Currency.DoesNotExist):
                    pass
            
            return Response({"error": f"No {currency_code} balance found."}, status=status.HTTP_404_NOT_FOUND)

        # Regular deduction if the user has balance in the requested currency
        if wallet_balance.balance < amount:
            return Response({"error": "Insufficient balance."}, status=status.HTTP_400_BAD_REQUEST)

        wallet_balance.balance -= amount
        wallet_balance.save()
        
        # Record transaction
        from .models import WalletTransaction
        WalletTransaction.objects.create(
            wallet=wallet,
            currency=currency,
            amount='-' + str(amount),
            transaction_type='deduct',
            description='Booking payment',
            status='completed'
        )

        return Response({
            "message": f"Deducted {amount:.2f} {currency.code} from wallet.",
            "new_balance": str(wallet_balance.balance),
            "currency": currency.code,
            "deducted_amount": str(amount)
        }, status=status.HTTP_200_OK)

    except (ValueError, TypeError, InvalidOperation):
        return Response({"error": "Invalid or missing amount."}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

from rest_framework.views import APIView

class UserWalletView(APIView):
    """
    GET    -> fetch all balances by user
    POST   -> deduct balance (expects currency & amount)
    PATCH  -> top up balance (expects currency & amount)
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, user_id):
        # Allow users to only access their own wallet, unless they're admin
        if not request.user.is_staff and str(request.user.id) != str(user_id):
            return Response({'error': 'Permission denied.'}, status=status.HTTP_403_FORBIDDEN)

        wallet, _ = Wallet.objects.get_or_create(user_id=user_id)
        balances = WalletBalance.objects.filter(wallet=wallet)
        serializer = WalletBalanceSerializer(balances, many=True)
        return Response({"balances": serializer.data}, status=status.HTTP_200_OK)

    def post(self, request, user_id):
        # Allow users to only deduct from their own wallet, unless they're admin
        if not request.user.is_staff and str(request.user.id) != str(user_id):
            return Response({'error': 'Permission denied.'}, status=status.HTTP_403_FORBIDDEN)

        currency_code = request.data.get("currency")
        amount = Decimal(request.data.get("amount", "0"))

        wallet = get_object_or_404(Wallet, user_id=user_id)
        currency = get_object_or_404(Currency, code=currency_code.upper())
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
        # Allow users to only top up their own wallet, unless they're admin
        if not request.user.is_staff and str(request.user.id) != str(user_id):
            return Response({'error': 'Permission denied.'}, status=status.HTTP_403_FORBIDDEN)

        currency_code = request.data.get("currency")
        amount = Decimal(request.data.get("amount", "0"))
        phone_number = request.data.get('phone_number')
        method = request.data.get('method')

        user = get_object_or_404(User, pk=user_id)
        wallet, _ = Wallet.objects.get_or_create(user_id=user_id)
        currency = get_object_or_404(Currency, code=currency_code.upper())
        balance_obj, _ = WalletBalance.objects.get_or_create(wallet=wallet, currency=currency)

        balance_obj.balance += amount
        balance_obj.save()

        # Award 10 loyalty points for wallet top-up
        from loyalty.models import LoyaltyAccount
        loyalty_account, _ = LoyaltyAccount.objects.get_or_create(user=user)
        loyalty_account.add_points(10, f"Reward: Wallet Top-Up Bonus (10 points) - {currency.code} {amount} via {method}")

        return Response({
            "message": f"{amount} {currency.code} added successfully via {method}. Earned 10 loyalty points!",
            "balance": balance_obj.balance,
            "points_earned": 10,
            "method_used": method
        }, status=status.HTTP_200_OK)
