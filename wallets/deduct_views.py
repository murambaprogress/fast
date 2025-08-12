from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .models import Wallet, WalletBalance, WalletTransaction
from currency.models import Currency
from decimal import Decimal

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def deduct_from_wallet(request, user_id, currency_code):
    """
    Deduct an amount from a user's wallet for a specific currency
    """
    # Check if the requesting user is the wallet owner or an admin
    if request.user.id != user_id and not request.user.is_staff:
        return Response({
            'error': 'You are not authorized to deduct from this wallet'
        }, status=status.HTTP_403_FORBIDDEN)
    
    amount = request.data.get('amount')
    if not amount:
        return Response({
            'error': 'Amount is required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        amount = Decimal(amount)
        if amount <= 0:
            raise ValueError("Amount must be positive")
    except (ValueError, TypeError):
        return Response({
            'error': 'Amount must be a valid positive number'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Get the user's wallet and balance for the specified currency
    try:
        wallet = Wallet.objects.get(user_id=user_id)
        currency = Currency.objects.get(code=currency_code.upper())
        wallet_balance = WalletBalance.objects.get(wallet=wallet, currency=currency)
        
        if wallet_balance.balance < amount:
            return Response({
                'error': f'Insufficient funds in {currency_code} wallet',
                'available': str(wallet_balance.balance),
                'required': str(amount)
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Deduct the amount
        wallet_balance.balance -= amount
        wallet_balance.save()
        
        # Create transaction record
        WalletTransaction.objects.create(
            wallet=wallet,
            currency=currency,
            amount='-' + str(amount),
            transaction_type='deduct',
            description=f'Booking payment in {currency_code}',
            status='completed'
        )
        
        return Response({
            'success': True,
            'new_balance': str(wallet_balance.balance),
            'currency': currency.code,
            'deducted': str(amount)
        })
    except Wallet.DoesNotExist:
        return Response({
            'error': f'Wallet not found for user {user_id}'
        }, status=status.HTTP_404_NOT_FOUND)
    except Currency.DoesNotExist:
        return Response({
            'error': f'Currency {currency_code} not found'
        }, status=status.HTTP_404_NOT_FOUND)
    except WalletBalance.DoesNotExist:
        return Response({
            'error': f'No {currency_code} balance found for this wallet'
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
