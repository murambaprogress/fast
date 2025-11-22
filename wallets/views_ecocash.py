import json
import logging
from decimal import Decimal
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_GET
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from .models import EcoCashTransaction, Wallet
from .utils.ecocash import EcoCashAPI
from currency.models import Currency

User = get_user_model()
logger = logging.getLogger(__name__)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def ecocash_initiate_payment(request):
    """
    Initiate an EcoCash payment for topping up the user's wallet.
    
    Required POST parameters:
    - amount: The amount to top-up
    - currency_code: The currency code (USD or ZWG)
    - phone_number: The user's phone number for EcoCash
    - remarks: Optional description for the payment
    
    Returns:
        A JSON response with the transaction details and status
    """
    try:
        # Extract data from request
        amount = request.data.get('amount')
        currency_code = request.data.get('currency_code')
        phone_number = request.data.get('phone_number')
        remarks = request.data.get('remarks')
        
        # Validate required fields
        if not all([amount, currency_code, phone_number]):
            return Response({
                'success': False,
                'message': 'Missing required fields: amount, currency_code, or phone_number'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Validate amount
        try:
            amount = Decimal(amount)
            if amount <= 0:
                return Response({
                    'success': False,
                    'message': 'Amount must be greater than zero'
                }, status=status.HTTP_400_BAD_REQUEST)
        except (ValueError, TypeError):
            return Response({
                'success': False,
                'message': 'Invalid amount format'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Validate currency
        if currency_code not in ['USD', 'ZWG']:
            return Response({
                'success': False,
                'message': 'Invalid currency code. Must be USD or ZWG'
            }, status=status.HTTP_400_BAD_REQUEST)
            
        # Get the user from the authenticated request
        user = request.user
        
        # Initialize EcoCash API with PRODUCTION endpoints
        ecocash_api = EcoCashAPI(is_production=True)
        
        # Initiate payment
        success, transaction, response_data = ecocash_api.initiate_payment(
            user=user,
            amount=amount,
            currency_code=currency_code,
            phone_number=phone_number,
            remarks=remarks
        )
        
        if not success:
            return Response({
                'success': False,
                'message': 'Failed to initiate EcoCash payment',
                'errors': response_data.get('error', 'Unknown error')
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        # Return successful response
        return Response({
            'success': True,
            'message': 'EcoCash payment initiated successfully',
            'transaction': {
                'id': transaction.id,
                'client_correlator': transaction.client_correlator,
                'reference_code': transaction.reference_code,
                'amount': str(transaction.amount),
                'currency_code': transaction.currency_code,
                'status': transaction.status,
                'created_at': transaction.created_at.isoformat(),
            },
            'provider_response': response_data
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.exception(f"Error in ecocash_initiate_payment: {str(e)}")
        return Response({
            'success': False,
            'message': f'An error occurred: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def ecocash_refund_payment(request):
    """
    Initiate an EcoCash refund for a previous transaction.
    
    Required POST parameters:
    - amount: The amount to refund
    - currency_code: The currency code (USD or ZWG)
    - phone_number: The user's phone number for EcoCash
    - original_reference: The original EcoCash transaction reference to refund
    - remarks: Optional description for the refund
    
    Returns:
        A JSON response with the refund details and status
    """
    try:
        # Extract data from request
        amount = request.data.get('amount')
        currency_code = request.data.get('currency_code')
        phone_number = request.data.get('phone_number')
        original_reference = request.data.get('original_reference')
        remarks = request.data.get('remarks')
        
        # Validate required fields
        if not all([amount, currency_code, phone_number, original_reference]):
            return Response({
                'success': False,
                'message': 'Missing required fields: amount, currency_code, phone_number, or original_reference'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Validate amount
        try:
            amount = Decimal(amount)
            if amount <= 0:
                return Response({
                    'success': False,
                    'message': 'Amount must be greater than zero'
                }, status=status.HTTP_400_BAD_REQUEST)
        except (ValueError, TypeError):
            return Response({
                'success': False,
                'message': 'Invalid amount format'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Validate currency
        if currency_code not in ['USD', 'ZWG']:
            return Response({
                'success': False,
                'message': 'Invalid currency code. Must be USD or ZWG'
            }, status=status.HTTP_400_BAD_REQUEST)
            
        # Get the user from the authenticated request
        user = request.user
        
        # Initialize EcoCash API with PRODUCTION endpoints
        ecocash_api = EcoCashAPI(is_production=True)
        
        # Initiate refund
        success, transaction, response_data = ecocash_api.refund_payment(
            user=user,
            amount=amount,
            currency_code=currency_code,
            phone_number=phone_number,
            original_reference=original_reference,
            remarks=remarks
        )
        
        if not success:
            return Response({
                'success': False,
                'message': 'Failed to initiate EcoCash refund',
                'errors': response_data.get('error', 'Unknown error')
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        # Return successful response
        return Response({
            'success': True,
            'message': 'EcoCash refund initiated successfully',
            'transaction': {
                'id': transaction.id,
                'client_correlator': transaction.client_correlator,
                'reference_code': transaction.reference_code,
                'amount': str(transaction.amount),
                'currency_code': transaction.currency_code,
                'status': transaction.status,
                'created_at': transaction.created_at.isoformat(),
            },
            'provider_response': response_data
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.exception(f"Error in ecocash_refund_payment: {str(e)}")
        return Response({
            'success': False,
            'message': f'An error occurred: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def ecocash_transaction_status(request, client_correlator):
    """
    Check the status of an EcoCash transaction.
    
    Args:
        client_correlator: The unique client_correlator of the transaction
        
    Returns:
        A JSON response with the transaction status and details
    """
    try:
        # Find the transaction in our database
        try:
            transaction = EcoCashTransaction.objects.get(client_correlator=client_correlator)
        except EcoCashTransaction.DoesNotExist:
            return Response({
                'success': False,
                'message': f'Transaction with client_correlator {client_correlator} not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Initialize EcoCash API with PRODUCTION endpoints
        ecocash_api = EcoCashAPI(is_production=True)
        
        # Query the transaction status from EcoCash
        success, response_data = ecocash_api.query_transaction(
            end_user_id=transaction.end_user_id,
            client_correlator=client_correlator
        )
        
        if not success:
            return Response({
                'success': False,
                'message': 'Failed to query EcoCash transaction status',
                'errors': response_data.get('error', 'Unknown error')
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        # Check for loyalty points awarded for this transaction
        loyalty_points_awarded = 0
        
        if transaction.status == 'completed':
            from loyalty.models import LoyaltyTransaction
            # Find any loyalty transaction connected to this EcoCash transaction
            try:
                # Look for loyalty transactions created around the same time as this transaction was completed
                recent_loyalty_txs = LoyaltyTransaction.objects.filter(
                    user=transaction.user,
                    transaction_type='earn',
                    description__contains='EcoCash wallet top-up',
                    created_at__gte=transaction.created_at,
                    created_at__lte=transaction.updated_at + timezone.timedelta(minutes=5)  # Give some buffer time
                ).order_by('-created_at')
                
                if recent_loyalty_txs.exists():
                    loyalty_points_awarded = recent_loyalty_txs.first().points
            except Exception as e:
                logger.error(f"Error fetching loyalty transaction: {e}")
        
        # Return transaction status
        return Response({
            'success': True,
            'message': 'Transaction status retrieved successfully',
            'transaction': {
                'id': transaction.id,
                'client_correlator': transaction.client_correlator,
                'reference_code': transaction.reference_code,
                'amount': str(transaction.amount),
                'currency_code': transaction.currency_code,
                'status': transaction.status,
                'ecocash_reference': transaction.ecocash_reference,
                'server_reference_code': transaction.server_reference_code,
                'created_at': transaction.created_at.isoformat(),
                'updated_at': transaction.updated_at.isoformat(),
                'loyalty_points_awarded': loyalty_points_awarded
            },
            'provider_response': response_data
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.exception(f"Error in ecocash_transaction_status: {str(e)}")
        return Response({
            'success': False,
            'message': f'An error occurred: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@csrf_exempt
@require_POST
def ecocash_webhook(request):
    """
    Webhook endpoint for receiving EcoCash payment notifications.
    
    This endpoint is called by EcoCash when a transaction status changes.
    
    Returns:
        A JsonResponse acknowledging receipt of the webhook
    """
    try:
        # Parse webhook data
        try:
            webhook_data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({
                'success': False,
                'message': 'Invalid JSON data in webhook'
            }, status=400)
        
        # Log webhook data
        logger.info(f"EcoCash webhook received: {webhook_data}")
        
        # Process webhook with PRODUCTION endpoints
        ecocash_api = EcoCashAPI(is_production=True)
        success, transaction, message = ecocash_api.process_webhook(webhook_data)
        
        if not success:
            logger.error(f"Failed to process EcoCash webhook: {message}")
            # Still return 200 to acknowledge receipt
            return JsonResponse({
                'success': False,
                'message': message
            }, status=200)
        
        # Return success response
        return JsonResponse({
            'success': True,
            'message': message,
            'transaction_id': transaction.id if transaction else None,
            'transaction_status': transaction.status if transaction else None
        }, status=200)
        
    except Exception as e:
        logger.exception(f"Error in ecocash_webhook: {str(e)}")
        # Still return 200 to acknowledge receipt
        return JsonResponse({
            'success': False,
            'message': f'An error occurred: {str(e)}'
        }, status=200)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def ecocash_transactions(request):
    """
    Get a list of EcoCash transactions for the authenticated user.
    
    Returns:
        A JSON response with the user's EcoCash transactions
    """
    try:
        user = request.user
        transactions = EcoCashTransaction.objects.filter(user=user).order_by('-created_at')
        
        # Prepare response data
        transaction_data = [{
            'id': t.id,
            'client_correlator': t.client_correlator,
            'reference_code': t.reference_code,
            'amount': str(t.amount),
            'currency_code': t.currency_code,
            'transaction_type': t.get_transaction_type_display(),
            'status': t.get_status_display(),
            'ecocash_reference': t.ecocash_reference,
            'created_at': t.created_at.isoformat(),
        } for t in transactions]
        
        return Response({
            'success': True,
            'transactions': transaction_data
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.exception(f"Error in ecocash_transactions: {str(e)}")
        return Response({
            'success': False,
            'message': f'An error occurred: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@csrf_exempt
@require_POST
def ecocash_notify_handler(request, transaction_id):
    """
    Handle EcoCash notification callbacks for specific transactions.
    
    This endpoint receives POST notifications from EcoCash when transaction status changes.
    It's designed to be called by EcoCash servers, not by frontend applications.
    
    URL Pattern: /api/wallets/ecocash/notify/<transaction_id>/
    
    Expected POST data from EcoCash:
    {
        "clientCorrelator": "ABC12345",
        "transactionOperationStatus": "COMPLETED" or "FAILED",
        "ecocashReference": "MP230214.1236.A93451",
        "serverReferenceCode": "772222211230214123501389",
        "referenceCode": "merchant_reference",
        "endUserId": "263774222540",
        "paymentAmount": {
            "charginginformation": {
                "amount": 2.00,
                "currency": "USD"
            }
        }
    }
    """
    logger.info(f"EcoCash notification received for transaction {transaction_id}")
    
    try:
        # Parse the JSON payload
        try:
            notification_data = json.loads(request.body)
            logger.info(f"Notification data: {notification_data}")
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in notification: {str(e)}")
            return JsonResponse({
                'success': False,
                'message': 'Invalid JSON payload'
            }, status=400)
        
        # Get the transaction
        try:
            transaction = EcoCashTransaction.objects.get(id=transaction_id)
            logger.info(f"Found transaction: {transaction.reference_code}")
        except EcoCashTransaction.DoesNotExist:
            logger.error(f"Transaction {transaction_id} not found")
            return JsonResponse({
                'success': False,
                'message': 'Transaction not found'
            }, status=404)
        
        # Validate that the notification is for the correct transaction
        client_correlator = notification_data.get('clientCorrelator')
        if client_correlator and client_correlator != transaction.client_correlator:
            logger.error(f"Client correlator mismatch: expected {transaction.client_correlator}, got {client_correlator}")
            return JsonResponse({
                'success': False,
                'message': 'Client correlator mismatch'
            }, status=400)
        
        # Extract notification details
        new_status = notification_data.get('transactionOperationStatus', '').upper()
        ecocash_reference = notification_data.get('ecocashReference')
        server_reference_code = notification_data.get('serverReferenceCode')
        
        # Log the notification details
        logger.info(f"Transaction {transaction.reference_code} status update: {new_status}")
        
        # Update transaction based on status
        updated = False
        
        if new_status == 'COMPLETED':
            if transaction.status != 'completed':
                transaction.status = 'completed'
                transaction.updated_at = timezone.now()
                updated = True
                
                # Update EcoCash reference if provided
                if ecocash_reference and not transaction.ecocash_reference:
                    transaction.ecocash_reference = ecocash_reference
                
                # Update server reference if provided
                if server_reference_code and not transaction.server_reference_code:
                    transaction.server_reference_code = server_reference_code
                
                # Process the successful payment - update wallet balance
                try:
                    wallet = transaction.wallet
                    currency = Currency.objects.get(code=transaction.currency_code)
                    
                    # Get or create wallet balance for this currency
                    from .models import WalletBalance
                    wallet_balance, created = WalletBalance.objects.get_or_create(
                        wallet=wallet,
                        currency=currency,
                        defaults={'balance': Decimal('0.00')}
                    )
                    
                    # Add the amount to wallet balance
                    wallet_balance.balance += transaction.amount
                    wallet_balance.save()
                    
                    logger.info(f"Wallet balance updated: {wallet_balance.balance} {currency.code}")
                    
                    # Award loyalty points if applicable
                    from loyalty.models import LoyaltyAccount
                    try:
                        loyalty_account, created = LoyaltyAccount.objects.get_or_create(
                            user=transaction.user,
                            defaults={'points': 0, 'lifetime_points': 0}
                        )
                        
                        # Calculate points: 10% of amount (1 point per $10, so $100 = 10 points)
                        points_to_award = int(transaction.amount / 10)
                        
                        if points_to_award > 0:
                            # Use add_points method to properly create transaction record
                            description = f"Points earned for EcoCash wallet top-up of {transaction.currency_code} {transaction.amount}"
                            loyalty_account.add_points(points_to_award, description)
                            
                            logger.info(f"Awarded {points_to_award} loyalty points to user {transaction.user.id}")
                            logger.info(f"New loyalty balance: {loyalty_account.points} points")
                    except Exception as e:
                        logger.error(f"Error awarding loyalty points: {str(e)}", exc_info=True)
                        
                except Exception as e:
                    logger.error(f"Error updating wallet balance: {str(e)}")
                    # Don't fail the notification, but log the error
                
        elif new_status == 'FAILED':
            if transaction.status not in ['failed', 'completed']:
                transaction.status = 'failed'
                transaction.updated_at = timezone.now()
                updated = True
                
                # Update EcoCash reference if provided
                if ecocash_reference and not transaction.ecocash_reference:
                    transaction.ecocash_reference = ecocash_reference
                
                # Update server reference if provided
                if server_reference_code and not transaction.server_reference_code:
                    transaction.server_reference_code = server_reference_code
        
        # Store the raw notification data for debugging
        if not transaction.raw_response:
            transaction.raw_response = {}
        
        # Add notification to raw_response
        if 'notifications' not in transaction.raw_response:
            transaction.raw_response['notifications'] = []
        
        transaction.raw_response['notifications'].append({
            'timestamp': timezone.now().isoformat(),
            'data': notification_data
        })
        
        # Save the transaction
        if updated or ecocash_reference or server_reference_code:
            transaction.save()
            logger.info(f"Transaction {transaction.reference_code} updated successfully")
        
        # Return success response
        return JsonResponse({
            'success': True,
            'message': 'Notification processed successfully',
            'transaction_status': transaction.status
        })
        
    except Exception as e:
        logger.exception(f"Error processing EcoCash notification for transaction {transaction_id}: {str(e)}")
        return JsonResponse({
            'success': False,
            'message': f'Internal server error: {str(e)}'
        }, status=500)