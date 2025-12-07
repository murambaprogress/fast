from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.shortcuts import get_object_or_404
from django.http import HttpResponse
from .models import Wallet, Currency, WalletBalance, WalletTransaction, ProcessedTransaction
from .serializers import WalletSerializer, WalletBalanceSerializer
from django.contrib.auth import get_user_model
from decimal import Decimal, InvalidOperation
import re
import json
import logging
import hmac
import hashlib
import requests
import time
from django.db import transaction
from django.utils import timezone
from django.conf import settings
from datetime import timedelta
from .bancabc_logger import log_bancabc_api_call

User = get_user_model()
logger = logging.getLogger(__name__)

class BancABCAuthentication(BaseAuthentication):
    """
    Custom authentication for BANCABC webhook endpoints.
    Validates API key and optionally HMAC signature for production security.
    For testing: Only API key is required
    For production webhooks: API key + HMAC signature + timestamp required
    """

    def authenticate(self, request):
        # Get API key from header
        api_key = request.META.get('HTTP_X_BANCABC_API_KEY')
        if not api_key:
            raise AuthenticationFailed('Missing BANCABC API key')

        # Validate API key (in production, this should be stored securely)
        expected_api_key = getattr(settings, 'BANCABC_API_KEY', None)
        if not expected_api_key or api_key != expected_api_key:
            raise AuthenticationFailed('Invalid BANCABC API key')

        # For webhooks (payment/notify), require signature verification
        # For other endpoints (validate, credit, report), API key is sufficient
        signature = request.META.get('HTTP_X_BANCABC_SIGNATURE')
        timestamp = request.META.get('HTTP_X_BANCABC_TIMESTAMP')
        
        # Only verify signature if both signature and timestamp are provided
        if signature and timestamp:
            # Validate timestamp (allow 5 minute window)
            try:
                request_timestamp = int(timestamp)
                current_timestamp = int(timezone.now().timestamp())
                if abs(current_timestamp - request_timestamp) > 300:  # 5 minutes
                    raise AuthenticationFailed('Request timestamp expired')
            except (ValueError, TypeError):
                raise AuthenticationFailed('Invalid timestamp format')

            # Verify HMAC signature
            secret_key = getattr(settings, 'BANCABC_SECRET_KEY', '')
            if not secret_key:
                raise AuthenticationFailed('BANCABC secret key not configured')

            # Create message to sign (timestamp + request body)
            body = request.body.decode('utf-8') if request.body else ''
            message = f"{timestamp}{body}"

            expected_signature = hmac.new(
                secret_key.encode('utf-8'),
                message.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()

            if not hmac.compare_digest(signature, expected_signature):
                raise AuthenticationFailed('Invalid BANCABC signature')

        return (None, None)  # Authentication successful, no user object needed


def bancabc_rate_limit(max_calls=10, time_window=60):
    """
    Rate limiting decorator for BANCABC endpoints.
    Limits calls per IP address within a time window.
    """
    def decorator(view_func):
        def wrapper(request, *args, **kwargs):
            from django.core.cache import cache
            import hashlib

            # Get client IP
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                ip = x_forwarded_for.split(',')[0].strip()
            else:
                ip = request.META.get('REMOTE_ADDR')

            # Create cache key
            cache_key = f"bancabc_rate_limit_{hashlib.md5(ip.encode()).hexdigest()}"
            current_time = int(timezone.now().timestamp())

            # Get current rate limit data
            rate_data = cache.get(cache_key, {'calls': [], 'blocked_until': 0})

            # Check if currently blocked
            if current_time < rate_data['blocked_until']:
                return Response({
                    'status': 'error',
                    'message': 'Rate limit exceeded. Try again later.'
                }, status=status.HTTP_429_TOO_MANY_REQUESTS)

            # Clean old calls outside the time window
            rate_data['calls'] = [call_time for call_time in rate_data['calls']
                                if current_time - call_time < time_window]

            # Check if limit exceeded
            if len(rate_data['calls']) >= max_calls:
                # Block for the time window duration
                rate_data['blocked_until'] = current_time + time_window
                cache.set(cache_key, rate_data, time_window * 2)
                logger.warning(f"BANCABC rate limit exceeded for IP: {ip}")
                return Response({
                    'status': 'error',
                    'message': 'Rate limit exceeded. Try again later.'
                }, status=status.HTTP_429_TOO_MANY_REQUESTS)

            # Add current call
            rate_data['calls'].append(current_time)
            cache.set(cache_key, rate_data, time_window * 2)

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


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
        idempotency_key = request.data.get('idempotency_key')  # Frontend should send unique key per request
        
        amount = Decimal(str(amount_raw))
        
        if amount <= 0:
            return Response({"code": "VALIDATION_ERROR", "message": "Amount must be greater than zero."}, status=status.HTTP_400_BAD_REQUEST)

        user = get_object_or_404(User, pk=user_id)
        currency = get_object_or_404(Currency, code=currency_code.upper())
        
        # Check for duplicate transaction using idempotency key
        if idempotency_key:
            existing_txn = WalletTransaction.objects.filter(
                wallet__user=user,
                description__icontains=idempotency_key
            ).first()
            
            if existing_txn:
                # Transaction already processed, return previous result
                wallet_balance = WalletBalance.objects.get(wallet__user=user, currency=currency)
                return Response({
                    "message": "Transaction already processed",
                    "new_balance": str(wallet_balance.balance),
                    "points_earned": 0,
                    "method_used": method,
                    "phone_number": phone_number,
                    "duplicate": True
                }, status=status.HTTP_200_OK)
        
        wallet, _ = Wallet.objects.get_or_create(user=user)
        wallet_balance, _ = WalletBalance.objects.get_or_create(wallet=wallet, currency=currency)
        
        # Add amount to wallet
        wallet_balance.balance += amount
        wallet_balance.save()
        
        # Record transaction with idempotency key
        description = f"Wallet Top-Up - {currency.code} {amount} via {method}"
        if idempotency_key:
            description += f" [Ref: {idempotency_key}]"
            
        WalletTransaction.objects.create(
            wallet=wallet,
            currency=currency,
            amount=str(amount),
            transaction_type='deposit',
            description=description
        )
        
        # Award loyalty points equal to 10% of the top-up amount (1 point per $10)
        from loyalty.models import LoyaltyAccount
        loyalty_account, _ = LoyaltyAccount.objects.get_or_create(user=user)
        # Calculate 10% points: $100 = 10 points
        points_earned = int(amount / 10)
        if points_earned > 0:
            loyalty_account.add_points(points_earned, f"Reward: Wallet Top-Up Bonus ({points_earned} points) - {currency.code} {amount} via {method}")
        
        return Response({
            "message": f"{currency.code} {amount} added successfully via {method}. Earned {points_earned} loyalty points!",
            "new_balance": str(wallet_balance.balance),
            "points_earned": points_earned,
            "method_used": method,
            "phone_number": phone_number
        }, status=status.HTTP_200_OK)
        
    except (ValueError, TypeError, InvalidOperation):
        return Response({"code": "VALIDATION_ERROR", "message": "Invalid amount provided."}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({"code": "SERVER_ERROR", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def deduct_balance(request, user_id, currency_code):
    try:
        # Allow users to only deduct from their own wallet, unless they're admin
        if not request.user.is_staff and str(request.user.id) != str(user_id):
            return Response({'error': 'Permission denied.'}, status=status.HTTP_403_FORBIDDEN)

        # DEBUG: log incoming request for troubleshooting invalid amount
        try:
            logger.debug("deduct_balance incoming content_type=%s body=%s data=%s", request.content_type, request.body.decode('utf-8', errors='replace'), dict(request.data))
        except Exception:
            # best-effort, don't crash on logging
            logger.debug("deduct_balance incoming raw body could not be decoded")

        # Robust amount parsing: accept numbers or strings like "1,234.56" or "$123.45"
        amount_raw = request.data.get('amount', None)

        # Fallback: if DRF didn't parse the body for some reason, try to parse raw JSON body
        if amount_raw is None:
            try:
                body_text = request.body.decode('utf-8') if request.body else ''
                parsed_body = json.loads(body_text) if body_text else {}
                logger.debug("deduct_balance fallback parsed_body=%s", parsed_body)
                if isinstance(parsed_body, dict) and 'amount' in parsed_body:
                    amount_raw = parsed_body.get('amount')
            except Exception as e:
                logger.debug("deduct_balance fallback parse failed: %s", str(e))
        if amount_raw is None or (isinstance(amount_raw, str) and amount_raw.strip() == ""):
            return Response({"code": "VALIDATION_ERROR", "message": "Amount is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            if isinstance(amount_raw, str):
                # remove common thousands separators and currency symbols, keep digits, dot and minus
                cleaned = re.sub(r"[^0-9.\-]", "", amount_raw)
                # guard against empty or invalid cleaned strings
                if cleaned in ("", ".", "-", "-.", "-." ):
                    raise InvalidOperation()
                amount = Decimal(cleaned)
            else:
                # numeric types (int/float/Decimal)
                amount = Decimal(str(amount_raw))

        except (InvalidOperation, ValueError, TypeError):
            return Response({"code": "VALIDATION_ERROR", "message": "Invalid amount provided."}, status=status.HTTP_400_BAD_REQUEST)

        if amount <= 0:
            return Response({"code": "VALIDATION_ERROR", "message": "Amount must be greater than zero."}, status=status.HTTP_400_BAD_REQUEST)

        user = get_object_or_404(User, pk=user_id)
        wallet = get_object_or_404(Wallet, user=user)
        currency = get_object_or_404(Currency, code=currency_code.upper())
        
        # Try to get balance for the specified currency. Perform the
        # deduction and transaction recording inside an atomic block so any
        # error after modifying balances will roll back and not leave the
        # wallet in an inconsistent state (debited but reporting an error).
        try:
            with transaction.atomic():
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
                                payload = {
                                    "code": "INSUFFICIENT_FUNDS",
                                    "message": f"Insufficient balance. You need {amount} USD but only have {usd_equivalent:.2f} USD equivalent in ZAR.",
                                    "required": str(amount),
                                    "available": str(round(usd_equivalent, 2)),
                                    "currency": "USD",
                                    "equivalent_currency": "ZAR"
                                }
                                logger.debug("deduct_balance returning: %s", payload)
                                return Response(payload, status=402)

                            # Deduct the equivalent amount from ZAR wallet
                            zar_amount = amount * exchange_rate
                            zar_balance.balance -= zar_amount
                            zar_balance.save()

                            # Record transaction
                            WalletTransaction.objects.create(
                                wallet=wallet,
                                currency=zar_currency,
                                amount='-' + str(zar_amount),
                                transaction_type='payment',
                                description=f'Booking payment in USD (converted from ZAR)'
                            )

                            payload = {
                                "message": f"Deducted ZAR {zar_amount:.2f} (USD {amount:.2f} equivalent) from wallet.",
                                "new_balance": str(zar_balance.balance),
                                "currency": "ZAR",
                                "deducted_amount": str(zar_amount),
                                "equivalent_amount": str(amount),
                                "equivalent_currency": "USD"
                            }
                            logger.debug("deduct_balance returning: %s", payload)
                            return Response(payload, status=status.HTTP_200_OK)
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
                                payload = {
                                    "code": "INSUFFICIENT_FUNDS",
                                    "message": f"Insufficient balance. You need {amount} ZAR but only have {zar_equivalent:.2f} ZAR equivalent in USD.",
                                    "required": str(amount),
                                    "available": str(round(zar_equivalent, 2)),
                                    "currency": "ZAR",
                                    "equivalent_currency": "USD"
                                }
                                logger.debug("deduct_balance returning: %s", payload)
                                return Response(payload, status=402)

                            # Deduct the equivalent amount from USD wallet
                            usd_amount = amount / exchange_rate
                            usd_balance.balance -= usd_amount
                            usd_balance.save()

                            # Record transaction
                            WalletTransaction.objects.create(
                                wallet=wallet,
                                currency=usd_currency,
                                amount='-' + str(usd_amount),
                                transaction_type='payment',
                                description=f'Booking payment in ZAR (converted from USD)'
                            )

                            payload = {
                                "message": f"Deducted USD {usd_amount:.2f} (ZAR {amount:.2f} equivalent) from wallet.",
                                "new_balance": str(usd_balance.balance),
                                "currency": "USD",
                                "deducted_amount": str(usd_amount),
                                "equivalent_amount": str(amount),
                                "equivalent_currency": "ZAR"
                            }
                            logger.debug("deduct_balance returning: %s", payload)
                            return Response(payload, status=status.HTTP_200_OK)
                        except (WalletBalance.DoesNotExist, Currency.DoesNotExist):
                            pass

                    payload = {"code": "NO_BALANCE", "message": f"No {currency_code} balance found."}
                    logger.debug("deduct_balance returning: %s", payload)
                    return Response(payload, status=status.HTTP_404_NOT_FOUND)
        except Exception:
            # Let outer exception handler catch and log
            raise

        # Regular deduction if the user has balance in the requested currency
        if wallet_balance.balance < amount:
            payload = {
                "code": "INSUFFICIENT_FUNDS",
                "message": f"Insufficient balance. Required {amount} {currency.code}, available {wallet_balance.balance} {currency.code}.",
                "required": str(amount),
                "available": str(wallet_balance.balance),
                "currency": currency.code
            }
            logger.debug("deduct_balance returning: %s", payload)
            return Response(payload, status=402)

        wallet_balance.balance -= amount
        wallet_balance.save()
        
        # Record transaction
        from .models import WalletTransaction
        WalletTransaction.objects.create(
            wallet=wallet,
            currency=currency,
            amount='-' + str(amount),
            transaction_type='payment',
            description='Booking payment'
        )

        payload = {
            "message": f"Deducted {amount:.2f} {currency.code} from wallet.",
            "new_balance": str(wallet_balance.balance),
            "currency": currency.code,
            "deducted_amount": str(amount)
        }
        logger.debug("deduct_balance returning: %s", payload)
        return Response(payload, status=status.HTTP_200_OK)

    except (ValueError, TypeError, InvalidOperation) as e:
        logger.exception("deduct_balance validation error: %s", str(e))
        payload = {"code": "VALIDATION_ERROR", "message": "Invalid or missing amount."}
        logger.debug("deduct_balance returning: %s", payload)
        return Response(payload, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        logger.exception("deduct_balance unexpected error: %s", str(e))
        payload = {"code": "SERVER_ERROR", "message": str(e)}
        logger.debug("deduct_balance returning: %s", payload)
        return Response(payload, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

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
            return Response({
                "code": "INSUFFICIENT_FUNDS",
                "message": f"Insufficient balance. Required {amount} {currency.code}, available {balance_obj.balance} {currency.code}.",
                "required": str(amount),
                "available": str(balance_obj.balance),
                "currency": currency.code
            }, status=402)

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


# BANCABC Payment Integration Endpoints
@api_view(['POST'])
@authentication_classes([BancABCAuthentication])
@permission_classes([AllowAny])
@bancabc_rate_limit(max_calls=20, time_window=60)  # 20 calls per minute
def bancabc_payment_success(request):
    """
    Callback endpoint for successful BANCABC wallet financing transactions.
    BANCABC calls this endpoint when a payment is successfully processed.
    """
    try:
        # Extract and sanitize transaction data from BANCABC callback
        transaction_id = request.data.get('transaction_id')
        user_id = request.data.get('user_id')
        amount = request.data.get('amount')
        currency = request.data.get('currency', 'ZAR').upper()
        reference = request.data.get('reference', '').strip()[:255]  # Limit length
        bancabc_transaction_id = request.data.get('bancabc_transaction_id', '').strip()[:255]
        bancabc_reference = request.data.get('bancabc_reference', '').strip()[:255]  # BancABC payment reference
        payment_method = request.data.get('payment_method', 'BANCABC').strip()[:50]

        # Comprehensive input validation
        validation_errors = []

        # Validate required fields
        if not transaction_id or not isinstance(transaction_id, str) or len(transaction_id.strip()) == 0:
            validation_errors.append('transaction_id is required and must be a non-empty string')
        else:
            transaction_id = transaction_id.strip()[:255]  # Sanitize and limit length

        if not user_id:
            validation_errors.append('user_id is required')
        else:
            try:
                user_id = int(user_id)
                if user_id <= 0:
                    validation_errors.append('user_id must be a positive integer')
            except (ValueError, TypeError):
                validation_errors.append('user_id must be a valid integer')

        if amount is None:
            validation_errors.append('amount is required')
        else:
            try:
                amount_decimal = Decimal(str(amount))
                if amount_decimal <= 0:
                    validation_errors.append('amount must be greater than zero')
                if amount_decimal > Decimal('1000000'):  # Reasonable upper limit
                    validation_errors.append('amount exceeds maximum allowed value')
            except (ValueError, TypeError, InvalidOperation):
                validation_errors.append('amount must be a valid decimal number')

        # Validate currency (USD only)
        if currency != 'USD':
            validation_errors.append('currency must be USD')

        # Validate transaction_id format (alphanumeric, hyphens, underscores only)
        if transaction_id and not re.match(r'^[a-zA-Z0-9_-]+$', transaction_id):
            validation_errors.append('transaction_id contains invalid characters')

        if validation_errors:
            return Response({
                'status': 'error',
                'message': 'Validation failed',
                'errors': validation_errors
            }, status=status.HTTP_400_BAD_REQUEST)

        # Get user and validate
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({
                'status': 'error',
                'message': 'User not found'
            }, status=status.HTTP_404_NOT_FOUND)

        # Get or create wallet and balance
        currency_obj = get_object_or_404(Currency, code=currency.upper())
        wallet, _ = Wallet.objects.get_or_create(user=user)
        wallet_balance, _ = WalletBalance.objects.get_or_create(wallet=wallet, currency=currency_obj)

        # Convert amount to Decimal
        try:
            amount_decimal = Decimal(str(amount))
        except (ValueError, TypeError):
            return Response({
                'status': 'error',
                'message': 'Invalid amount format'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Idempotency check using Idempotency-Key header
        idempotency_key = request.META.get('HTTP_IDEMPOTENCY_KEY')
        if idempotency_key:
            try:
                processed_txn = ProcessedTransaction.objects.get(idempotency_key=idempotency_key)
                # Return the cached response if already processed
                if processed_txn.status == 'completed' and processed_txn.response_data:
                    return Response(processed_txn.response_data, status=status.HTTP_200_OK)
                elif processed_txn.status == 'processing':
                    return Response({
                        'status': 'processing',
                        'message': 'Transaction is being processed',
                        'transaction_id': transaction_id
                    }, status=status.HTTP_202_ACCEPTED)
            except ProcessedTransaction.DoesNotExist:
                pass  # Continue processing

        # Check for duplicate transaction by transaction_id
        existing_processed = ProcessedTransaction.objects.filter(
            transaction_id=transaction_id,
            status='completed'
        ).first()

        if existing_processed:
            return Response({
                'status': 'success',
                'message': 'Transaction already processed',
                'transaction_id': transaction_id
            }, status=status.HTTP_200_OK)

        # SECURITY CHECK: Verify payment was successful before crediting wallet
        # Check if BancABC has notified us about successful payment
        payment_verification = ProcessedTransaction.objects.filter(
            bancabc_transaction_id=bancabc_reference,
            status='payment_verified'
        ).first()

        if not payment_verification:
            # Payment not verified - reject credit push
            logger.error(f"BancABC credit push rejected - payment not verified: {bancabc_reference}")
            return Response({
                'status': 'error',
                'message': 'Payment not verified. Please call Payment Notification API first to report successful payment.',
                'bancabc_reference': bancabc_reference,
                'required_action': 'Call POST /api/wallets/bancabc/payment/notify/ with payment_status=SUCCESS first'
            }, status=status.HTTP_403_FORBIDDEN)

        # Create processed transaction record
        processed_txn, created = ProcessedTransaction.objects.get_or_create(
            transaction_id=transaction_id,
            defaults={
                'idempotency_key': idempotency_key or f"bancabc-{transaction_id}-{timezone.now().timestamp()}",
                'user': user,
                'amount': amount_decimal,
                'currency': currency_obj,
                'status': 'processing',
                'bancabc_transaction_id': bancabc_transaction_id,
            }
        )

        if not created and processed_txn.status == 'completed':
            return Response({
                'status': 'success',
                'message': 'Transaction already processed',
                'transaction_id': transaction_id
            }, status=status.HTTP_200_OK)

        try:
            # Top up wallet balance within transaction
            with transaction.atomic():
                wallet_balance.balance += amount_decimal
                wallet_balance.save()

                # Record transaction
                WalletTransaction.objects.create(
                    wallet=wallet,
                    currency=currency_obj,
                    amount=str(amount_decimal),
                    transaction_type='deposit',
                    description=f'BANCABC Wallet Top-up - Transaction: {transaction_id}, Reference: {reference or "N/A"}'
                )

                # Award loyalty points (10% of amount = 1 point per $10)
                from loyalty.models import LoyaltyAccount
                loyalty_account, _ = LoyaltyAccount.objects.get_or_create(user=user)
                points_earned = int(amount_decimal / 10)  # $100 = 10 points
                if points_earned > 0:
                    loyalty_account.add_points(points_earned, f"Reward: BANCABC Wallet Top-Up Bonus ({points_earned} points)")

                # Update processed transaction status
                processed_txn.status = 'completed'
                processed_txn.processed_at = timezone.now()
                processed_txn.response_data = {
                    'status': 'success',
                    'message': f'Wallet topped up successfully with {amount} {currency}',
                    'transaction_id': transaction_id,
                    'new_balance': str(wallet_balance.balance),
                    'points_earned': points_earned,
                    'processed_at': processed_txn.processed_at.isoformat()
                }
                processed_txn.save()

                # Log successful transaction
                logger.info(f"BANCABC payment success: User {user_id}, Amount {amount} {currency}, Transaction {transaction_id}")

                return Response(processed_txn.response_data, status=status.HTTP_200_OK)

        except Exception as e:
            # Mark transaction as failed
            processed_txn.status = 'failed'
            processed_txn.response_data = {
                'status': 'error',
                'message': f'Processing failed: {str(e)}'
            }
            processed_txn.save()

            logger.error(f"BANCABC payment processing error: {str(e)}")
            return Response({
                'status': 'error',
                'message': 'Internal server error processing payment'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    except Exception as e:
        logger.error(f"BANCABC payment success callback error: {str(e)}")
        return Response({
            'status': 'error',
            'message': 'Internal server error processing payment'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@authentication_classes([BancABCAuthentication])
@permission_classes([AllowAny])
@bancabc_rate_limit(max_calls=20, time_window=60)
def bancabc_payment_failure(request):
    """
    Callback endpoint for failed BANCABC wallet financing transactions.
    BANCABC calls this endpoint when a payment fails or is declined.
    """
    try:
        # Extract transaction data from BANCABC callback
        transaction_id = request.data.get('transaction_id')
        user_id = request.data.get('user_id')
        amount = request.data.get('amount')
        currency = request.data.get('currency', 'ZAR')
        reference = request.data.get('reference')
        failure_reason = request.data.get('failure_reason', 'Unknown')
        bancabc_transaction_id = request.data.get('bancabc_transaction_id')

        # Validate required fields
        if not transaction_id:
            return Response({
                'status': 'error',
                'message': 'Missing required field: transaction_id'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Log failed transaction (don't need to modify wallet balance)
        logger.warning(f"BANCABC payment failure: Transaction {transaction_id}, User {user_id}, Reason: {failure_reason}")

        # Optional: Store failure record in database for audit purposes
        # You could create a FailedTransaction model if needed

        return Response({
            'status': 'acknowledged',
            'message': 'Payment failure acknowledged',
            'transaction_id': transaction_id,
            'failure_reason': failure_reason,
            'processed_at': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"BANCABC payment failure callback error: {str(e)}")
        return Response({
            'status': 'error',
            'message': 'Internal server error processing failure notification'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@authentication_classes([BancABCAuthentication])
@permission_classes([AllowAny])
@bancabc_rate_limit(max_calls=10, time_window=60)  # Lower limit for account updates
def bancabc_account_update(request):
    """
    Callback endpoint for BANCABC account updates.
    BANCABC calls this endpoint when user account information needs to be updated.
    """
    try:
        # Extract account update data from BANCABC callback
        user_id = request.data.get('user_id')
        account_number = request.data.get('account_number')
        account_status = request.data.get('account_status')  # active, suspended, closed
        account_type = request.data.get('account_type')
        last_updated = request.data.get('last_updated')

        # Validate required fields
        if not user_id:
            return Response({
                'status': 'error',
                'message': 'Missing required field: user_id'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Get user and validate
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({
                'status': 'error',
                'message': 'User not found'
            }, status=status.HTTP_404_NOT_FOUND)

        # Update user account information
        update_fields = []
        if account_number is not None:
            user.account_number = account_number
            update_fields.append('account_number')

        if account_status is not None:
            user.account_status = account_status
            update_fields.append('account_status')

        if account_type is not None:
            user.account_type = account_type
            update_fields.append('account_type')

        if update_fields:
            user.save(update_fields=update_fields)

        # Log account update
        logger.info(f"BANCABC account update: User {user_id}, Updated fields: {', '.join(update_fields)}")

        return Response({
            'status': 'success',
            'message': 'Account information updated successfully',
            'user_id': user_id,
            'updated_fields': update_fields,
            'processed_at': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"BANCABC account update callback error: {str(e)}")
        return Response({
            'status': 'error',
            'message': 'Internal server error processing account update'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# BANCABC Payment Initiation Endpoint
@api_view(['POST'])
@permission_classes([AllowAny])  # Public endpoint for payment initiation
def bancabc_initiate_payment(request):
    """
    Initiate a BANCABC wallet financing payment.
    This endpoint creates a payment request and returns BANCABC payment details.
    """
    try:
        # Extract payment initiation data
        user_id = request.data.get('user_id')
        amount = request.data.get('amount')
        currency = request.data.get('currency', 'ZAR')
        return_url = request.data.get('return_url')  # URL to redirect after payment
        callback_url = request.data.get('callback_url')  # Our callback URL for BANCABC

        # Validate required fields
        if not all([user_id, amount, return_url]):
            return Response({
                'status': 'error',
                'message': 'Missing required fields: user_id, amount, return_url'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Get user and validate
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({
                'status': 'error',
                'message': 'User not found'
            }, status=status.HTTP_404_NOT_FOUND)

        # Validate amount
        try:
            amount_decimal = Decimal(str(amount))
            if amount_decimal <= 0 or amount_decimal > Decimal('10000'):
                return Response({
                    'status': 'error',
                    'message': 'Amount must be between 0.01 and 10000'
                }, status=status.HTTP_400_BAD_REQUEST)
        except (ValueError, TypeError, InvalidOperation):
            return Response({
                'status': 'error',
                'message': 'Invalid amount format'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Generate unique transaction ID
        import uuid
        transaction_id = f"BANCABC-{uuid.uuid4().hex[:16].upper()}"

        # Get or create wallet and balance
        currency_obj = get_object_or_404(Currency, code=currency.upper())
        wallet, _ = Wallet.objects.get_or_create(user=user)
        wallet_balance, _ = WalletBalance.objects.get_or_create(wallet=wallet, currency=currency_obj)

        # Create payment initiation record (you might want to create a PaymentInitiation model)
        # For now, we'll use ProcessedTransaction with 'processing' status
        processed_txn = ProcessedTransaction.objects.create(
            idempotency_key=f"init-{transaction_id}-{timezone.now().timestamp()}",
            transaction_id=transaction_id,
            user=user,
            amount=amount_decimal,
            currency=currency_obj,
            status='processing',
            bancabc_transaction_id=None,  # Will be set when BANCABC responds
            response_data={
                'initiated_at': timezone.now().isoformat(),
                'amount': str(amount_decimal),
                'currency': currency,
                'return_url': return_url,
                'callback_url': callback_url or f"{request.scheme}://{request.get_host()}/api/wallets/bancabc/payment/success/"
            }
        )

        # In a real implementation, you would:
        # 1. Call BANCABC's API to initiate payment
        # 2. Get payment URL and reference from BANCABC
        # 3. Return the payment URL to frontend

        # For now, simulate BANCABC response
        bancabc_payment_url = f"https://bancabc-payment-gateway.com/pay?transaction_id={transaction_id}&amount={amount_decimal}&currency={currency}&return_url={return_url}"

        # Log payment initiation
        logger.info(f"BANCABC payment initiated: User {user_id}, Amount {amount} {currency}, Transaction {transaction_id}")

        return Response({
            'status': 'success',
            'transaction_id': transaction_id,
            'payment_url': bancabc_payment_url,
            'amount': str(amount_decimal),
            'currency': currency,
            'expires_at': (timezone.now() + timedelta(minutes=30)).isoformat(),  # Payment expires in 30 minutes
            'message': 'Payment initiated successfully. Redirect user to payment_url.'
        }, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"BANCABC payment initiation error: {str(e)}")
        return Response({
            'status': 'error',
            'message': 'Internal server error initiating payment'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([AllowAny])
def bancabc_payment_status(request, transaction_id):
    """
    Check the status of a BANCABC payment.
    """
    try:
        # Find the processed transaction
        processed_txn = ProcessedTransaction.objects.filter(
            transaction_id=transaction_id
        ).first()

        if not processed_txn:
            return Response({
                'status': 'error',
                'message': 'Transaction not found'
            }, status=status.HTTP_404_NOT_FOUND)

        return Response({
            'status': 'success',
            'transaction_id': transaction_id,
            'payment_status': processed_txn.status,
            'amount': str(processed_txn.amount),
            'currency': processed_txn.currency.code,
            'created_at': processed_txn.created_at.isoformat(),
            'processed_at': processed_txn.processed_at.isoformat() if processed_txn.processed_at else None
        }, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"BANCABC payment status error: {str(e)}")
        return Response({
            'status': 'error',
            'message': 'Internal server error checking payment status'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ================================
# BancABC Wallet Validation & Credit Push APIs
# ================================

@api_view(['POST'])
@authentication_classes([BancABCAuthentication])
@permission_classes([AllowAny])
@bancabc_rate_limit(max_calls=30, time_window=60)  # 30 calls per minute for validation
def bancabc_wallet_validation(request):
    """
    Wallet Validation/Lookup API for BancABC
    
    Allows BancABC to look up and validate Fastjet customer accounts from their system.
    BancABC can search by phone number, email, or customer ID to verify if a customer
    has a Fastjet account before initiating a wallet funding transaction.
    
    Request Body:
    {
        "phone_number": "263771234567",     // Optional - Primary lookup method
        "email": "customer@email.com",      // Optional - Alternative lookup
        "customer_id": "12345",             // Optional - If BancABC has stored it
        "national_id": "63-123456-A-12",    // Optional - Future use
        "account_number": "BANCABC-ACC-123" // Optional - BancABC's reference
    }
    
    At least one identifier is required (phone_number, email, or customer_id).
    
    Response (Customer Found):
    {
        "status": "success",
        "customer_found": true,
        "customer_details": {
            "customer_id": 12345,
            "phone_number": "263771234567",
            "email": "customer@email.com",
            "first_name": "John",
            "last_name": "Doe",
            "full_name": "John Doe",
            "user_type": "individual",
            "company_name": null,
            "wallet_exists": true,
            "wallet_active": true,
            "account_status": "active",
            "is_verified": true,
            "is_approved": true,
            "can_receive_funds": true,
            "registered_date": "2024-01-15T10:30:00Z",
            "currencies": ["USD", "ZAR"],
            "balances": {
                "USD": "150.00",
                "ZAR": "2500.00"
            },
            "total_transactions": 45,
            "last_transaction_date": "2025-12-01T15:20:00Z"
        },
        "validation_timestamp": "2025-12-04T10:30:00Z",
        "bancabc_reference": "BANCABC-ACC-123"
    }
    
    Response (Customer Not Found):
    {
        "status": "success",
        "customer_found": false,
        "message": "No Fastjet account found for the provided details",
        "searched_by": "phone_number",
        "validation_timestamp": "2025-12-04T10:30:00Z"
    }
    """
    start_time = time.time()
    try:
        # Extract all possible lookup parameters
        phone_number = request.data.get('phone_number', '').strip()
        email = request.data.get('email', '').strip()
        customer_id = request.data.get('customer_id')
        national_id = request.data.get('national_id', '').strip()
        account_number = request.data.get('account_number', '').strip()

        # Validate input - at least one identifier required
        if not phone_number and not email and not customer_id and not national_id:
            response_data = {
                'status': 'error',
                'message': 'At least one identifier is required: phone_number, email, customer_id, or national_id'
            }
            log_bancabc_api_call(request, 'wallet_validate', 400, response_data, 'validation_error', 
                               'Missing required identifier', start_time=start_time)
            return Response(response_data, status=status.HTTP_400_BAD_REQUEST)

        # Try to find user by various methods (in priority order)
        user = None
        search_method = None
        
        # Method 1: Search by customer ID (most specific)
        if customer_id and not user:
            try:
                user = User.objects.filter(id=int(customer_id)).first()
                if user:
                    search_method = 'customer_id'
            except (ValueError, TypeError):
                pass
        
        # Method 2: Search by phone number (most common)
        if phone_number and not user:
            # Normalize phone number (remove spaces, dashes, parentheses, etc.)
            normalized_phone = re.sub(r'[^0-9+]', '', phone_number)
            
            # Try exact match first
            user = User.objects.filter(phone_number=normalized_phone).first()
            
            # Try variations if exact match fails
            if not user and normalized_phone.startswith('263'):
                # Try with +263
                user = User.objects.filter(phone_number=f'+{normalized_phone}').first()
            elif not user and normalized_phone.startswith('+263'):
                # Try without +
                user = User.objects.filter(phone_number=normalized_phone[1:]).first()
            elif not user and normalized_phone.startswith('0'):
                # Try replacing leading 0 with 263
                user = User.objects.filter(phone_number=f'263{normalized_phone[1:]}').first()
            
            if user:
                search_method = 'phone_number'
        
        # Method 3: Search by email
        if email and not user:
            user = User.objects.filter(email__iexact=email).first()
            if user:
                search_method = 'email'
        
        # Method 4: Search by national ID (if implemented in future)
        # This is a placeholder for future enhancement
        if national_id and not user:
            # user = User.objects.filter(national_id=national_id).first()
            # if user:
            #     search_method = 'national_id'
            pass

        # If user not found after all attempts
        if not user:
            logger.info(f"BancABC lookup: Customer not found - Phone: {phone_number}, Email: {email}, ID: {customer_id}")
            response_data = {
                'status': 'success',
                'customer_found': False,
                'message': 'No Fastjet account found for the provided details',
                'searched_by': 'phone_number' if phone_number else 'email' if email else 'customer_id',
                'validation_timestamp': timezone.now().isoformat()
            }
            log_bancabc_api_call(request, 'wallet_validate', 200, response_data, 'success', start_time=start_time)
            return Response(response_data, status=status.HTTP_200_OK)

        # Get wallet information
        wallet = None
        wallet_balances = {}
        currencies = []
        wallet_active = False
        total_transactions = 0
        last_transaction_date = None
        
        if hasattr(user, 'wallet'):
            wallet = user.wallet
            wallet_active = True
            
            # Get balances
            balances = WalletBalance.objects.filter(wallet=wallet)
            for balance in balances:
                currencies.append(balance.currency.code)
                wallet_balances[balance.currency.code] = str(balance.balance)
            
            # Get transaction stats
            transactions = WalletTransaction.objects.filter(wallet=wallet)
            total_transactions = transactions.count()
            
            latest_txn = transactions.order_by('-created_at').first()
            if latest_txn:
                last_transaction_date = latest_txn.created_at.isoformat()

        # Determine if customer can receive funds
        can_receive_funds = (
            user.is_active and 
            user.is_approved and 
            wallet is not None
        )

        # Build comprehensive customer details response
        customer_details = {
            'customer_id': user.id,
            'phone_number': user.phone_number,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'full_name': user.get_full_name(),
            'user_type': user.user_type,
            'company_name': user.company_name if user.user_type == 'corporate' else None,
            'wallet_exists': wallet is not None,
            'wallet_active': wallet_active,
            'account_status': 'active' if user.is_active else 'inactive',
            'is_verified': user.email_verified,
            'is_approved': user.is_approved,
            'can_receive_funds': can_receive_funds,
            'registered_date': user.date_joined.isoformat() if hasattr(user, 'date_joined') else None,
            'currencies': currencies,
            'balances': wallet_balances,
            'total_transactions': total_transactions,
            'last_transaction_date': last_transaction_date
        }

        # Log successful validation
        logger.info(f"BancABC lookup success: User {user.id} ({user.phone_number}) found via {search_method}")

        response_data = {
            'status': 'success',
            'customer_found': True,
            'search_method': search_method,
            'customer_details': customer_details,
            'validation_timestamp': timezone.now().isoformat(),
            'bancabc_reference': account_number if account_number else None
        }
        log_bancabc_api_call(request, 'wallet_validate', 200, response_data, 'success', start_time=start_time)
        return Response(response_data, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"BancABC wallet validation error: {str(e)}", exc_info=True)
        response_data = {
            'status': 'error',
            'message': 'Internal server error during validation'
        }
        log_bancabc_api_call(request, 'wallet_validate', 500, response_data, 'error', str(e), start_time=start_time)
        return Response(response_data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@authentication_classes([BancABCAuthentication])
@permission_classes([AllowAny])
@bancabc_rate_limit(max_calls=20, time_window=60)  # 20 calls per minute for credit push
def bancabc_credit_push(request):
    """
    Credit Push API for BancABC
    
    Credits customer wallet directly from BancABC channels (branches, kiosks, digital, agents).
    This endpoint receives payment information from BancABC and credits the customer's wallet.
    
    Request Body:
    {
        "transaction_id": "BANCABC-TXN-123456",     // Required - Unique transaction ID
        "bancabc_reference": "REF-789012",          // Required - BancABC internal reference
        "customer_id": 12345,                        // Optional (phone or customer_id required)
        "phone_number": "263771234567",              // Optional (phone or customer_id required)
        "amount": 100.00,                            // Required - Amount to credit
        "currency": "USD",                           // Required - Currency code
        "channel": "branch",                         // Required - branch/kiosk/digital/agent
        "operator_id": "OP123",                      // Optional - Operator who processed
        "branch_code": "HRE001",                     // Optional - Branch/location code
        "remarks": "Wallet funding via BancABC",     // Optional - Transaction remarks
        "customer_account": "ACC123456"              // Optional - Customer's BancABC account
    }
    
    Response:
    {
        "status": "success",
        "message": "Wallet credited successfully with 100.00 USD",
        "transaction_id": "BANCABC-TXN-123456",
        "fastjet_transaction_id": "FJ-INT-789ABC",
        "customer_id": 12345,
        "amount": "100.00",
        "currency": "USD",
        "new_balance": "250.00",
        "points_earned": 10,
        "processed_at": "2025-12-04T10:30:00Z",
        "bancabc_reference": "REF-789012"
    }
    """
    start_time = time.time()
    try:
        # Extract transaction data
        transaction_id = request.data.get('transaction_id', '').strip()
        bancabc_reference = request.data.get('bancabc_reference', '').strip()
        customer_id = request.data.get('customer_id')
        phone_number = request.data.get('phone_number', '').strip()
        amount = request.data.get('amount')
        currency = request.data.get('currency', 'USD').upper()
        channel = request.data.get('channel', 'unknown').lower()
        operator_id = request.data.get('operator_id', '').strip()
        branch_code = request.data.get('branch_code', '').strip()
        remarks = request.data.get('remarks', 'Wallet funding via BancABC').strip()[:255]
        customer_account = request.data.get('customer_account', '').strip()

        # Comprehensive validation
        validation_errors = []

        # Validate required fields
        if not transaction_id:
            validation_errors.append('transaction_id is required')
        if not bancabc_reference:
            validation_errors.append('bancabc_reference is required')
        if not phone_number and not customer_id:
            validation_errors.append('Either phone_number or customer_id is required')
        if amount is None:
            validation_errors.append('amount is required')
        if not currency:
            validation_errors.append('currency is required')
        if not channel:
            validation_errors.append('channel is required')

        # Validate amount
        if amount is not None:
            try:
                amount_decimal = Decimal(str(amount))
                if amount_decimal <= 0:
                    validation_errors.append('amount must be greater than zero')
                if amount_decimal > Decimal('1000000'):
                    validation_errors.append('amount exceeds maximum allowed value')
            except (ValueError, TypeError, InvalidOperation):
                validation_errors.append('amount must be a valid decimal number')

        # Validate currency
        if currency and currency not in ['USD', 'ZAR', 'ZWG', 'EUR', 'GBP']:
            validation_errors.append(f'currency must be one of: USD, ZAR, ZWG, EUR, GBP')

        # Validate channel
        valid_channels = ['branch', 'kiosk', 'digital', 'agent', 'atm', 'online', 'mobile']
        if channel and channel not in valid_channels:
            validation_errors.append(f'channel must be one of: {", ".join(valid_channels)}')

        if validation_errors:
            logger.warning(f"BancABC credit push validation failed: {', '.join(validation_errors)}")
            response_data = {
                'status': 'error',
                'message': 'Validation failed',
                'errors': validation_errors
            }
            log_bancabc_api_call(request, 'wallet_credit', 400, response_data, 'validation_error',
                               ', '.join(validation_errors), start_time=start_time)
            return Response(response_data, status=status.HTTP_400_BAD_REQUEST)

        # Find user
        user = None
        if phone_number:
            normalized_phone = re.sub(r'[^0-9+]', '', phone_number)
            user = User.objects.filter(phone_number=normalized_phone).first()
        elif customer_id:
            try:
                user = User.objects.filter(id=int(customer_id)).first()
            except (ValueError, TypeError):
                response_data = {
                    'status': 'error',
                    'message': 'Invalid customer_id format'
                }
                log_bancabc_api_call(request, 'wallet_credit', 400, response_data, 'validation_error',
                                   'Invalid customer_id format', start_time=start_time)
                return Response(response_data, status=status.HTTP_400_BAD_REQUEST)

        if not user:
            logger.error(f"BancABC credit push failed: User not found - Phone: {phone_number}, ID: {customer_id}")
            response_data = {
                'status': 'error',
                'message': 'Customer not found in our system'
            }
            log_bancabc_api_call(request, 'wallet_credit', 404, response_data, 'failed',
                               'Customer not found', start_time=start_time)
            return Response(response_data, status=status.HTTP_404_NOT_FOUND)

        # Idempotency check
        idempotency_key = request.META.get('HTTP_IDEMPOTENCY_KEY') or f"bancabc-credit-{transaction_id}"
        
        existing_txn = ProcessedTransaction.objects.filter(
            idempotency_key=idempotency_key,
            status='completed'
        ).first()

        if existing_txn:
            # Return cached response
            logger.info(f"BancABC credit push - duplicate transaction: {transaction_id}")
            response_data = existing_txn.response_data or {
                'status': 'success',
                'message': 'Transaction already processed',
                'transaction_id': transaction_id
            }
            log_bancabc_api_call(request, 'wallet_credit', 200, response_data, 'duplicate',
                               'Transaction already processed', start_time=start_time)
            return Response(response_data, status=status.HTTP_200_OK)

        # Get currency object
        currency_obj = get_object_or_404(Currency, code=currency.upper())

        # Get or create wallet
        wallet, _ = Wallet.objects.get_or_create(user=user)
        wallet_balance, _ = WalletBalance.objects.get_or_create(wallet=wallet, currency=currency_obj)

        # Convert amount to Decimal
        amount_decimal = Decimal(str(amount))

        # Generate internal Fastjet transaction ID
        import uuid
        internal_txn_id = f"FJ-BANCABC-{uuid.uuid4().hex[:12].upper()}"

        # Create processed transaction record
        processed_txn = ProcessedTransaction.objects.create(
            idempotency_key=idempotency_key,
            transaction_id=internal_txn_id,
            user=user,
            amount=amount_decimal,
            currency=currency_obj,
            status='processing',
            bancabc_transaction_id=bancabc_reference,
            response_data={
                'bancabc_transaction_id': transaction_id,
                'bancabc_reference': bancabc_reference,
                'channel': channel,
                'operator_id': operator_id,
                'branch_code': branch_code,
                'customer_account': customer_account
            }
        )

        try:
            # Credit wallet within atomic transaction
            with transaction.atomic():
                wallet_balance.balance += amount_decimal
                wallet_balance.save()

                # Record wallet transaction
                transaction_description = f"BancABC Credit Push - {channel.upper()} channel"
                if branch_code:
                    transaction_description += f" - Branch: {branch_code}"
                if remarks:
                    transaction_description += f" - {remarks}"
                transaction_description += f" - Ref: {bancabc_reference}"

                WalletTransaction.objects.create(
                    wallet=wallet,
                    currency=currency_obj,
                    amount=str(amount_decimal),
                    transaction_type='deposit',
                    description=transaction_description,
                    reference=bancabc_reference
                )

                # Award loyalty points (10% of amount = 1 point per $10)
                from loyalty.models import LoyaltyAccount
                loyalty_account, _ = LoyaltyAccount.objects.get_or_create(user=user)
                points_earned = int(amount_decimal / 10)
                if points_earned > 0:
                    loyalty_account.add_points(
                        points_earned,
                        f"Reward: BancABC Wallet Funding ({points_earned} points) - {currency} {amount_decimal} via {channel}"
                    )

                # Update processed transaction
                processed_txn.status = 'completed'
                processed_txn.processed_at = timezone.now()
                processed_txn.response_data.update({
                    'status': 'success',
                    'message': f'Wallet credited successfully with {amount_decimal} {currency}',
                    'transaction_id': transaction_id,
                    'fastjet_transaction_id': internal_txn_id,
                    'customer_id': user.id,
                    'amount': str(amount_decimal),
                    'currency': currency,
                    'new_balance': str(wallet_balance.balance),
                    'points_earned': points_earned,
                    'processed_at': processed_txn.processed_at.isoformat(),
                    'bancabc_reference': bancabc_reference,
                    'channel': channel
                })
                processed_txn.save()

                # Log success
                logger.info(f"BancABC credit push success: User {user.id}, Amount {amount_decimal} {currency}, Channel {channel}, Ref {bancabc_reference}")

                log_bancabc_api_call(request, 'wallet_credit', 200, processed_txn.response_data, 'success',
                                   f'Wallet credited: {amount_decimal} {currency}', start_time=start_time,
                                   auto_credited=True, auto_credit_amount=amount_decimal)
                return Response(processed_txn.response_data, status=status.HTTP_200_OK)

        except Exception as e:
            # Mark transaction as failed
            processed_txn.status = 'failed'
            processed_txn.response_data.update({
                'status': 'error',
                'message': f'Processing failed: {str(e)}'
            })
            processed_txn.save()

            logger.error(f"BancABC credit push processing error: {str(e)}", exc_info=True)
            response_data = {
                'status': 'error',
                'message': 'Internal server error processing credit push'
            }
            log_bancabc_api_call(request, 'wallet_credit', 500, response_data, 'error',
                               f'Processing failed: {str(e)}', start_time=start_time)
            return Response(response_data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    except Exception as e:
        logger.error(f"BancABC credit push error: {str(e)}", exc_info=True)
        response_data = {
            'status': 'error',
            'message': 'Internal server error processing credit push'
        }
        log_bancabc_api_call(request, 'wallet_credit', 500, response_data, 'error',
                           f'Error: {str(e)}', start_time=start_time)
        return Response(response_data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@authentication_classes([BancABCAuthentication])
@permission_classes([AllowAny])
@bancabc_rate_limit(max_calls=30, time_window=60)  # 30 calls per minute for reports
def bancabc_transaction_report(request):
    """
    Transaction Report API for BancABC
    
    Provides transaction reports for reconciliation purposes.
    Returns both successful and failed transactions within specified date range.
    
    Request Body:
    {
        "start_date": "2025-12-01T00:00:00Z",  // Required - ISO 8601 format
        "end_date": "2025-12-04T23:59:59Z",    // Required - ISO 8601 format
        "transaction_type": "all",              // Optional - "all", "success", "failed"
        "channel": "branch",                    // Optional - Filter by channel
        "currency": "USD",                      // Optional - Filter by currency
        "page": 1,                              // Optional - Page number (default: 1)
        "page_size": 50                         // Optional - Records per page (default: 50, max: 1000)
    }
    
    Response:
    {
        "status": "success",
        "report": {
            "start_date": "2025-12-01T00:00:00Z",
            "end_date": "2025-12-04T23:59:59Z",
            "total_transactions": 150,
            "successful_transactions": 145,
            "failed_transactions": 5,
            "total_amount": {
                "USD": "15000.00",
                "ZAR": "250000.00"
            },
            "transactions": [
                {
                    "transaction_id": "FJ-BANCABC-ABC123",
                    "bancabc_reference": "REF-789012",
                    "bancabc_transaction_id": "BANCABC-TXN-123456",
                    "customer_id": 12345,
                    "phone_number": "263771234567",
                    "amount": "100.00",
                    "currency": "USD",
                    "status": "completed",
                    "channel": "branch",
                    "created_at": "2025-12-01T10:30:00Z",
                    "processed_at": "2025-12-01T10:30:05Z"
                }
            ]
        },
        "pagination": {
            "page": 1,
            "page_size": 50,
            "total_pages": 3,
            "total_records": 150
        },
        "generated_at": "2025-12-04T10:30:00Z"
    }
    """
    start_time = time.time()
    try:
        # Extract report parameters
        start_date_str = request.data.get('start_date')
        end_date_str = request.data.get('end_date')
        transaction_type = request.data.get('transaction_type', 'all').lower()
        channel_filter = request.data.get('channel', '').lower()
        currency_filter = request.data.get('currency', '').upper()
        page = int(request.data.get('page', 1))
        page_size = min(int(request.data.get('page_size', 50)), 1000)  # Max 1000 per page

        # Validate required fields
        if not start_date_str or not end_date_str:
            response_data = {
                'status': 'error',
                'message': 'start_date and end_date are required'
            }
            log_bancabc_api_call(request, 'transaction_report', 400, response_data, 'validation_error',
                               'Missing required dates', start_time=start_time)
            return Response(response_data, status=status.HTTP_400_BAD_REQUEST)

        # Parse dates
        try:
            from dateutil import parser
            start_date = parser.isoparse(start_date_str)
            end_date = parser.isoparse(end_date_str)
        except Exception:
            response_data = {
                'status': 'error',
                'message': 'Invalid date format. Use ISO 8601 format (e.g., 2025-12-01T00:00:00Z)'
            }
            log_bancabc_api_call(request, 'transaction_report', 400, response_data, 'validation_error',
                               'Invalid date format', start_time=start_time)
            return Response(response_data, status=status.HTTP_400_BAD_REQUEST)

        # Validate date range
        if start_date > end_date:
            response_data = {
                'status': 'error',
                'message': 'start_date must be before end_date'
            }
            log_bancabc_api_call(request, 'transaction_report', 400, response_data, 'validation_error',
                               'Invalid date range', start_time=start_time)
            return Response(response_data, status=status.HTTP_400_BAD_REQUEST)

        # Limit date range to 90 days for performance
        date_diff = (end_date - start_date).days
        if date_diff > 90:
            response_data = {
                'status': 'error',
                'message': 'Date range cannot exceed 90 days'
            }
            log_bancabc_api_call(request, 'transaction_report', 400, response_data, 'validation_error',
                               'Date range exceeds 90 days', start_time=start_time)
            return Response(response_data, status=status.HTTP_400_BAD_REQUEST)

        # Build query filters
        query_filters = {
            'created_at__gte': start_date,
            'created_at__lte': end_date,
            'bancabc_transaction_id__isnull': False  # Only BancABC transactions
        }

        # Filter by transaction status
        if transaction_type == 'success':
            query_filters['status'] = 'completed'
        elif transaction_type == 'failed':
            query_filters['status'] = 'failed'

        # Filter by currency
        if currency_filter:
            currency_obj = Currency.objects.filter(code=currency_filter).first()
            if currency_obj:
                query_filters['currency'] = currency_obj

        # Get transactions
        transactions_query = ProcessedTransaction.objects.filter(**query_filters).order_by('-created_at')

        # Filter by channel (stored in response_data JSON)
        if channel_filter:
            transactions_query = transactions_query.filter(response_data__channel=channel_filter)

        # Get total count before pagination
        total_count = transactions_query.count()

        # Calculate pagination
        total_pages = (total_count + page_size - 1) // page_size
        offset = (page - 1) * page_size
        
        # Get paginated results
        transactions = transactions_query[offset:offset + page_size]

        # Build transaction list
        transaction_list = []
        total_amounts = {}
        successful_count = 0
        failed_count = 0

        for txn in transactions:
            try:
                # Count status
                if txn.status == 'completed':
                    successful_count += 1
                elif txn.status == 'failed':
                    failed_count += 1

                # Aggregate amounts by currency
                if txn.status == 'completed' and txn.currency:
                    currency_code = txn.currency.code
                    if currency_code not in total_amounts:
                        total_amounts[currency_code] = Decimal('0.00')
                    total_amounts[currency_code] += txn.amount

                # Get channel from response_data
                response_data = txn.response_data or {}
                
                transaction_list.append({
                    'transaction_id': txn.transaction_id,
                    'bancabc_reference': getattr(txn, 'bancabc_transaction_id', '') or '',
                    'bancabc_transaction_id': response_data.get('bancabc_transaction_id', ''),
                    'customer_id': txn.user.id if txn.user else None,
                    'phone_number': getattr(txn.user, 'phone_number', '') if txn.user else '',
                    'email': getattr(txn.user, 'email', '') if txn.user else '',
                    'customer_name': txn.user.get_full_name() if txn.user and hasattr(txn.user, 'get_full_name') else '',
                    'amount': str(txn.amount) if txn.amount else '0.00',
                    'currency': txn.currency.code if txn.currency else 'USD',
                    'status': txn.status or 'unknown',
                    'channel': response_data.get('channel', 'unknown'),
                    'operator_id': response_data.get('operator_id', ''),
                    'branch_code': response_data.get('branch_code', ''),
                    'created_at': txn.created_at.isoformat() if txn.created_at else None,
                    'processed_at': txn.processed_at.isoformat() if txn.processed_at else None
                })
            except Exception as txn_error:
                logger.warning(f"Error processing transaction {txn.id}: {str(txn_error)}")
                continue

        # Convert Decimal to string for JSON serialization
        total_amounts_str = {k: str(v) for k, v in total_amounts.items()}

        # Build report response
        report = {
            'start_date': start_date.isoformat(),
            'end_date': end_date.isoformat(),
            'filters': {
                'transaction_type': transaction_type,
                'channel': channel_filter if channel_filter else 'all',
                'currency': currency_filter if currency_filter else 'all'
            },
            'summary': {
                'total_transactions': total_count,
                'successful_transactions': successful_count,
                'failed_transactions': failed_count,
                'total_amount': total_amounts_str
            },
            'transactions': transaction_list
        }

        # Log report generation
        logger.info(f"BancABC transaction report generated: {start_date} to {end_date}, {total_count} transactions")

        response_data = {
            'status': 'success',
            'report': report,
            'pagination': {
                'page': page,
                'page_size': page_size,
                'total_pages': total_pages,
                'total_records': total_count
            },
            'generated_at': timezone.now().isoformat()
        }
        log_bancabc_api_call(request, 'transaction_report', 200, response_data, 'success',
                           f'Report generated: {total_count} transactions', start_time=start_time)
        return Response(response_data, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"BancABC transaction report error: {str(e)}", exc_info=True)
        response_data = {
            'status': 'error',
            'message': 'Internal server error generating report'
        }
        log_bancabc_api_call(request, 'transaction_report', 500, response_data, 'error',
                           f'Error: {str(e)}', start_time=start_time)
        return Response(response_data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@authentication_classes([BancABCAuthentication])
@permission_classes([AllowAny])
@bancabc_rate_limit(max_calls=50, time_window=60)  # 50 calls per minute for payment notifications
def bancabc_payment_notification(request):
    """
    Payment Status Notification API for BancABC
    
    BancABC calls this endpoint to notify Fastjet about payment status BEFORE initiating credit push.
    This ensures wallets are only credited after successful payment verification.
    
    TWO-STEP PROCESS:
    Step 1: BancABC processes payment and calls this endpoint to report status
    Step 2: If payment successful, BancABC calls Credit Push API to fund wallet
    
    Request Body:
    {
        "bancabc_transaction_id": "BANCABC-TXN-123456",  // Required - BancABC's unique transaction ID
        "bancabc_reference": "REF-20251204-001",         // Required - Payment reference
        "payment_status": "SUCCESS",                      // Required - SUCCESS, FAILED, PENDING
        "customer_id": 12345,                             // Optional - Fastjet customer ID
        "phone_number": "263771234567",                   // Optional - Customer phone
        "amount": 100.00,                                 // Required - Payment amount
        "currency": "USD",                                // Required - Currency code
        "channel": "branch",                              // Required - Payment channel
        "operator_id": "OP123",                           // Optional - Operator who processed
        "branch_code": "HRE001",                          // Optional - Branch code
        "payment_method": "CASH",                         // Optional - CASH, CARD, TRANSFER, etc.
        "payment_date": "2025-12-04T10:30:00Z",          // Optional - Payment timestamp
        "failure_reason": "Insufficient funds",           // Required if FAILED
        "customer_account": "BANCABC-ACC-123456",        // Optional - Customer's BancABC account
        "remarks": "Payment processed successfully"       // Optional - Additional notes
    }
    
    Response (Success):
    {
        "status": "success",
        "message": "Payment status recorded successfully",
        "bancabc_transaction_id": "BANCABC-TXN-123456",
        "payment_status": "SUCCESS",
        "can_proceed_with_credit": true,
        "fastjet_reference": "FJ-PAY-ABC123DEF456",
        "recorded_at": "2025-12-04T10:30:15Z",
        "next_step": "Call Credit Push API to fund customer wallet"
    }
    
    Response (Failed Payment):
    {
        "status": "success",
        "message": "Failed payment recorded",
        "bancabc_transaction_id": "BANCABC-TXN-123456",
        "payment_status": "FAILED",
        "can_proceed_with_credit": false,
        "failure_reason": "Insufficient funds",
        "recorded_at": "2025-12-04T10:30:15Z",
        "next_step": "Do not proceed with wallet credit"
    }
    """
    start_time = time.time()
    try:
        # Extract payment notification data
        bancabc_transaction_id = request.data.get('bancabc_transaction_id', '').strip()
        bancabc_reference = request.data.get('bancabc_reference', '').strip()
        payment_status = request.data.get('payment_status', '').upper().strip()
        customer_id = request.data.get('customer_id')
        phone_number = request.data.get('phone_number', '').strip()
        amount = request.data.get('amount')
        currency = request.data.get('currency', 'USD').upper()
        channel = request.data.get('channel', 'unknown').lower()
        operator_id = request.data.get('operator_id', '').strip()
        branch_code = request.data.get('branch_code', '').strip()
        payment_method = request.data.get('payment_method', 'UNKNOWN').upper()
        payment_date_str = request.data.get('payment_date')
        failure_reason = request.data.get('failure_reason', '').strip()
        customer_account = request.data.get('customer_account', '').strip()
        remarks = request.data.get('remarks', '').strip()[:500]

        # Validation
        validation_errors = []

        if not bancabc_transaction_id:
            validation_errors.append('bancabc_transaction_id is required')
        if not bancabc_reference:
            validation_errors.append('bancabc_reference is required')
        if not payment_status:
            validation_errors.append('payment_status is required')
        elif payment_status not in ['SUCCESS', 'FAILED', 'PENDING', 'CANCELLED']:
            validation_errors.append('payment_status must be SUCCESS, FAILED, PENDING, or CANCELLED')
        
        if amount is None:
            validation_errors.append('amount is required')
        else:
            try:
                amount_decimal = Decimal(str(amount))
                if amount_decimal <= 0:
                    validation_errors.append('amount must be greater than zero')
            except (ValueError, TypeError, InvalidOperation):
                validation_errors.append('amount must be a valid decimal number')

        if not currency:
            validation_errors.append('currency is required')
        elif currency != 'USD':
            validation_errors.append('currency must be USD')
        
        if payment_status == 'FAILED' and not failure_reason:
            validation_errors.append('failure_reason is required when payment_status is FAILED')

        if validation_errors:
            logger.warning(f"BancABC payment notification validation failed: {', '.join(validation_errors)}")
            response_data = {
                'status': 'error',
                'message': 'Validation failed',
                'errors': validation_errors
            }
            log_bancabc_api_call(request, 'payment_notify', 400, response_data, 'validation_error',
                               ', '.join(validation_errors), start_time=start_time)
            return Response(response_data, status=status.HTTP_400_BAD_REQUEST)

        # Check for duplicate notification
        existing_payment = ProcessedTransaction.objects.filter(
            bancabc_transaction_id=bancabc_transaction_id
        ).first()

        if existing_payment:
            logger.info(f"BancABC payment notification - duplicate: {bancabc_transaction_id}")
            can_proceed = existing_payment.status == 'payment_verified'
            response_data = {
                'status': 'success',
                'message': 'Payment status already recorded',
                'bancabc_transaction_id': bancabc_transaction_id,
                'payment_status': payment_status,
                'can_proceed_with_credit': can_proceed,
                'fastjet_reference': existing_payment.transaction_id,
                'recorded_at': existing_payment.created_at.isoformat(),
                'duplicate': True
            }
            log_bancabc_api_call(request, 'payment_notify', 200, response_data, 'success', start_time=start_time)
            return Response(response_data, status=status.HTTP_200_OK)

        # Find customer (optional for payment notification)
        user = None
        if phone_number:
            normalized_phone = re.sub(r'[^0-9+]', '', phone_number)
            user = User.objects.filter(phone_number=normalized_phone).first()
        elif customer_id:
            try:
                user = User.objects.filter(id=int(customer_id)).first()
            except (ValueError, TypeError):
                pass

        # Get currency object
        currency_obj = Currency.objects.filter(code=currency.upper()).first()
        if not currency_obj:
            # Create currency if it doesn't exist
            currency_obj = Currency.objects.create(code=currency.upper(), name=currency)

        # Convert amount
        amount_decimal = Decimal(str(amount))

        # Generate internal Fastjet payment reference
        import uuid
        fastjet_payment_ref = f"FJ-PAY-{uuid.uuid4().hex[:12].upper()}"

        # Parse payment date
        payment_date = None
        if payment_date_str:
            try:
                from dateutil import parser
                payment_date = parser.isoparse(payment_date_str)
            except:
                payment_date = timezone.now()
        else:
            payment_date = timezone.now()

        # Determine internal status based on payment status
        internal_status = 'payment_verified' if payment_status == 'SUCCESS' else 'payment_failed'
        can_proceed_with_credit = payment_status == 'SUCCESS'

        # Create payment notification record
        payment_record = ProcessedTransaction.objects.create(
            idempotency_key=f"payment-notif-{bancabc_transaction_id}",
            transaction_id=fastjet_payment_ref,
            user=user,  # Can be None if customer not found
            amount=amount_decimal,
            currency=currency_obj,
            status=internal_status,
            bancabc_transaction_id=bancabc_transaction_id,
            created_at=payment_date,
            response_data={
                'notification_type': 'payment_status',
                'bancabc_reference': bancabc_reference,
                'payment_status': payment_status,
                'channel': channel,
                'operator_id': operator_id,
                'branch_code': branch_code,
                'payment_method': payment_method,
                'failure_reason': failure_reason if payment_status == 'FAILED' else None,
                'customer_account': customer_account,
                'remarks': remarks,
                'customer_id': customer_id,
                'phone_number': phone_number,
                'notification_received_at': timezone.now().isoformat()
            }
        )

        # Prepare response based on payment status
        if payment_status == 'SUCCESS':
            message = 'Payment status recorded successfully - proceed with wallet credit'
            next_step = 'Call Credit Push API with the same bancabc_transaction_id to fund customer wallet'
            logger.info(f"BancABC payment notification SUCCESS: {bancabc_transaction_id}, Amount: {amount_decimal} {currency}")
        elif payment_status == 'FAILED':
            message = 'Failed payment recorded - do not credit wallet'
            next_step = 'Do not proceed with wallet credit. Inform customer about payment failure.'
            logger.warning(f"BancABC payment notification FAILED: {bancabc_transaction_id}, Reason: {failure_reason}")
        elif payment_status == 'PENDING':
            message = 'Payment pending - wait for final status'
            next_step = 'Send another notification when payment status is finalized (SUCCESS or FAILED)'
            logger.info(f"BancABC payment notification PENDING: {bancabc_transaction_id}")
        else:  # CANCELLED
            message = 'Payment cancelled - do not credit wallet'
            next_step = 'Do not proceed with wallet credit. Payment was cancelled.'
            logger.info(f"BancABC payment notification CANCELLED: {bancabc_transaction_id}")

        response_data = {
            'status': 'success',
            'message': message,
            'bancabc_transaction_id': bancabc_transaction_id,
            'bancabc_reference': bancabc_reference,
            'payment_status': payment_status,
            'can_proceed_with_credit': can_proceed_with_credit,
            'fastjet_reference': fastjet_payment_ref,
            'amount': str(amount_decimal),
            'currency': currency,
            'recorded_at': payment_record.created_at.isoformat(),
            'next_step': next_step
        }

        if payment_status == 'FAILED':
            response_data['failure_reason'] = failure_reason

        # Log API call and auto-credit if SUCCESS
        auto_credited = False
        credit_txn_id = None
        auto_credit_amount = None
        points_earned = 0
        if payment_status == 'SUCCESS' and user:
            # Auto-credit the wallet
            try:
                wallet, _ = Wallet.objects.get_or_create(user=user)
                wallet_balance, _ = WalletBalance.objects.get_or_create(wallet=wallet, currency=currency_obj)
                wallet_balance.balance += amount_decimal
                wallet_balance.save()
                
                # Record wallet transaction
                WalletTransaction.objects.create(
                    wallet=wallet,
                    currency=currency_obj,
                    amount=str(amount_decimal),
                    transaction_type='deposit',
                    description=f"Auto-credit from BancABC payment - Ref: {bancabc_reference}",
                    reference=bancabc_reference
                )
                
                # Award loyalty points
                from loyalty.models import LoyaltyAccount
                loyalty_account, _ = LoyaltyAccount.objects.get_or_create(user=user)
                points_earned = int(amount_decimal / 10)
                if points_earned > 0:
                    loyalty_account.add_points(points_earned, f"BancABC Payment Bonus - {amount_decimal} {currency}")
                
                auto_credited = True
                credit_txn_id = fastjet_payment_ref
                auto_credit_amount = amount_decimal
                response_data['auto_credited'] = True
                response_data['new_balance'] = str(wallet_balance.balance)
                response_data['points_earned'] = points_earned
                logger.info(f"Auto-credited {amount_decimal} {currency} to user {user.id} from BancABC payment")
            except Exception as credit_error:
                logger.error(f"Auto-credit failed: {str(credit_error)}")
                response_data['auto_credit_failed'] = True
        
        log_bancabc_api_call(request, 'payment_notify', 200, response_data, 'success',
                           auto_credited=auto_credited, auto_credit_amount=auto_credit_amount,
                           points_awarded=points_earned,
                           credit_transaction_id=credit_txn_id, start_time=start_time)
        return Response(response_data, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"BancABC payment notification error: {str(e)}", exc_info=True)
        response_data = {
            'status': 'error',
            'message': 'Internal server error processing payment notification'
        }
        log_bancabc_api_call(request, 'payment_notify', 500, response_data, 'error', str(e), start_time=start_time)
        return Response(response_data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ================================
# InnBucks Wallet Integration
# ================================

# ================================
# InnBucks Wallet Integration
# ================================

class InnBucksClient:
    """
    Client for interacting with InnBucks API
    """
    def get_account_number_by_msisdn(self, msisdn: str) -> dict:
        """
        Get InnBucks account number by MSISDN
        """
        auth_result = self.ensure_authenticated()
        if not auth_result['success']:
            return auth_result
        url = f"{self.base_url}/api/account/msisdn/{msisdn}/details"
        try:
            response = requests.get(
                url,
                headers=self._get_headers(include_auth=True),
                timeout=30
            )
        except requests.exceptions.RequestException as e:
            logger.error(f"InnBucks account lookup error: {str(e)} | url={url}")
            return {'success': False, 'error': str(e)}
        if response.status_code != 200:
            logger.error(f"InnBucks account lookup HTTP error: {response.status_code} | url={url}")
            return {'success': False, 'error': f'HTTP {response.status_code}'}
        data = response.json()
        if 'accountNumber' in data:
            return {'success': True, 'accountNumber': data['accountNumber'], 'details': data}
        logger.error(f"InnBucks account lookup failed: {data}")
        return {'success': False, 'error': 'Account number not found'}

    def deposit_to_wallet(self, account_number: str, amount: int, narration: str, reference: str) -> dict:
        """
        Deposit funds from user's InnBucks account to Fastjet wallet
        """
        auth_result = self.ensure_authenticated()
        if not auth_result['success']:
            return auth_result
        url = f"{self.base_url}/api/transaction/deposit"
        payload = {
            "reference": reference,
            "amount": amount,
            "narration": narration,
            "destinationAccount": account_number
        }
        try:
            response = requests.post(
                url,
                json=payload,
                headers=self._get_headers(include_auth=True),
                timeout=30
            )
        except requests.exceptions.RequestException as e:
            logger.error(f"InnBucks deposit error: {str(e)} | url={url} payload={payload}")
            return {'success': False, 'error': str(e)}
        if response.status_code != 200:
            logger.error(f"InnBucks deposit HTTP error: {response.status_code} | url={url}")
            return {'success': False, 'error': f'HTTP {response.status_code}'}
        data = response.json()
        if str(data.get('responseCode')) in ['0', '00']:
            logger.info(f"InnBucks deposit successful: {data}")
            return {'success': True, 'data': data}
        logger.error(f"InnBucks deposit failed: {data}")
        return {'success': False, 'error': data.get('responseMsg', 'Deposit failed')}
    """
    Client for interacting with InnBucks API
    """
    def __init__(self) -> None:
        self.base_url: str = settings.INNBUCKS_BASE_URL
        self.api_key: str = settings.INNBUCKS_API_KEY
        self.username: str = settings.INNBUCKS_USERNAME
        self.password: str = settings.INNBUCKS_PASSWORD
        self.account: str = settings.INNBUCKS_ACCOUNT
        self.access_token: str | None = None
        self.token_expiry: timezone.datetime | None = None

    def _get_headers(self, include_auth: bool = False) -> dict:
        """Get headers for InnBucks API requests"""
        headers = {
            'X-Api-Key': self.api_key,
            'Content-Type': 'application/json'
        }
        if include_auth and self.access_token:
            headers['Authorization'] = f'Bearer {self.access_token}'
        return headers

    def authenticate(self) -> dict:
        """
        Authenticate with InnBucks API and get access token
        """
        url = f"{self.base_url}/auth/third-party"
        payload = {
            "username": self.username,
            "password": self.password
        }
        
        headers = self._get_headers()
        
        try:
            logger.info(f"InnBucks authenticating to: {url}")
            logger.debug(f"InnBucks auth headers: {headers}")
            logger.debug(f"InnBucks auth payload: {{'username': '{self.username}', 'password': '***'}}")
            
            response = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=30
            )
            
            logger.info(f"InnBucks auth response status: {response.status_code}")
        except requests.exceptions.RequestException as e:
            logger.error(f"InnBucks authentication error: {str(e)} | url={url}")
            return {'success': False, 'error': str(e)}

        if response.status_code != 200:
            # Log more details about the error
            try:
                error_data = response.json()
                logger.error(f"InnBucks authentication HTTP error: {response.status_code} | url={url} | response: {error_data}")
            except:
                logger.error(f"InnBucks authentication HTTP error: {response.status_code} | url={url} | response text: {response.text}")
            
            # Check for common authentication issues
            if response.status_code == 401:
                logger.error("InnBucks credentials may have expired. Please check if credentials need to be updated.")
            
            return {'success': False, 'error': f'HTTP {response.status_code}'}

        try:
            data = response.json()
            logger.info(f"InnBucks auth response data: {data}")
            
            # Check for responseCode "00" which indicates success
            if data.get('responseCode') == '00' and 'accessToken' in data:
                self.access_token = data['accessToken']
                # Set token expiry to now + 15 minutes (default for InnBucks)
                self.token_expiry = timezone.now() + timedelta(minutes=15)
                logger.info(f"InnBucks authentication successful. Token expires at: {self.token_expiry}")
                return {'success': True, 'token': self.access_token}
            else:
                error_msg = data.get('responseDescription', 'Authentication failed')
                logger.error(f"InnBucks authentication failed: {data}")
                return {'success': False, 'error': error_msg}
        except Exception as e:
            logger.error(f"Error processing InnBucks auth response: {str(e)}")
            return {'success': False, 'error': f'Error processing response: {str(e)}'}

    def ensure_authenticated(self) -> dict:
        """
        Check if authentication token is valid and re-authenticate if needed
        """
        # If no token or token expired, authenticate again
        if not self.access_token or not self.token_expiry or timezone.now() >= self.token_expiry:
            return self.authenticate()
        return {'success': True}

    def generate_code(self, amount: int, narration: str, reference: str, code_type: str = 'PAYMENT') -> dict:
        """
        Generate an InnBucks payment code
        
        Args:
            amount: Amount in cents as integer, no decimals (e.g., 1000 for $10.00)
            narration: Description of the transaction
            reference: Unique transaction reference
            code_type: Type of code (PAYMENT or WITHDRAWAL)
            
        Returns:
            Dictionary with success status and data/error
        """
        auth_result = self.ensure_authenticated()
        if not auth_result['success']:
            logger.error(f"InnBucks authentication failed before code generation: {auth_result.get('error')}")
            return auth_result
        
        url = f"{self.base_url}/api/code/generate"
        payload = {
            "amount": amount,
            "narration": narration,
            "reference": reference,
            "type": code_type
        }
        
        headers = self._get_headers(include_auth=True)
        
        try:
            logger.info(f"InnBucks generating code with payload: {payload}")
            logger.debug(f"InnBucks request headers: {headers}")
            logger.debug(f"InnBucks access token present: {bool(self.access_token)}")
            
            response = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=30
            )
            
            logger.info(f"InnBucks code generation response status: {response.status_code}")
        except requests.exceptions.RequestException as e:
            logger.error(f"InnBucks code generation error: {str(e)} | url={url} payload={payload}")
            return {'success': False, 'error': str(e)}
            
        if response.status_code != 200:
            try:
                error_data = response.json()
                logger.error(f"InnBucks code generation HTTP error: {response.status_code} | url={url} | response: {error_data}")
                
                # If error code is 06 and related to auth, try re-authenticating once
                if error_data.get('code') in ['06', '07'] and not hasattr(self, '_retry_attempted'):
                    logger.info("Attempting to re-authenticate due to possible token expiry...")
                    self._retry_attempted = True
                    self.access_token = None
                    self.token_expiry = None
                    return self.generate_code(amount, narration, reference, code_type)
                    
            except:
                logger.error(f"InnBucks code generation HTTP error: {response.status_code} | url={url} | response text: {response.text}")
            
            if hasattr(self, '_retry_attempted'):
                delattr(self, '_retry_attempted')
            return {'success': False, 'error': f'HTTP {response.status_code}'}
            
        try:
            data = response.json()
            logger.info(f"InnBucks code generation full response: {data}")
            
            # Check for successful response (responseCode 0)
            if data.get('responseCode') == 0 and 'code' in data:
                logger.info(f"InnBucks code generated successfully: {data.get('code')}")
                if hasattr(self, '_retry_attempted'):
                    delattr(self, '_retry_attempted')
                return {'success': True, 'data': data}
            else:
                error_msg = data.get('responseMsg', 'Code generation failed')
                logger.error(f"InnBucks code generation failed: {data}")
                if hasattr(self, '_retry_attempted'):
                    delattr(self, '_retry_attempted')
                return {'success': False, 'error': error_msg}
        except Exception as e:
            logger.error(f"Error processing InnBucks code generation response: {str(e)}")
            if hasattr(self, '_retry_attempted'):
                delattr(self, '_retry_attempted')
            return {'success': False, 'error': f'Error processing response: {str(e)}'}
            
    def query_code(self, code: str, reference: str = None) -> dict:
        """
        Query the status of an InnBucks payment code
        
        Args:
            code: InnBucks code to check
            reference: Optional transaction reference
            
        Returns:
            Dictionary with success status and data/error
        """
        auth_result = self.ensure_authenticated()
        if not auth_result['success']:
            return auth_result
            
        url = f"{self.base_url}/api/code/query"
        payload = {
            "code": code
        }
        if reference:
            payload["reference"] = reference
            
        try:
            logger.debug(f"InnBucks querying code: {code}")
            response = requests.post(  # Changed from GET to POST
                url,
                json=payload,
                headers=self._get_headers(include_auth=True),
                timeout=30
            )
        except requests.exceptions.RequestException as e:
            logger.error(f"InnBucks code query error: {str(e)} | url={url}")
            return {'success': False, 'error': str(e)}
            
        if response.status_code != 200:
            try:
                error_data = response.json()
                logger.error(f"InnBucks code query HTTP error: {response.status_code} | url={url} | response: {error_data}")
            except:
                logger.error(f"InnBucks code query HTTP error: {response.status_code} | url={url} | response text: {response.text}")
            return {'success': False, 'error': f'HTTP {response.status_code}'}
            
        try:
            data = response.json()
            # Check for successful response (responseCode 0)
            if data.get('responseCode') == 0 and 'status' in data:
                logger.info(f"InnBucks code {code} status: {data.get('status')}")
                return {'success': True, 'data': data}
            else:
                error_msg = data.get('responseMsg', 'Code query failed')
                logger.error(f"InnBucks code query failed: {data}")
                return {'success': False, 'error': error_msg}
        except Exception as e:
            logger.error(f"Error processing InnBucks code query response: {str(e)}")
            return {'success': False, 'error': f'Error processing response: {str(e)}'}



@api_view(['POST'])
@permission_classes([IsAuthenticated])
def innbucks_generate_code(request):
    """
    Generate an InnBucks payment code for wallet top-up
    """
    try:
        user_id = request.data.get('user_id')
        amount = request.data.get('amount')
        currency = request.data.get('currency', 'USD')
        
        # Validate user authorization
        if not request.user.is_staff and str(request.user.id) != str(user_id):
            return Response({
                'status': 'error',
                'message': 'Permission denied'
            }, status=status.HTTP_403_FORBIDDEN)

        # Validate required fields
        if not all([user_id, amount]):
            return Response({
                'status': 'error',
                'message': 'Missing required fields: user_id, amount'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate amount
        try:
            amount_decimal = Decimal(str(amount))
            if amount_decimal <= 0:
                return Response({
                    'status': 'error',
                    'message': 'Amount must be greater than zero'
                }, status=status.HTTP_400_BAD_REQUEST)
        except (ValueError, TypeError, InvalidOperation):
            return Response({
                'status': 'error',
                'message': 'Invalid amount format'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Get user
        user = get_object_or_404(User, pk=user_id)

        # Convert amount to cents (integer, no decimals) as required by InnBucks
        amount_cents = int(amount_decimal * 100)

        # Generate unique reference
        import uuid
        reference = f"FJ-{uuid.uuid4().hex[:12].upper()}"

        # Create InnBucks client and generate code
        innbucks_client = InnBucksClient()
        
        # Generate the code with real API (InnBucks expects amount in cents as integer)
        result = innbucks_client.generate_code(
            amount=amount_cents,
            narration=f"FastJet Wallet Top-up - {user.email or user.phone}",
            reference=reference,
            code_type='PAYMENT'
        )

        if result['success']:
            data = result['data']
            
            # Store the payment initiation
            currency_obj = get_object_or_404(Currency, code=currency.upper())
            processed_txn = ProcessedTransaction.objects.create(
                idempotency_key=f"innbucks-{reference}",
                transaction_id=reference,
                user=user,
                amount=amount_decimal,
                currency=currency_obj,
                status='processing',
                bancabc_transaction_id=data.get('code'),  # Store InnBucks code here
                response_data={
                    'innbucks_code': data.get('code'),
                    'auth_number': data.get('authNumber'),
                    'stan': data.get('stan'),
                    'qr_code': data.get('qrCode'),
                    'initiated_at': timezone.now().isoformat()
                }
            )

            logger.info(f"InnBucks code generated for user {user_id}: {data.get('code')}")

            return Response({
                'status': 'success',
                'innbucks_code': data.get('code'),
                'qr_code': data.get('qrCode'),
                'amount': str(amount_decimal),
                'amount_cents': amount_cents,
                'currency': currency,
                'reference': reference,
                'auth_number': data.get('authNumber'),
                'stan': data.get('stan'),
                'description': data.get('description', f'FastJet Wallet Top-up - ${amount_decimal}'),
                'deep_link': f"schinn.wbpycode://innbucks.co.zw?pymInnCode={data.get('code')}",
                'time_to_live': data.get('timeToLive', 'N/A'),
                'message': 'InnBucks payment code generated successfully. Customer should scan QR code or enter code in InnBucks app to complete payment.'
            }, status=status.HTTP_200_OK)
        else:
            error_msg = result.get('error', 'Unknown error')
            logger.error(f"InnBucks code generation failed: {error_msg}")
            
            # Provide specific error messages based on the error
            if 'HTTP 400' in str(error_msg):
                user_message = "InnBucks service is currently unavailable for code generation. This may be due to account configuration. Please try again later or use an alternative payment method."
                status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            elif 'authentication' in str(error_msg).lower():
                user_message = "InnBucks authentication failed. Please contact support."
                status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            else:
                user_message = "There was a problem with the InnBucks service. Please try again later or contact support."
                status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            
            return Response({
                'status': 'error',
                'message': user_message,
                'error_code': 'INNBUCKS_SERVICE_ERROR',
                'technical_details': str(error_msg) if settings.DEBUG else None
            }, status=status_code)

    except Exception as e:
        logger.error(f"InnBucks code generation exception: {str(e)}", exc_info=True)
        return Response({
            'status': 'error',
            'message': 'An unexpected error occurred while processing your request. Please try again later.',
            'error_code': 'INTERNAL_ERROR',
            'technical_details': str(e) if settings.DEBUG else None
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])
def innbucks_check_payment_status(request):
    """
    Check the status of an InnBucks payment and process if paid
    """
    try:
        innbucks_code = request.data.get('innbucks_code')
        transaction_id = request.data.get('transaction_id')

        if not innbucks_code or not transaction_id:
            return Response({
                'status': 'error',
                'message': 'Missing required fields: innbucks_code, transaction_id'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Find the processed transaction
        processed_txn = ProcessedTransaction.objects.filter(
            transaction_id=transaction_id
        ).first()

        if not processed_txn:
            return Response({
                'status': 'error',
                'message': 'Transaction not found'
            }, status=status.HTTP_404_NOT_FOUND)

        # Check user authorization
        if request.user.is_authenticated and not request.user.is_staff and processed_txn.user != request.user:
            return Response({
                'status': 'error',
                'message': 'Permission denied'
            }, status=status.HTTP_403_FORBIDDEN)

        # If already completed, return success WITHOUT processing again
        if processed_txn.status == 'completed':
            wallet_balance = WalletBalance.objects.filter(
                wallet__user=processed_txn.user,
                currency=processed_txn.currency
            ).first()
            
            # Get the points from the original processing
            points_earned = processed_txn.response_data.get('points_earned', 0) if processed_txn.response_data else 0
            
            return Response({
                'status': 'success',
                'payment_status': 'Paid',
                'message': 'Payment already processed',
                'new_balance': str(wallet_balance.balance) if wallet_balance else '0',
                'points_earned': points_earned,
                'transaction_id': transaction_id
            }, status=status.HTTP_200_OK)

        # Query InnBucks for status using real API
        innbucks_client = InnBucksClient()
        result = innbucks_client.query_code(innbucks_code, reference=transaction_id)
        
        if not result['success']:
            return Response({
                'status': 'error',
                'message': result.get('error', 'Failed to query InnBucks status')
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        data = result['data']
        payment_status = data.get('status')  # New, Claimed, Paid, Expired, Timed Out

        # If payment is completed (Claimed or Paid), process the top-up
        # Use select_for_update to prevent race conditions from multiple polling requests
        if payment_status in ['Claimed', 'Paid']:
            with transaction.atomic():
                # Lock the transaction record to prevent concurrent processing
                locked_txn = ProcessedTransaction.objects.select_for_update().get(id=processed_txn.id)
                
                # Double-check it hasn't been processed by another request
                if locked_txn.status == 'completed':
                    wallet_balance = WalletBalance.objects.get(
                        wallet__user=locked_txn.user,
                        currency=locked_txn.currency
                    )
                    points_earned = locked_txn.response_data.get('points_earned', 0) if locked_txn.response_data else 0
                    
                    return Response({
                        'status': 'success',
                        'payment_status': payment_status,
                        'message': 'Payment already processed',
                        'new_balance': str(wallet_balance.balance),
                        'points_earned': points_earned,
                        'transaction_id': transaction_id
                    }, status=status.HTTP_200_OK)
                
                # Get wallet and currency
                wallet, _ = Wallet.objects.get_or_create(user=locked_txn.user)
                wallet_balance, _ = WalletBalance.objects.get_or_create(
                    wallet=wallet,
                    currency=locked_txn.currency
                )

                # Add amount to wallet
                wallet_balance.balance += locked_txn.amount
                wallet_balance.save()

                # Record transaction
                WalletTransaction.objects.create(
                    wallet=wallet,
                    currency=locked_txn.currency,
                    amount=str(locked_txn.amount),
                    transaction_type='deposit',
                    description=f'InnBucks Wallet Top-up - Code: {innbucks_code}, Reference: {transaction_id}'
                )

                # Award loyalty points (10% of amount = 1 point per $10)
                from loyalty.models import LoyaltyAccount
                loyalty_account, _ = LoyaltyAccount.objects.get_or_create(user=locked_txn.user)
                points_earned = int(locked_txn.amount / 10)  # $100 = 10 points
                if points_earned > 0:
                    loyalty_account.add_points(
                        points_earned,
                        f"Points earned for InnBucks wallet top-up of {locked_txn.currency.code} {locked_txn.amount}"
                    )

                # Update processed transaction status
                locked_txn.status = 'completed'
                locked_txn.processed_at = timezone.now()
                if not locked_txn.response_data:
                    locked_txn.response_data = {}
                locked_txn.response_data.update({
                    'payment_status': payment_status,
                    'completed_at': timezone.now().isoformat(),
                    'points_earned': points_earned
                })
                locked_txn.save()

                logger.info(f"InnBucks payment processed: User {locked_txn.user.id}, Amount {locked_txn.amount}, Code {innbucks_code}")

                return Response({
                    'status': 'success',
                    'payment_status': payment_status,
                    'message': f'Wallet topped up successfully with {locked_txn.amount} {locked_txn.currency.code}',
                    'new_balance': str(wallet_balance.balance),
                    'points_earned': points_earned,
                    'transaction_id': transaction_id
                }, status=status.HTTP_200_OK)

        elif payment_status in ['Expired', 'Timed Out']:
            processed_txn.status = 'failed'
            processed_txn.response_data.update({'payment_status': payment_status})
            processed_txn.save()

            return Response({
                'status': 'error',
                'payment_status': payment_status,
                'message': f'Payment {payment_status.lower()}',
                'transaction_id': transaction_id
            }, status=status.HTTP_400_BAD_REQUEST)

        else:
            # Still pending (New)
            return Response({
                'status': 'pending',
                'payment_status': payment_status,
                'message': 'Payment not yet completed. Please complete the payment in your InnBucks app.',
                'time_to_live': data.get('timeToLive'),
                'transaction_id': transaction_id
            }, status=status.HTTP_202_ACCEPTED)

    except Exception as e:
        logger.error(f"InnBucks payment status check error: {str(e)}")
        return Response({
            'status': 'error',
            'message': 'Internal server error checking payment status'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([AllowAny])
def innbucks_simulate_scan(request, innbucks_code, transaction_id):
    """
    Simulates a QR code scan and marks the payment as complete.
    This is only for demo purposes and will display a success page when the QR code is scanned.
    """
    try:
        # Find the processed transaction
        processed_txn = ProcessedTransaction.objects.filter(
            transaction_id=transaction_id,
            bancabc_transaction_id=innbucks_code,  # We stored the innbucks code here
            status='processing'
        ).first()

        if not processed_txn:
            html_content = """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>FastJet InnBucks Payment</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 0; padding: 20px; text-align: center; background-color: #f7f7f7; }
                    .container { max-width: 500px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                    .error { color: #d9534f; }
                    h1 { color: #333; }
                    p { color: #555; line-height: 1.5; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1 class="error">Transaction Not Found</h1>
                    <p>The payment could not be processed because the transaction was not found or has already been completed.</p>
                    <p>Please close this window and try again.</p>
                </div>
            </body>
            </html>
            """
            return HttpResponse(html_content, content_type='text/html')

        # Mark transaction as "Claimed" to simulate payment in progress
        processed_txn.response_data = processed_txn.response_data or {}
        processed_txn.response_data['payment_status'] = 'Claimed'
        processed_txn.response_data['scanned_at'] = timezone.now().isoformat()
        processed_txn.save()
        
        # Return a nice HTML page that redirects back to the app after a few seconds
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>FastJet InnBucks Payment</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; text-align: center; background-color: #f7f7f7; }
                .container { max-width: 500px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                .success { color: #5cb85c; }
                h1 { color: #333; }
                p { color: #555; line-height: 1.5; }
                .spinner { 
                    border: 5px solid #f3f3f3; 
                    border-top: 5px solid #5cb85c; 
                    border-radius: 50%;
                    width: 40px;
                    height: 40px;
                    animation: spin 1s linear infinite;
                    margin: 20px auto;
                }
                @keyframes spin {
                    0% { transform: rotate(0deg); }
                    100% { transform: rotate(360deg); }
                }
                .logo {
                    max-width: 150px;
                    margin-bottom: 20px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1 class="success">Payment in Progress</h1>
                <div class="spinner"></div>
                <p>Your InnBucks payment is being processed.</p>
                <p>Please wait while we complete your transaction...</p>
                <p><strong>Amount:</strong> """ + str(processed_txn.amount) + " " + processed_txn.currency.code + """</p>
                <p><strong>Reference:</strong> """ + transaction_id + """</p>
                <p><small>You can close this window and return to the FastJet app.</small></p>
            </div>
            <script>
                // After 5 seconds, we'll mark this transaction as paid
                setTimeout(function() {
                    fetch('/api/wallets/innbucks/check-status/', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            'innbucks_code': '""" + innbucks_code + """',
                            'transaction_id': '""" + transaction_id + """'
                        })
                    });
                }, 5000);
            </script>
        </body>
        </html>
        """
        return HttpResponse(html_content, content_type='text/html')

    except Exception as e:
        logger.error(f"InnBucks simulate scan error: {str(e)}")
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>FastJet InnBucks Payment</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; text-align: center; background-color: #f7f7f7; }
                .container { max-width: 500px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                .error { color: #d9534f; }
                h1 { color: #333; }
                p { color: #555; line-height: 1.5; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1 class="error">Error Processing Payment</h1>
                <p>There was an error processing your payment. Please try again or contact support.</p>
                <p>Error reference: """ + str(timezone.now().timestamp()) + """</p>
            </div>
        </body>
        </html>
        """
        return HttpResponse(html_content, content_type='text/html')


# ============================================================================
# BANCABC API LOGS DASHBOARD ENDPOINTS
# ============================================================================

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def bancabc_api_logs(request):
    """
    Get BancABC API logs for admin dashboard.
    
    Query Parameters:
    - date_from: Start date (YYYY-MM-DD)
    - date_to: End date (YYYY-MM-DD)
    - endpoint: Filter by endpoint (wallet_validation, payment_notify, wallet_credit, transaction_report)
    - status: Filter by status (success, failed, validation_error, error, duplicate, pending)
    - auto_credited: Filter by auto-credit status (true, false)
    - search: Search by phone number, reference, or error message
    - page: Page number (default: 1)
    - page_size: Records per page (default: 50, max: 100)
    """
    from .models import BancABCAPILog
    from django.db.models import Q, Sum, Count
    from django.core.paginator import Paginator
    
    # Check if user is staff
    if not request.user.is_staff:
        return Response({
            'status': 'error',
            'message': 'Admin access required'
        }, status=status.HTTP_403_FORBIDDEN)
    
    try:
        # Get query parameters
        date_from = request.query_params.get('date_from')
        date_to = request.query_params.get('date_to')
        endpoint_filter = request.query_params.get('endpoint', '')
        status_filter = request.query_params.get('status', '')
        auto_credited_filter = request.query_params.get('auto_credited', '')
        search = request.query_params.get('search', '')
        page = int(request.query_params.get('page', 1))
        page_size = min(int(request.query_params.get('page_size', 50)), 100)
        
        # Build query
        queryset = BancABCAPILog.objects.all().order_by('-created_at')
        
        # Date filters
        if date_from:
            from dateutil import parser
            queryset = queryset.filter(created_at__gte=parser.isoparse(date_from))
        if date_to:
            from dateutil import parser
            end_date = parser.isoparse(date_to)
            # Include the entire end day
            end_date = end_date.replace(hour=23, minute=59, second=59)
            queryset = queryset.filter(created_at__lte=end_date)
        
        # Endpoint filter
        if endpoint_filter:
            queryset = queryset.filter(endpoint=endpoint_filter)
        
        # Status filter
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        # Auto-credited filter
        if auto_credited_filter:
            if auto_credited_filter.lower() == 'true':
                queryset = queryset.filter(auto_credited=True)
            elif auto_credited_filter.lower() == 'false':
                queryset = queryset.filter(auto_credited=False)
        
        # Search filter
        if search:
            queryset = queryset.filter(
                Q(phone_number__icontains=search) |
                Q(transaction_reference__icontains=search) |
                Q(error_message__icontains=search)
            )
        
        # Get total count before pagination
        total_count = queryset.count()
        
        # Paginate
        paginator = Paginator(queryset, page_size)
        page_obj = paginator.get_page(page)
        
        # Build response
        logs = []
        for log in page_obj:
            logs.append({
                'id': log.id,
                'endpoint': log.endpoint,
                'request_method': log.request_method,
                'response_status_code': log.response_status_code,
                'status': log.status,
                'error_message': log.error_message,
                'phone_number': log.phone_number,
                'amount': str(log.amount) if log.amount else None,
                'currency': log.currency,
                'transaction_reference': log.transaction_reference,
                'ip_address': log.ip_address,
                'response_time_ms': log.response_time_ms,
                'auto_credited': log.auto_credited,
                'auto_credit_amount': str(log.auto_credit_amount) if log.auto_credit_amount else None,
                'points_awarded': log.points_awarded,
                'created_at': log.created_at.isoformat() if log.created_at else None,
            })
        
        return Response({
            'status': 'success',
            'logs': logs,
            'pagination': {
                'page': page,
                'page_size': page_size,
                'total_pages': paginator.num_pages,
                'total_records': total_count,
                'has_next': page_obj.has_next(),
                'has_previous': page_obj.has_previous(),
            }
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Error fetching BancABC API logs: {str(e)}", exc_info=True)
        return Response({
            'status': 'error',
            'message': 'Error fetching API logs'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def bancabc_api_stats(request):
    """
    Get BancABC API statistics for admin dashboard.
    
    Query Parameters:
    - date_from: Start date (YYYY-MM-DD)
    - date_to: End date (YYYY-MM-DD)
    """
    from .models import BancABCAPILog
    from django.db.models import Sum, Count, Avg, Q
    
    # Check if user is staff
    if not request.user.is_staff:
        return Response({
            'status': 'error',
            'message': 'Admin access required'
        }, status=status.HTTP_403_FORBIDDEN)
    
    try:
        # Get query parameters
        date_from = request.query_params.get('date_from')
        date_to = request.query_params.get('date_to')
        
        # Build query
        queryset = BancABCAPILog.objects.all()
        
        # Date filters
        if date_from:
            from dateutil import parser
            queryset = queryset.filter(created_at__gte=parser.isoparse(date_from))
        if date_to:
            from dateutil import parser
            end_date = parser.isoparse(date_to)
            end_date = end_date.replace(hour=23, minute=59, second=59)
            queryset = queryset.filter(created_at__lte=end_date)
        
        # Calculate statistics
        total_calls = queryset.count()
        successful_calls = queryset.filter(status='success').count()
        failed_calls = queryset.filter(status__in=['failed', 'error']).count()
        validation_errors = queryset.filter(status='validation_error').count()
        
        # Auto-credit stats
        auto_credited_count = queryset.filter(auto_credited=True).count()
        auto_credit_total = queryset.filter(auto_credited=True).aggregate(
            total=Sum('auto_credit_amount')
        )['total'] or Decimal('0')
        total_points_awarded = queryset.aggregate(total=Sum('points_awarded'))['total'] or 0
        
        # Response time stats
        avg_response_time = queryset.aggregate(avg=Avg('response_time_ms'))['avg'] or 0
        
        # Endpoint breakdown
        endpoint_stats = queryset.values('endpoint').annotate(
            count=Count('id'),
            successful=Count('id', filter=Q(status='success')),
            failed=Count('id', filter=Q(status__in=['failed', 'error'])),
        ).order_by('-count')
        
        # Status breakdown
        status_breakdown = queryset.values('status').annotate(
            count=Count('id')
        ).order_by('-count')
        
        # Recent activity (last 24 hours)
        from datetime import datetime, timedelta
        last_24h = timezone.now() - timedelta(hours=24)
        recent_calls = queryset.filter(created_at__gte=last_24h).count()
        recent_auto_credits = queryset.filter(
            created_at__gte=last_24h, 
            auto_credited=True
        ).count()
        
        return Response({
            'status': 'success',
            'stats': {
                'total_calls': total_calls,
                'successful_calls': successful_calls,
                'failed_calls': failed_calls,
                'validation_errors': validation_errors,
                'success_rate': round((successful_calls / total_calls * 100) if total_calls > 0 else 0, 2),
                'auto_credited_count': auto_credited_count,
                'auto_credit_total': str(auto_credit_total),
                'total_points_awarded': total_points_awarded,
                'avg_response_time_ms': round(avg_response_time, 2),
                'recent_calls_24h': recent_calls,
                'recent_auto_credits_24h': recent_auto_credits,
            },
            'endpoint_breakdown': list(endpoint_stats),
            'status_breakdown': list(status_breakdown),
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Error fetching BancABC API stats: {str(e)}", exc_info=True)
        return Response({
            'status': 'error',
            'message': 'Error fetching API statistics'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def bancabc_api_log_detail(request, log_id):
    """
    Get detailed information for a specific BancABC API log entry.
    
    Parameters:
    - log_id: The ID of the log entry
    """
    from .models import BancABCAPILog
    
    # Check if user is staff
    if not request.user.is_staff:
        return Response({
            'status': 'error',
            'message': 'Admin access required'
        }, status=status.HTTP_403_FORBIDDEN)
    
    try:
        log = get_object_or_404(BancABCAPILog, id=log_id)
        
        return Response({
            'status': 'success',
            'log': {
                'id': log.id,
                'endpoint': log.endpoint,
                'request_method': log.request_method,
                'request_headers': log.request_headers,
                'request_body': log.request_body,
                'response_status_code': log.response_status_code,
                'response_body': log.response_body,
                'status': log.status,
                'error_message': log.error_message,
                'phone_number': log.phone_number,
                'amount': str(log.amount) if log.amount else None,
                'currency': log.currency,
                'transaction_reference': log.transaction_reference,
                'ip_address': log.ip_address,
                'user_agent': log.user_agent,
                'response_time_ms': log.response_time_ms,
                'auto_credited': log.auto_credited,
                'auto_credit_amount': str(log.auto_credit_amount) if log.auto_credit_amount else None,
                'points_awarded': log.points_awarded,
                'created_at': log.created_at.isoformat() if log.created_at else None,
            }
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Error fetching BancABC API log detail: {str(e)}", exc_info=True)
        return Response({
            'status': 'error',
            'message': 'Error fetching log details'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
