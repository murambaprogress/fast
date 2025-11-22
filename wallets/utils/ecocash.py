import json
import uuid
import requests
import logging
from django.conf import settings
from django.utils import timezone
from ..models import EcoCashTransaction, Wallet

logger = logging.getLogger(__name__)

class EcoCashAPI:
    """
    Handles communication with the EcoCash Instant Payment (EIP) API.
    
    Supports:
    - Payment requests (top-ups)
    - Refund requests
    - Transaction queries
    """
    
    # Test/Sandbox endpoints
    TEST_BASE_URL = "https://payonline.econet.co.zw/ecocashGateway-preprod"
    TEST_PAYMENT_URL = f"{TEST_BASE_URL}/payment/v1/transactions/amount"
    TEST_REFUND_URL = f"{TEST_BASE_URL}/payment/v1/transactions/refund"
    TEST_QUERY_URL_TEMPLATE = f"{TEST_BASE_URL}/payment/v1/{{end_user_id}}/transactions/amount/{{client_correlator}}"
    
    # Production endpoints (Updated November 2025)
    PROD_PAYMENT_URL = "https://payonline.econet.co.zw/ecocashGateway/payment/v1/transactions/amount"
    PROD_REFUND_URL = "https://payonline.econet.co.zw/ecocashGateway/payment/v1/transactions/refund"
    PROD_QUERY_URL_TEMPLATE = "https://payonline.econet.co.zw/ecocashGateway/payment/v1/{end_user_id}/transactions/amount/{client_correlator}"
    
    def __init__(self, is_production=False):
        """
        Initialize the EcoCash API client.
        
        Args:
            is_production (bool): Whether to use production or test endpoints
        """
        self.is_production = is_production
        
        # Set API credentials from settings
        self.username = settings.ECOCASH_API_USERNAME
        self.password = settings.ECOCASH_API_PASSWORD
        self.merchant_code = settings.ECOCASH_MERCHANT_CODE
        self.merchant_pin = settings.ECOCASH_MERCHANT_PIN
        self.merchant_number = settings.ECOCASH_MERCHANT_NUMBER  # 070339 as provided
        self.merchant_name = settings.ECOCASH_MERCHANT_NAME
        self.super_merchant_name = settings.ECOCASH_SUPER_MERCHANT_NAME
        self.terminal_id = settings.ECOCASH_TERMINAL_ID
        self.location = settings.ECOCASH_LOCATION
        self.notify_url = settings.ECOCASH_NOTIFY_URL
        
        # Points award rate - can be moved to settings if needed
        self.points_award_rate = getattr(settings, 'ECOCASH_POINTS_AWARD_RATE', 0.02)  # 2% of transaction amount by default
        
    @property
    def payment_url(self):
        return self.PROD_PAYMENT_URL if self.is_production else self.TEST_PAYMENT_URL
    
    @property
    def refund_url(self):
        return self.PROD_REFUND_URL if self.is_production else self.TEST_REFUND_URL
    
    def query_url(self, end_user_id, client_correlator):
        template = self.PROD_QUERY_URL_TEMPLATE if self.is_production else self.TEST_QUERY_URL_TEMPLATE
        return template.format(end_user_id=end_user_id, client_correlator=client_correlator)
    
    def _get_auth(self):
        """Return the auth tuple for HTTP Basic Auth"""
        return (self.username, self.password)
    
    def _process_completed_payment(self, transaction):
        """
        Process a completed payment - update wallet balance and award loyalty points.
        This is called when a payment completes, either from the initial API response
        or from a webhook notification.
        
        Args:
            transaction: The EcoCashTransaction that completed
        """
        try:
            # Import here to avoid circular imports
            from currency.models import Currency
            from ..models import WalletBalance, WalletTransaction
            from loyalty.models import LoyaltyAccount
            
            # Only process merchant payments (top-ups), not refunds
            if transaction.transaction_type != 'MER':
                logger.info(f"Skipping wallet update for non-MER transaction {transaction.id}")
                return
            
            # Get the currency
            try:
                currency = Currency.objects.get(code=transaction.currency_code)
            except Currency.DoesNotExist:
                logger.error(f"Currency {transaction.currency_code} not found for transaction {transaction.id}")
                return
            
            # Update wallet balance
            wallet_balance, created = WalletBalance.objects.get_or_create(
                wallet=transaction.wallet,
                currency=currency,
                defaults={'balance': 0}
            )
            
            wallet_balance.balance += transaction.amount
            wallet_balance.save()
            
            logger.info(f"✅ Wallet balance updated: {wallet_balance.balance} {currency.code} for transaction {transaction.id}")
            
            # Create wallet transaction record
            WalletTransaction.objects.create(
                wallet=transaction.wallet,
                amount=transaction.amount,
                currency=currency,
                transaction_type='deposit',
                description=transaction.remarks or 'EcoCash Top-up',
                reference=transaction.ecocash_reference or transaction.client_correlator
            )
            
            logger.info(f"✅ Wallet transaction record created for transaction {transaction.id}")
            
            # Award loyalty points
            self.award_loyalty_points(transaction)
            
        except Exception as e:
            logger.exception(f"Error processing completed payment for transaction {transaction.id}: {str(e)}")
    
    def _handle_api_response(self, response, transaction=None):
        """
        Handle API response, log errors and update transaction if provided
        
        Args:
            response: The requests.Response object
            transaction: Optional EcoCashTransaction to update
            
        Returns:
            dict: The JSON response data
        """
        try:
            response_data = response.json()
            
            if transaction:
                transaction.raw_response = response_data
                
                # Check for transaction status in response
                if 'transactionOperationStatus' in response_data:
                    status = response_data['transactionOperationStatus']
                    old_status = transaction.status
                    
                    if status == 'COMPLETED':
                        transaction.status = 'completed'
                    elif status == 'PENDING SUBSCRIBER VALIDATION':
                        transaction.status = 'pending_subscriber'
                    elif status == 'FAILED':
                        transaction.status = 'failed'
                    
                    # Save server reference codes if available
                    if 'serverReferenceCode' in response_data:
                        transaction.server_reference_code = response_data['serverReferenceCode']
                    if 'ecocashReference' in response_data:
                        transaction.ecocash_reference = response_data['ecocashReference']
                    
                    # If transaction just completed, process the payment
                    if status == 'COMPLETED' and old_status != 'completed':
                        logger.info(f"Transaction {transaction.id} completed in API response, processing payment...")
                        self._process_completed_payment(transaction)
                
                transaction.save()
            
            if response.status_code >= 400:
                logger.error(f"EcoCash API error: {response.status_code}, {response_data}")
                
            return response_data
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to decode EcoCash API response: {str(e)}, Response: {response.text}")
            if transaction:
                transaction.status = 'failed'
                transaction.save()
            return {"error": "Invalid JSON response", "raw_response": response.text}
    
    def initiate_payment(self, user, amount, currency_code, phone_number, remarks=None):
        """
        Initiate a payment (top-up) request to EcoCash.
        
        Args:
            user: The user initiating the payment
            amount: The payment amount
            currency_code: The currency code (USD or ZWG)
            phone_number: The customer's phone number (MSISDN)
            remarks: Optional payment description
            
        Returns:
            tuple: (success, transaction_object, response_data)
        """
        try:
            # Format phone number - clean and normalize to 263XXXXXXXXX format
            # Remove all non-digit characters first (removes +, spaces, hyphens, etc.)
            phone_number = ''.join(filter(str.isdigit, phone_number))
            
            # Handle different formats
            if phone_number.startswith('263'):
                # Already has 263 prefix, use as is
                pass
            elif phone_number.startswith('0'):
                # Local format with leading 0, replace with 263
                phone_number = f"263{phone_number[1:]}"
            elif len(phone_number) == 9:
                # Just the 9 digits without prefix
                phone_number = f"263{phone_number}"
            else:
                # Invalid format - try to use as is
                logger.warning(f"Unexpected phone number format: {phone_number}")
            
            # Create a unique client_correlator for idempotency
            # Using timestamp-based format with reduced special characters as per EcoCash recommendation
            timestamp = timezone.now().strftime('%Y%m%d%H%M%S%f')  # YYYYMMDDHHMMSSμs
            client_correlator = f"FASTJET{timestamp}"
            reference_code = f"FASTJET{timezone.now().strftime('%Y%m%d%H%M%S')}"
            
            # Get or create user wallet
            wallet, _ = Wallet.objects.get_or_create(user=user)
            
            # Create transaction record (without notify_url first)
            transaction = EcoCashTransaction.objects.create(
                user=user,
                wallet=wallet,
                amount=amount,
                currency_code=currency_code,
                client_correlator=client_correlator,
                reference_code=reference_code,
                end_user_id=phone_number,
                remarks=remarks or "FastJet Loyalty Top-up",
            )
            
            # Generate transaction-specific notify URL
            base_url = getattr(settings, 'BASE_URL', 'https://yourdomain.com')
            transaction_notify_url = f"{base_url}/api/wallets/ecocash/notify/{transaction.id}/"
            
            # Update transaction with the notify URL
            transaction.notify_url = transaction_notify_url
            transaction.save()
            
            # Prepare payment request
            payload = {
                "clientCorrelator": client_correlator,
                "notifyUrl": transaction_notify_url,
                "referenceCode": reference_code,
                "tranType": "MER",
                "endUserId": phone_number,
                "remarks": remarks or "FastJet Loyalty Top-up",
                "transactionOperationStatus": "Charged",
                "paymentAmount": {
                    "charginginformation": {
                        "amount": float(amount),
                        "currency": currency_code,
                        "description": "FastJet Loyalty Top-up"
                    },
                    "chargeMetaData": {
                        "channel": "WEB",
                        "purchaseCategoryCode": "Loyalty Top-up",
                        "onBeHalfOf": "FastJet Loyalty"
                    }
                },
                "merchantCode": self.merchant_code,
                "merchantPin": self.merchant_pin,
                "merchantNumber": self.merchant_number,
                "currencyCode": currency_code,
                "countryCode": "ZW",
                "terminalID": self.terminal_id,
                "location": self.location,
                "superMerchantName": self.super_merchant_name,
                "merchantName": self.merchant_name
            }
            
            # Store raw request for debugging
            transaction.raw_request = payload
            transaction.save()
            
            # Send request to EcoCash
            headers = {'Content-Type': 'application/json'}
            
            # Debug logging
            logger.info(f"EcoCash Payment Request:")
            logger.info(f"URL: {self.payment_url}")
            logger.info(f"Username: {self.username}")
            logger.info(f"Password: {'*' * len(self.password) if self.password else 'None'}")
            logger.info(f"Merchant Code: {self.merchant_code}")
            logger.info(f"Merchant Number: {self.merchant_number}")
            
            response = requests.post(
                self.payment_url,
                auth=self._get_auth(),
                headers=headers,
                json=payload
            )
            
            # Log response status
            logger.info(f"EcoCash Response Status: {response.status_code}")
            if response.status_code != 200:
                logger.error(f"EcoCash API error: {response.status_code}, {response.text}")
            
            # Handle response
            response_data = self._handle_api_response(response, transaction)
            success = response.status_code == 200
            
            return success, transaction, response_data
        
        except Exception as e:
            logger.exception(f"Error initiating EcoCash payment: {str(e)}")
            return False, None, {"error": str(e)}
    
    def refund_payment(self, user, amount, currency_code, phone_number, original_reference, remarks=None):
        """
        Initiate a refund request to EcoCash.
        
        Args:
            user: The user initiating the refund
            amount: The refund amount
            currency_code: The currency code (USD or ZWG)
            phone_number: The customer's phone number (MSISDN)
            original_reference: The original EcoCash transaction reference to refund
            remarks: Optional refund description
            
        Returns:
            tuple: (success, transaction_object, response_data)
        """
        try:
            # Format phone number - clean and normalize to 263XXXXXXXXX format
            # Remove all non-digit characters first (removes +, spaces, hyphens, etc.)
            phone_number = ''.join(filter(str.isdigit, phone_number))
            
            # Handle different formats
            if phone_number.startswith('263'):
                # Already has 263 prefix, use as is
                pass
            elif phone_number.startswith('0'):
                # Local format with leading 0, replace with 263
                phone_number = f"263{phone_number[1:]}"
            elif len(phone_number) == 9:
                # Just the 9 digits without prefix
                phone_number = f"263{phone_number}"
            else:
                # Invalid format - try to use as is
                logger.warning(f"Unexpected phone number format: {phone_number}")
                    
            # Create a unique client_correlator for idempotency
            # Using timestamp-based format with reduced special characters as per EcoCash recommendation
            timestamp = timezone.now().strftime('%Y%m%d%H%M%S%f')  # YYYYMMDDHHMMSSμs
            client_correlator = f"FASTJETREF{timestamp}"
            reference_code = f"FASTJETREF{timezone.now().strftime('%Y%m%d%H%M%S')}"
            
            # Get user wallet
            wallet = Wallet.objects.get(user=user)
            
            # Create transaction record for the refund
            transaction = EcoCashTransaction.objects.create(
                user=user,
                wallet=wallet,
                amount=amount,
                currency_code=currency_code,
                client_correlator=client_correlator,
                reference_code=reference_code,
                end_user_id=phone_number,
                transaction_type="REF",
                original_ecocash_reference=original_reference,
                remarks=remarks or "FastJet Loyalty Refund",
            )
            
            # Prepare refund request
            payload = {
                "clientCorrelator": client_correlator,
                "referenceCode": reference_code,
                "endUserId": phone_number,
                "originalEcocashReference": original_reference,
                "tranType": "REF",
                "remark": remarks or "FastJet Loyalty Refund",
                "paymentAmount": {
                    "charginginformation": {
                        "amount": float(amount),
                        "currency": currency_code,
                        "description": "FastJet Loyalty Refund"
                    },
                    "chargeMetaData": {
                        "channel": "WEB",
                        "purchaseCategoryCode": "Loyalty Refund",
                        "onBeHalfOf": "FastJet Loyalty"
                    }
                },
                "merchantCode": self.merchant_code,
                "merchantPin": self.merchant_pin,
                "merchantNumber": self.merchant_number,
                "currencyCode": currency_code,
                "countryCode": "ZW",
                "terminalID": self.terminal_id,
                "location": self.location,
                "superMerchantName": self.super_merchant_name,
                "merchantName": self.merchant_name
            }
            
            # Store raw request for debugging
            transaction.raw_request = payload
            transaction.save()
            
            # Send request to EcoCash
            headers = {'Content-Type': 'application/json'}
            response = requests.post(
                self.refund_url,
                auth=self._get_auth(),
                headers=headers,
                json=payload
            )
            
            # Handle response
            response_data = self._handle_api_response(response, transaction)
            success = response.status_code == 200
            
            return success, transaction, response_data
        
        except Exception as e:
            logger.exception(f"Error initiating EcoCash refund: {str(e)}")
            return False, None, {"error": str(e)}
    
    def query_transaction(self, end_user_id, client_correlator):
        """
        Query a transaction status from EcoCash.
        
        Args:
            end_user_id: The customer's phone number (MSISDN)
            client_correlator: The original client correlator used in the transaction
            
        Returns:
            tuple: (success, response_data)
        """
        try:
            # Format phone number if needed
            if not end_user_id.startswith('263'):
                # If it starts with 0, replace with 263
                if end_user_id.startswith('0'):
                    end_user_id = f"263{end_user_id[1:]}"
                # If it doesn't have any prefix, add 263
                else:
                    end_user_id = f"263{end_user_id}"
            
            # Get the query URL
            url = self.query_url(end_user_id, client_correlator)
            
            # Send request to EcoCash
            response = requests.get(
                url,
                auth=self._get_auth(),
                headers={'Content-Type': 'application/json'}
            )
            
            # Find the transaction
            try:
                transaction = EcoCashTransaction.objects.get(client_correlator=client_correlator)
                response_data = self._handle_api_response(response, transaction)
            except EcoCashTransaction.DoesNotExist:
                response_data = self._handle_api_response(response)
            
            success = response.status_code == 200
            return success, response_data
            
        except Exception as e:
            logger.exception(f"Error querying EcoCash transaction: {str(e)}")
            return False, {"error": str(e)}
    
    def process_webhook(self, webhook_data):
        """
        Process a webhook notification from EcoCash.
        
        Args:
            webhook_data: The webhook data from EcoCash
            
        Returns:
            tuple: (success, transaction_object, message)
        """
        try:
            # Extract client_correlator from the webhook data
            client_correlator = webhook_data.get('clientCorrelator')
            
            if not client_correlator:
                return False, None, "Missing clientCorrelator in webhook data"
            
            # Find the transaction
            try:
                transaction = EcoCashTransaction.objects.get(client_correlator=client_correlator)
            except EcoCashTransaction.DoesNotExist:
                return False, None, f"Transaction with client_correlator {client_correlator} not found"
            
            # Update transaction with webhook data
            transaction.raw_response = webhook_data
            
            # Extract status information
            status = webhook_data.get('transactionOperationStatus')
            
            if status == 'COMPLETED':
                transaction.status = 'completed'
                
                # Update wallet balance for completed transactions
                if transaction.transaction_type == 'MER':  # For merchant payment (top-up)
                    # Get the currency
                    from currency.models import Currency
                    try:
                        currency = Currency.objects.get(code=transaction.currency_code)
                        
                        # Update wallet balance
                        from ..models import WalletBalance, WalletTransaction
                        
                        balance, created = WalletBalance.objects.get_or_create(
                            wallet=transaction.wallet,
                            currency=currency,
                            defaults={'balance': 0}
                        )
                        
                        balance.balance += transaction.amount
                        balance.save()
                        
                        # Create wallet transaction record
                        WalletTransaction.objects.create(
                            wallet=transaction.wallet,
                            amount=transaction.amount,
                            currency=currency,
                            transaction_type='deposit',
                            description=transaction.remarks or 'EcoCash Top-up',
                            reference=transaction.ecocash_reference or transaction.client_correlator
                        )
                        
                        # Award loyalty points for the top-up
                        self.award_loyalty_points(transaction)
                        
                    except Currency.DoesNotExist:
                        logger.error(f"Currency not found for code: {transaction.currency_code}")
            
            elif status == 'FAILED':
                transaction.status = 'failed'
            
            # Save server reference codes if available
            if 'serverReferenceCode' in webhook_data:
                transaction.server_reference_code = webhook_data['serverReferenceCode']
            if 'ecocashReference' in webhook_data:
                transaction.ecocash_reference = webhook_data['ecocashReference']
                
            transaction.save()
            
            return True, transaction, f"Webhook processed successfully. Transaction status: {transaction.status}"
            
        except Exception as e:
            logger.exception(f"Error processing EcoCash webhook: {str(e)}")
            return False, None, f"Error processing webhook: {str(e)}"
            
    def award_loyalty_points(self, transaction):
        """
        Award loyalty points for successful EcoCash transactions.
        
        Points are awarded based on a percentage of the transaction amount.
        
        Args:
            transaction: The EcoCashTransaction object
            
        Returns:
            int: The number of points awarded
        """
        try:
            from loyalty.models import LoyaltyAccount
            
            # Calculate points to award (2% of transaction amount by default)
            # For example, if amount is $100, points awarded would be 2
            amount = float(transaction.amount)
            points_to_award = int(amount * self.points_award_rate)
            
            # Ensure at least 1 point for any successful transaction
            if amount > 0 and points_to_award < 1:
                points_to_award = 1
                
            if points_to_award <= 0:
                logger.info(f"No points to award for transaction {transaction.id} with amount {amount}")
                return 0
                
            # Get or create loyalty account
            try:
                loyalty_account, created = LoyaltyAccount.objects.get_or_create(
                    user=transaction.user,
                    defaults={'points': 0, 'lifetime_points': 0}
                )
                
                # Add points with description
                description = f"Points earned for EcoCash wallet top-up of {transaction.currency_code} {transaction.amount}"
                loyalty_account.add_points(points_to_award, description)
                
                logger.info(f"Awarded {points_to_award} loyalty points to user {transaction.user.id} for EcoCash transaction {transaction.id}")
                logger.info(f"New loyalty points balance: {loyalty_account.points} (lifetime: {loyalty_account.lifetime_points})")
                return points_to_award
                
            except Exception as e:
                logger.error(f"Error awarding loyalty points: {str(e)}")
                return 0
                
        except ImportError:
            logger.error("Loyalty module not available, cannot award points")
            return 0
        except Exception as e:
            logger.exception(f"Error in award_loyalty_points: {str(e)}")
            return 0