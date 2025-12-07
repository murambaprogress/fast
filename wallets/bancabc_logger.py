"""
BancABC API Logging Utility
===========================
Logs all incoming BancABC API requests for monitoring and debugging.
"""

import time
import logging
from decimal import Decimal
from django.utils import timezone

logger = logging.getLogger(__name__)


def log_bancabc_api_call(
    request,
    endpoint,
    response_status_code,
    response_body,
    status='success',
    error_message=None,
    auto_credited=False,
    auto_credit_amount=None,
    points_awarded=0,
    credit_transaction_id=None,
    start_time=None
):
    """
    Log a BancABC API call to the database for monitoring.
    
    Args:
        request: Django request object
        endpoint: API endpoint name (wallet_validate, payment_notify, wallet_credit, transaction_report)
        response_status_code: HTTP status code returned
        response_body: Response data (dict)
        status: Request status (success, failed, error, validation_error, auth_error)
        error_message: Error message if any
        auto_credited: Whether auto-credit was triggered
        auto_credit_amount: Amount that was auto-credited (Decimal)
        points_awarded: Loyalty points awarded (int)
        credit_transaction_id: Transaction ID if credit was applied
        start_time: Start time for calculating response time
    """
    from wallets.models import BancABCAPILog
    
    try:
        # Calculate response time
        response_time_ms = 0
        if start_time:
            response_time_ms = int((time.time() - start_time) * 1000)
        
        # Extract request data
        request_body = None
        try:
            request_body = dict(request.data) if hasattr(request, 'data') else None
        except:
            pass
        
        # Extract headers (only relevant ones)
        request_headers = {
            'Content-Type': request.content_type,
            'X-BancABC-API-Key': '***' if request.META.get('HTTP_X_BANCABC_API_KEY') else None,
        }
        
        # Extract customer info from request
        phone_number = None
        customer_id = None
        transaction_reference = None
        amount = None
        currency = None
        
        if request_body:
            phone_number = request_body.get('phone_number', '').strip() if isinstance(request_body.get('phone_number'), str) else request_body.get('phone_number')
            customer_id = request_body.get('customer_id')
            transaction_reference = (
                request_body.get('transaction_id') or 
                request_body.get('bancabc_transaction_id') or 
                request_body.get('bancabc_reference')
            )
            try:
                amount_raw = request_body.get('amount')
                if amount_raw:
                    amount = Decimal(str(amount_raw))
            except:
                pass
            currency = request_body.get('currency', 'USD')
        
        # Get IP address
        ip_address = get_client_ip(request)
        
        # Get user agent
        user_agent = request.META.get('HTTP_USER_AGENT', '')[:500]
        
        # Create log entry
        log_entry = BancABCAPILog.objects.create(
            endpoint=endpoint,
            request_method=request.method,
            request_url=request.build_absolute_uri(),
            request_headers=request_headers,
            request_body=request_body,
            response_status_code=response_status_code,
            response_body=response_body,
            response_time_ms=response_time_ms,
            status=status,
            error_message=error_message,
            phone_number=phone_number,
            customer_id=customer_id,
            transaction_reference=transaction_reference,
            amount=amount,
            currency=currency,
            auto_credited=auto_credited,
            auto_credit_amount=auto_credit_amount,
            points_awarded=points_awarded or 0,
            credit_transaction_id=credit_transaction_id,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        
        logger.info(f"BancABC API Log created: {endpoint} - {status} - ID: {log_entry.id}")
        return log_entry
        
    except Exception as e:
        logger.error(f"Failed to log BancABC API call: {str(e)}", exc_info=True)
        return None


def get_client_ip(request):
    """Get client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


class BancABCAPILoggerMixin:
    """
    Mixin class for logging BancABC API calls.
    Use this in your API views for automatic logging.
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._api_start_time = None
        self._api_endpoint = 'other'
    
    def start_logging(self, endpoint):
        """Call at the start of API processing"""
        self._api_start_time = time.time()
        self._api_endpoint = endpoint
    
    def log_response(self, request, response_status_code, response_body, 
                     status='success', error_message=None, 
                     auto_credited=False, credit_transaction_id=None):
        """Call when returning response"""
        return log_bancabc_api_call(
            request=request,
            endpoint=self._api_endpoint,
            response_status_code=response_status_code,
            response_body=response_body,
            status=status,
            error_message=error_message,
            auto_credited=auto_credited,
            credit_transaction_id=credit_transaction_id,
            start_time=self._api_start_time
        )
