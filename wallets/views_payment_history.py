import logging
from django.utils import timezone
from datetime import timedelta
from django.db.models import Q
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from .models import WalletTransaction
from loyalty.models import LoyaltyTransaction

logger = logging.getLogger(__name__)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def innbucks_transaction_history(request):
    """
    Get the InnBucks transaction history for the authenticated user
    
    Optional query parameters:
    - limit: The maximum number of transactions to return (default: 10)
    - offset: The offset for pagination (default: 0)
    - status: Filter by transaction status
    - search: Search term for reference codes, amounts, etc.
    - date_filter: Filter by date range (today, week, month, 3months)
    
    Returns:
        A JSON response with the transaction history and loyalty points awarded
    """
    try:
        logger.info(f"InnBucks history request for user: {request.user.id}")
        
        # Extract query parameters
        limit = int(request.GET.get('limit', 10))
        offset = int(request.GET.get('offset', 0))
        status_filter = request.GET.get('status')
        search_term = request.GET.get('search', '').strip()
        date_filter = request.GET.get('date_filter')
        
        # Get the user from the authenticated request
        user = request.user
        
        # Build query filters for InnBucks transactions
        filters = {
            'wallet__user': user,
            'transaction_type': 'deposit',
            'description__icontains': 'InnBucks'
        }
        
        # Note: WalletTransaction doesn't have a status field, all records are completed
        # If status_filter is provided, it's ignored for this model
            
        # Query transactions
        query = WalletTransaction.objects.filter(**filters)
        
        # Apply search filter
        if search_term:
            query = query.filter(
                Q(reference_code__icontains=search_term) |
                Q(amount__icontains=search_term) |
                Q(description__icontains=search_term)
            )
        
        # Apply date filter
        if date_filter and date_filter != 'all':
            now = timezone.now()
            
            if date_filter == 'today':
                start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
                query = query.filter(created_at__gte=start_date)
            elif date_filter == 'week':
                start_date = now - timedelta(days=7)
                query = query.filter(created_at__gte=start_date)
            elif date_filter == 'month':
                start_date = now - timedelta(days=30)
                query = query.filter(created_at__gte=start_date)
            elif date_filter == '3months':
                start_date = now - timedelta(days=90)
                query = query.filter(created_at__gte=start_date)
        
        query = query.order_by('-created_at')
        total_count = query.count()
        transactions = query[offset:offset + limit]
        
        logger.info(f"Found {total_count} InnBucks transactions for user {request.user.id}")
        
        # Process each transaction to include loyalty points information
        transaction_data = []
        for transaction in transactions:
            # Look for loyalty transactions
            loyalty_points = 0
            loyalty_transaction = None
            
            # Find any loyalty transaction created around the same time for InnBucks top-ups
            recent_loyalty_txs = LoyaltyTransaction.objects.filter(
                user=user,
                transaction_type='earn',
                description__icontains='InnBucks',
                created_at__gte=transaction.created_at - timedelta(minutes=1),
                created_at__lte=transaction.created_at + timedelta(minutes=5)
            ).order_by('-created_at')
            
            if recent_loyalty_txs.exists():
                loyalty_transaction = recent_loyalty_txs.first()
                loyalty_points = loyalty_transaction.points
            
            # Add transaction data with loyalty points
            transaction_data.append({
                'id': transaction.id,
                'reference_code': getattr(transaction, 'reference', f'INN-{transaction.id}'),
                'amount': str(transaction.amount),
                'currency_code': transaction.currency.code if transaction.currency else 'USD',
                'status': 'completed',  # WalletTransaction exists means it's completed
                'innbucks_code': f'INN{transaction.id:06d}',
                'innbucks_reference': getattr(transaction, 'reference', f'INN-REF-{transaction.id}'),
                'phone_number': getattr(user, 'phone', ''),
                'remarks': transaction.description or 'InnBucks Top-up',
                'created_at': transaction.created_at.isoformat(),
                'updated_at': transaction.created_at.isoformat(),  # Use created_at since there's no updated_at
                'loyalty_points_awarded': loyalty_points,
                'loyalty_transaction_id': loyalty_transaction.id if loyalty_transaction else None
            })
        
        # Return paginated response
        return Response({
            'success': True,
            'count': total_count,
            'next': None if offset + limit >= total_count else f"?offset={offset + limit}&limit={limit}",
            'previous': None if offset == 0 else f"?offset={max(0, offset - limit)}&limit={limit}",
            'transactions': transaction_data
        }, status=status.HTTP_200_OK)
        
    except ValueError as e:
        logger.error(f"Invalid parameter in InnBucks history request: {str(e)}")
        return Response({
            'success': False,
            'message': f"Invalid request parameters: {str(e)}"
        }, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        logger.exception(f"Error retrieving InnBucks transaction history: {str(e)}")
        return Response({
            'success': False,
            'message': f"Error retrieving transaction history: {str(e)}"
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def omari_transaction_history(request):
    """
    Get the O Mari transaction history for the authenticated user
    
    Optional query parameters:
    - limit: The maximum number of transactions to return (default: 10)
    - offset: The offset for pagination (default: 0)
    - status: Filter by transaction status
    - search: Search term for reference codes, amounts, etc.
    - date_filter: Filter by date range (today, week, month, 3months)
    
    Returns:
        A JSON response with the transaction history and loyalty points awarded
    """
    try:
        logger.info(f"O Mari history request for user: {request.user.id}")
        
        # Extract query parameters
        limit = int(request.GET.get('limit', 10))
        offset = int(request.GET.get('offset', 0))
        status_filter = request.GET.get('status')
        search_term = request.GET.get('search', '').strip()
        date_filter = request.GET.get('date_filter')
        
        # Get the user from the authenticated request
        user = request.user
        
        # Build query filters for O Mari transactions
        filters = {
            'wallet__user': user,
            'transaction_type': 'deposit',
            'description__icontains': 'O Mari'
        }
        
        if status_filter and status_filter != 'all':
            filters['status'] = status_filter
            
        # Query transactions
        query = WalletTransaction.objects.filter(**filters)
        
        # Apply search filter
        if search_term:
            query = query.filter(
                Q(reference_code__icontains=search_term) |
                Q(amount__icontains=search_term) |
                Q(description__icontains=search_term)
            )
        
        # Apply date filter
        if date_filter and date_filter != 'all':
            now = timezone.now()
            
            if date_filter == 'today':
                start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
                query = query.filter(created_at__gte=start_date)
            elif date_filter == 'week':
                start_date = now - timedelta(days=7)
                query = query.filter(created_at__gte=start_date)
            elif date_filter == 'month':
                start_date = now - timedelta(days=30)
                query = query.filter(created_at__gte=start_date)
            elif date_filter == '3months':
                start_date = now - timedelta(days=90)
                query = query.filter(created_at__gte=start_date)
        
        query = query.order_by('-created_at')
        total_count = query.count()
        transactions = query[offset:offset + limit]
        
        logger.info(f"Found {total_count} O Mari transactions for user {request.user.id}")
        
        # Process each transaction to include loyalty points information
        transaction_data = []
        for transaction in transactions:
            # Look for loyalty transactions
            loyalty_points = 0
            loyalty_transaction = None
            
            if hasattr(transaction, 'status') and transaction.status == 'completed':
                # Find any loyalty transaction created around the same time
                recent_loyalty_txs = LoyaltyTransaction.objects.filter(
                    user=user,
                    transaction_type='earn',
                    description__contains='O Mari',
                    created_at__gte=transaction.created_at,
                    created_at__lte=transaction.updated_at + timezone.timedelta(minutes=5)
                ).order_by('-created_at')
                
                if recent_loyalty_txs.exists():
                    loyalty_transaction = recent_loyalty_txs.first()
                    loyalty_points = loyalty_transaction.points
            
            # Add transaction data with loyalty points
            transaction_data.append({
                'id': transaction.id,
                'reference_code': getattr(transaction, 'reference_code', f'OM-{transaction.id}'),
                'amount': str(transaction.amount),
                'currency_code': transaction.currency.code if transaction.currency else 'USD',
                'status': getattr(transaction, 'status', 'completed'),
                'omari_reference': getattr(transaction, 'reference_code', f'OM-REF-{transaction.id}'),
                'phone_number': getattr(user, 'phone_number', ''),
                'transaction_fee': '0.00',  # Default fee
                'remarks': transaction.description or 'O Mari Top-up',
                'created_at': transaction.created_at.isoformat(),
                'updated_at': transaction.updated_at.isoformat(),
                'loyalty_points_awarded': loyalty_points,
                'loyalty_transaction_id': loyalty_transaction.id if loyalty_transaction else None
            })
        
        # Return paginated response
        return Response({
            'success': True,
            'count': total_count,
            'next': None if offset + limit >= total_count else f"?offset={offset + limit}&limit={limit}",
            'previous': None if offset == 0 else f"?offset={max(0, offset - limit)}&limit={limit}",
            'transactions': transaction_data
        }, status=status.HTTP_200_OK)
        
    except ValueError as e:
        logger.error(f"Invalid parameter in O Mari history request: {str(e)}")
        return Response({
            'success': False,
            'message': f"Invalid request parameters: {str(e)}"
        }, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        logger.exception(f"Error retrieving O Mari transaction history: {str(e)}")
        return Response({
            'success': False,
            'message': f"Error retrieving transaction history: {str(e)}"
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)