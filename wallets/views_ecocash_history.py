import logging
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from .models import EcoCashTransaction
from loyalty.models import LoyaltyTransaction

logger = logging.getLogger(__name__)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def ecocash_transaction_history(request):
    """
    Get the EcoCash transaction history for the authenticated user with loyalty points information
    
    Optional query parameters:
    - limit: The maximum number of transactions to return (default: 10)
    - offset: The offset for pagination (default: 0)
    - status: Filter by transaction status (e.g., "completed", "pending", "failed")
    
    Returns:
        A JSON response with the transaction history and loyalty points awarded
    """
    try:
        # Extract query parameters
        limit = int(request.GET.get('limit', 10))
        offset = int(request.GET.get('offset', 0))
        status_filter = request.GET.get('status')
        
        # Get the user from the authenticated request
        user = request.user
        
        # Build query filters
        filters = {'user': user}
        if status_filter:
            filters['status'] = status_filter
            
        # Query transactions
        query = EcoCashTransaction.objects.filter(**filters).order_by('-created_at')
        total_count = query.count()
        transactions = query[offset:offset + limit]
        
        # Process each transaction to include loyalty points information
        transaction_data = []
        for transaction in transactions:
            # Look for loyalty transactions connected to this EcoCash transaction
            loyalty_points = 0
            loyalty_transaction = None
            
            if transaction.status == 'completed':
                # Find any loyalty transaction created around the same time
                recent_loyalty_txs = LoyaltyTransaction.objects.filter(
                    user=user,
                    transaction_type='earn',
                    description__contains='EcoCash wallet top-up',
                    created_at__gte=transaction.created_at,
                    created_at__lte=transaction.updated_at + timezone.timedelta(minutes=5)
                ).order_by('-created_at')
                
                if recent_loyalty_txs.exists():
                    loyalty_transaction = recent_loyalty_txs.first()
                    loyalty_points = loyalty_transaction.points
            
            # Add transaction data with loyalty points
            transaction_data.append({
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
        
    except Exception as e:
        logger.exception(f"Error retrieving EcoCash transaction history: {str(e)}")
        return Response({
            'success': False,
            'message': f"Error retrieving transaction history: {str(e)}"
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)