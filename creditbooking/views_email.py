from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from utils.email_service import EmailService

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def send_booking_emails(request):
    """
    Send email notifications for credit booking to bank and admin
    """
    try:
        booking_data = {
            'reference': request.data.get('reference'),
            'customer_name': request.data.get('customer_name'),
            'national_id': request.data.get('national_id'),
            'bank': request.data.get('bank'),
            'bank_account': request.data.get('bank_account'),
            'route': request.data.get('route'),
            'travel_date': request.data.get('travel_date'),
            'return_date': request.data.get('return_date'),
            'schedule_id': request.data.get('schedule_id'),
            'currency': request.data.get('currency', 'USD'),
            'base_amount': request.data.get('base_amount'),
            'total_amount': request.data.get('total_amount'),
            'repayment_months': request.data.get('repayment_months'),
            'interest_rate': request.data.get('interest_rate'),
            'repayment_date': request.data.get('repayment_date'),
        }

        bank_email = request.data.get('bank_email')
        admin_email = request.data.get('admin_email', settings.ADMIN_EMAIL)

        if not bank_email:
            return Response(
                {'error': 'Bank email is required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        success, message = EmailService.send_credit_booking_notification(
            booking_data, 
            bank_email, 
            admin_email
        )

        if success:
            return Response({
                'message': 'Notification emails sent successfully'
            })
        else:
            return Response(
                {'error': f'Failed to send emails: {message}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    except Exception as e:
        return Response(
            {'error': str(e)}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
