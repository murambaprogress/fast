from django.core.mail import EmailMessage
from django.conf import settings
# Utility: get bank email by name (dummy for now)
def get_bank_email(bank_name):
    bank_emails = {
        'BancABC': 'bancabc@example.com',
        'FBC': 'fbc@example.com',
        'CABS': 'cabs@example.com',
    }
    return bank_emails.get(bank_name, None)

# API endpoint: send document to email
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.parsers import MultiPartParser, FormParser
from django.http import JsonResponse

class SendDocumentEmailView(APIView):
    permission_classes = [AllowAny]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request, *args, **kwargs):
        # Get file, label, bank (optional)
        file = request.FILES.get('file')
        label = request.data.get('label', 'Document')
        bank = request.data.get('bank')
        user_email = request.data.get('user_email')

        # Determine recipient
        recipients = ['info@hydrogeospatial.com']
        if bank:
            bank_email = get_bank_email(bank)
            if bank_email:
                recipients.append(bank_email)

        subject = f"Credit Booking Document: {label}"
        body = f"A user submitted a document for credit booking.\nLabel: {label}.\nBank: {bank or 'N/A'}.\nUser Email: {user_email or 'N/A'}"

        if not file:
            return JsonResponse({'detail': 'No file provided'}, status=400)

        try:
            email = EmailMessage(
                subject=subject,
                body=body,
                from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', None),
                to=recipients,
            )
            email.attach(file.name, file.read(), file.content_type)
            email.send()
            return JsonResponse({'detail': 'Email sent successfully'})
        except Exception as e:
            return JsonResponse({'detail': f'Failed to send email: {str(e)}'}, status=500)
from django.shortcuts import render
from rest_framework import viewsets, status, permissions
from rest_framework.response import Response
from rest_framework.decorators import action
from .models import DocumentType, CreditBooking, CreditDocument
from .serializers import (
    DocumentTypeSerializer, 
    CreditBookingSerializer,
    CreditDocumentSerializer,
    CreateCreditBookingSerializer
)
from django.db import transaction
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from booking.models import Booking
import logging
from django.db import IntegrityError
from decimal import Decimal
from datetime import timedelta
from django.utils import timezone

logger = logging.getLogger(__name__)

class DocumentTypeViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = DocumentType.objects.all()
    serializer_class = DocumentTypeSerializer
    permission_classes = [permissions.IsAuthenticated]

class CreditBookingViewSet(viewsets.ModelViewSet):
    # ...existing code...
    queryset = CreditBooking.objects.all()
    permission_classes = [permissions.IsAuthenticated]
    
    def get_serializer_class(self):
        if self.action == 'create':
            return CreateCreditBookingSerializer
        return CreditBookingSerializer
    
    def get_queryset(self):
        user = self.request.user
        if user.is_staff:
            return CreditBooking.objects.all()
        return CreditBooking.objects.filter(user=user)

    def create(self, request, *args, **kwargs):
        # Raw diagnostics
        try:
            raw_body = request.body.decode('utf-8') if request.body else ''
        except Exception:
            raw_body = '<unreadable>'
        logger.warning("[CreditBooking][CREATE] content_type=%s raw_body=%s", request.content_type, raw_body)
        logger.warning("[CreditBooking][CREATE] parsed_keys=%s", list(request.data.keys()))

        # Fallback: if booking_id not in request.data but raw JSON contains it, try parse
        if 'booking_id' not in request.data and raw_body:
            import json as _json
            try:
                parsed = _json.loads(raw_body)
                if isinstance(parsed, dict) and 'booking_id' in parsed:
                    # Mutate request.data (QueryDict) safely via copy
                    mutable = request.data.copy()
                    mutable['booking_id'] = parsed['booking_id']
                    request._full_data = mutable  # Force DRF to use updated data
                    logger.warning("[CreditBooking][CREATE] Injected booking_id from raw body: %s", parsed['booking_id'])
            except Exception as _e:
                logger.error("[CreditBooking][CREATE] Failed raw JSON parse for fallback: %s", _e)

        serializer = self.get_serializer(data=request.data, context={'request': request})
        if not serializer.is_valid():
            # Return richer diagnostics
            return Response({
                'errors': serializer.errors,
                'received_keys': list(request.data.keys()),
                'note': 'Expecting booking_id, amount, reason',
            }, status=status.HTTP_400_BAD_REQUEST)
        booking_id = serializer.validated_data.get('booking_id')
        # Ensure the linked booking departs at least 7 days from now
        try:
            booking_obj = Booking.objects.get(id=booking_id)
        except Booking.DoesNotExist:
            return Response({'detail': 'Linked booking not found'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            departure = booking_obj.outbound_schedule.departure_time
        except Exception:
            departure = None

        if not departure:
            return Response({'detail': 'Linked booking has no outbound schedule/departure time'}, status=status.HTTP_400_BAD_REQUEST)

        # Require at least 7 days lead time for credit applications
        if departure - timezone.now() < timedelta(days=7):
            return Response({'detail': 'Credit booking is only available for bookings made at least 7 days in advance'}, status=status.HTTP_400_BAD_REQUEST)
        # Duplicate guard
        existing = CreditBooking.objects.filter(booking__id=booking_id, user=request.user).first()
        if existing:
            logger.info("[CreditBooking][CREATE] Duplicate detected for booking_id=%s returning existing id=%s", booking_id, existing.id)
            existing_ser = CreditBookingSerializer(existing, context={'request': request})
            return Response({
                'detail': 'Credit booking already exists for this booking',
                'id': existing.id,
                'credit_booking': existing_ser.data
            }, status=status.HTTP_200_OK)
        try:
            credit_booking = serializer.save()  # serializer.create handles linkage
        except IntegrityError as ie:
            logger.exception("[CreditBooking][CREATE] IntegrityError booking_id=%s", booking_id)
            return Response({'detail': 'Integrity error creating credit booking', 'error': str(ie)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as exc:
            logger.exception("[CreditBooking][CREATE] Unexpected error booking_id=%s", booking_id)
            return Response({'detail': 'Unexpected error creating credit booking', 'error': str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        # Prepare serialized response
        output = CreditBookingSerializer(credit_booking, context={'request': request})
        logger.info("[CreditBooking][CREATE] Success id=%s", credit_booking.id)
        # Generate PDF attachment and email to admin
        try:
            import io
            from reportlab.pdfgen import canvas

            buffer = io.BytesIO()
            pdf = canvas.Canvas(buffer)
            text = pdf.beginText(40, 800)
            text.setFont('Helvetica', 12)
            text.textLine(f'Credit Booking Application #{credit_booking.id}')
            text.textLine(f'User: {request.user.get_full_name() or request.user.username}')
            text.textLine(f'Amount: {credit_booking.amount}')
            text.textLine(f'Reason: {credit_booking.reason}')
            text.textLine(f'Submitted At: {credit_booking.created_at.strftime("%Y-%m-%d %H:%M:%S")}')
            pdf.drawText(text)
            pdf.showPage()
            pdf.save()
            buffer.seek(0)

            subject = f'Credit Booking Application Submitted: #{credit_booking.id}'
            email = EmailMessage(
                subject=subject,
                body='Please find attached the credit booking application PDF.',
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=['farayi.chikuni@fastjet.com'],
            )
            email.attach(f'credit_booking_{credit_booking.id}.pdf', buffer.read(), 'application/pdf')
            email.send(fail_silently=True)
        except Exception as e:
            logger.error("Error sending booking PDF for id=%s: %s", credit_booking.id, e)
        # Return API response
        headers = self.get_success_headers(output.data)
        return Response(output.data, status=status.HTTP_201_CREATED, headers=headers)
    
    @action(detail=True, methods=['post'], parser_classes=[MultiPartParser, FormParser])
    def upload_document(self, request, pk=None):
        credit_booking = self.get_object()
        document_type_id = request.data.get('document_type')
        
        if not document_type_id:
            return Response({"detail": "Document type is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            document_type = DocumentType.objects.get(id=document_type_id)
        except DocumentType.DoesNotExist:
            return Response({"detail": "Document type not found"}, status=status.HTTP_404_NOT_FOUND)
        
        if 'file' not in request.data:
            return Response({"detail": "File is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        document = CreditDocument.objects.create(
            credit_booking=credit_booking,
            document_type=document_type,
            file=request.data['file']
        )
        
        serializer = CreditDocumentSerializer(document)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    
    @action(detail=True, methods=['get'])
    def documents(self, request, pk=None):
        credit_booking = self.get_object()
        documents = CreditDocument.objects.filter(credit_booking=credit_booking)
        serializer = CreditDocumentSerializer(documents, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def approve(self, request, pk=None):
        if not request.user.is_staff:
            return Response({"detail": "Only staff can approve credit bookings"}, 
                          status=status.HTTP_403_FORBIDDEN)
        
        credit_booking = self.get_object()
        admin_notes = request.data.get('admin_notes', '')

        # Optionally convert the related booking into an installment (laybuy) plan
        convert_to_installments = request.data.get('convert_to_installments', False)
        try:
            installment_count = int(request.data.get('installment_count', 3) or 3)
        except Exception:
            installment_count = 3

        with transaction.atomic():
            credit_booking.status = 'approved'
            credit_booking.admin_notes = admin_notes
            credit_booking.save()

            # Update or convert the related booking
            booking = credit_booking.booking

            if convert_to_installments:
                try:
                    # Import here to avoid circular import at module load
                    from booking.models import InstallmentPayment

                    # Ensure numeric types are Decimal for arithmetic
                    base_total = booking.total_price or booking.calculate_total_price()
                    base_total_dec = Decimal(str(base_total))
                    installment_total = booking.installment_total or (base_total_dec * Decimal('1.285'))
                    installment_amount = (Decimal(str(installment_total)) / Decimal(installment_count))

                    booking.is_installment = True
                    booking.installment_total = installment_total
                    booking.installment_count = installment_count
                    booking.installment_amount = installment_amount
                    booking.status = 'laybuy'
                    booking.payment_status = 'partial'
                    booking.installment_deadline = booking.outbound_schedule.departure_time - timedelta(days=30)
                    booking.save()

                    # Remove existing pending installment rows then create new ones
                    booking.installment_payments.all().delete()
                    for i in range(installment_count):
                        due_date = timezone.now() + timedelta(days=30 * (i + 1))
                        InstallmentPayment.objects.create(
                            booking=booking,
                            installment_number=i + 1,
                            amount=installment_amount,
                            due_date=due_date,
                            payment_method='wallet'
                        )
                except Exception as e:
                    logger.exception("Failed to convert booking %s to installments: %s", getattr(booking, 'id', None), e)
                    # fallback: confirm booking
                    booking.status = 'confirmed'
                    booking.save()
            else:
                booking.status = 'confirmed'
                booking.save()
        
        serializer = self.get_serializer(credit_booking)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def reject(self, request, pk=None):
        if not request.user.is_staff:
            return Response({"detail": "Only staff can reject credit bookings"}, 
                          status=status.HTTP_403_FORBIDDEN)
        
        credit_booking = self.get_object()
        admin_notes = request.data.get('admin_notes', '')
        
        with transaction.atomic():
            credit_booking.status = 'rejected'
            credit_booking.admin_notes = admin_notes
            credit_booking.save()
            
            # Update the related booking status
            booking = credit_booking.booking
            booking.status = 'cancelled'
            booking.save()
        
        serializer = self.get_serializer(credit_booking)
        return Response(serializer.data)
