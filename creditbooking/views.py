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

logger = logging.getLogger(__name__)

class DocumentTypeViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = DocumentType.objects.all()
    serializer_class = DocumentTypeSerializer
    permission_classes = [permissions.IsAuthenticated]

class CreditBookingViewSet(viewsets.ModelViewSet):
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
        output = CreditBookingSerializer(credit_booking, context={'request': request})
        logger.info("[CreditBooking][CREATE] Success id=%s", credit_booking.id)
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
        
        with transaction.atomic():
            credit_booking.status = 'approved'
            credit_booking.admin_notes = admin_notes
            credit_booking.save()
            
            # Update the related booking status
            booking = credit_booking.booking
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
