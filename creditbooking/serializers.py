from rest_framework import serializers
from .models import DocumentType, CreditBooking, CreditDocument
from booking.serializers import BookingSerializer
from users.serializers import UserSerializer

class DocumentTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = DocumentType
        fields = '__all__'

class CreditDocumentSerializer(serializers.ModelSerializer):
    document_type_name = serializers.ReadOnlyField(source='document_type.name')
    
    class Meta:
        model = CreditDocument
        fields = ['id', 'document_type', 'document_type_name', 'file', 'uploaded_at']

class CreditBookingSerializer(serializers.ModelSerializer):
    documents = CreditDocumentSerializer(many=True, read_only=True)
    booking = BookingSerializer(read_only=True)
    user = UserSerializer(read_only=True)
    status_display = serializers.SerializerMethodField()
    
    class Meta:
        model = CreditBooking
        fields = ['id', 'user', 'booking', 'amount', 'status', 'status_display', 
                  'reason', 'admin_notes', 'created_at', 'updated_at', 'documents']
    
    def get_status_display(self, obj):
        return dict(CreditBooking.STATUS_CHOICES).get(obj.status, obj.status)

class CreateCreditBookingSerializer(serializers.ModelSerializer):
    booking_id = serializers.IntegerField(write_only=True)
    
    class Meta:
        model = CreditBooking
        fields = ['booking_id', 'amount', 'reason']
    
    def create(self, validated_data):
        booking_id = validated_data.pop('booking_id')
        user = self.context['request'].user
        
        from booking.models import Booking
        booking = Booking.objects.get(id=booking_id)
        
        # Create credit booking
        credit_booking = CreditBooking.objects.create(
            user=user,
            booking=booking,
            **validated_data
        )
        
        return credit_booking
