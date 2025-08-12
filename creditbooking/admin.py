from django.contrib import admin
from .models import DocumentType, CreditBooking, CreditDocument

@admin.register(DocumentType)
class DocumentTypeAdmin(admin.ModelAdmin):
    list_display = ('name', 'is_required')
    search_fields = ('name',)

@admin.register(CreditBooking)
class CreditBookingAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'amount', 'status', 'created_at')
    list_filter = ('status', 'created_at')
    search_fields = ('user__username', 'booking__booking_reference')
    readonly_fields = ('created_at', 'updated_at')

@admin.register(CreditDocument)
class CreditDocumentAdmin(admin.ModelAdmin):
    list_display = ('id', 'credit_booking', 'document_type', 'uploaded_at')
    list_filter = ('document_type', 'uploaded_at')
    search_fields = ('credit_booking__user__username',)
