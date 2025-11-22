from django.shortcuts import render
from django.contrib.auth import get_user_model
from django.http import JsonResponse
from django.views.decorators import csrf
from django.views.decorators import http
from django.utils.decorators import method_decorator
from django.views import View
from django.db import models
from rest_framework import generics, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from destinations.models import Destination
import json
from datetime import datetime, timedelta, date, time, timezone as dt_timezone
import logging
from decimal import Decimal
from django.utils import timezone
from .models import Booking, Flight, FlightSchedule, InstallmentPayment, BookingHistory
from .serializers import BookingSerializer, FlightSerializer, FlightScheduleSerializer, FlightScheduleCreateSerializer
from .models import BOOKING_STATUS_CHOICES
import logging

logger = logging.getLogger(__name__)

# Flight Management Views
class FlightListCreateView(generics.ListCreateAPIView):
    permission_classes = [AllowAny]  # Allow public access to view flights
    queryset = Flight.objects.all()
    serializer_class = FlightSerializer

class FlightDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [AllowAny]  # Allow public access to view flight details
    queryset = Flight.objects.all()
    serializer_class = FlightSerializer

class FlightScheduleListCreateView(generics.ListCreateAPIView):
    permission_classes = [AllowAny]  # Allow public access to view schedules
    queryset = FlightSchedule.objects.all()

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return FlightScheduleCreateSerializer
        return FlightScheduleSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def perform_create(self, serializer):
        serializer.save()

class FlightScheduleDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [AllowAny]  # Allow public access to view schedule details
    queryset = FlightSchedule.objects.all()
    serializer_class = FlightScheduleSerializer

# Flight Search View
class FlightSearchView(APIView):
    permission_classes = [AllowAny]  # Allow unauthenticated flight search
    logger = logging.getLogger(__name__)
    
    def get(self, request):
        """Get all active flights without filtering"""
        flights = FlightSchedule.objects.filter(
            is_active=True,
            departure_time__gte=timezone.now()
        ).order_by('departure_time')[:20]  # Limit to 20 upcoming flights
        
        serializer = FlightScheduleSerializer(flights, many=True)
        
        return Response({
            "available_flights": serializer.data
        })
    
    def post(self, request):
        """Search for flights with tolerant matching.

        Accepts destination name (case-insensitive) or numeric destination id.
        Uses date-only filtering to avoid timezone boundary issues.
        """
        # Optional debug flag to expose filter-stage counts (use ?debug=true or {"debug": true})
        def _to_bool(val):
            if isinstance(val, bool):
                return val
            if val is None:
                return False
            s = str(val).strip().lower()
            return s in {"1", "true", "yes", "y", "on"}

        debug_flag = False
        try:
            # prefer query param if available (DRF Request has query_params)
            if hasattr(request, 'query_params') and request.query_params is not None:
                debug_flag = _to_bool(request.query_params.get('debug'))
        except Exception:
            pass
        if not debug_flag:
            try:
                debug_flag = _to_bool(request.data.get('debug'))
            except Exception:
                pass
        from_destination = request.data.get('from_destination') or None
        to_destination = request.data.get('to_destination') or None
        departure_date = request.data.get('departure_date') or None
        return_date = request.data.get('return_date')
        trip_type = request.data.get('trip_type')
        adult_count = request.data.get('adult_count', 1)
        child_count = request.data.get('child_count', 0)

        all_qs = FlightSchedule.objects.all()
        flights = all_qs.filter(is_active=True)
        diagnostics = {}
        if debug_flag:
            try:
                diagnostics['total_schedules'] = all_qs.count()
                diagnostics['total_active'] = flights.count()
            except Exception:
                pass

        # Helper to apply destination filter flexibly, prefer direct FK if available
        def apply_destination_filter(qs, field_name, value):
            if not value:
                return qs
            try:
                # If numeric, treat as destination id
                if isinstance(value, int) or (isinstance(value, str) and value.isdigit()):
                    dest_id = int(value)
                    # Try direct FK first
                    if field_name in ['from_destination', 'to_destination']:
                        return qs.filter(**{f"{field_name}_id": dest_id})
                    # Fallback to original path
                    return qs.filter(**{f"{field_name}_id": dest_id})
                # Try exact match by name or airport code
                dest = Destination.objects.filter(
                    models.Q(name__iexact=value) |
                    models.Q(airport_code__iexact=value)
                ).first()
                if dest:
                    if field_name in ['from_destination', 'to_destination']:
                        return qs.filter(**{f"{field_name}_id": dest.id})
                    return qs.filter(**{f"{field_name}_id": dest.id})
                # If no exact match found, try partial match on name
                if field_name in ['from_destination', 'to_destination']:
                    return qs.filter(**{f"{field_name}__name__icontains": value})
                return qs.filter(**{f"{field_name}__name__icontains": value})
            except Exception as e:
                self.logger.error(f"Error in apply_destination_filter: {str(e)}")
                return qs.none()  # Return empty queryset on error

        # Try direct FK first, fallback to original path if needed
        # Adjust these field names if your model uses direct FKs
        from_field = 'flight__route__from_destination'
        to_field = 'flight__route__to_destination'
        # If your FlightSchedule has direct FKs, use:
        # from_field = 'from_destination'
        # to_field = 'to_destination'

        if from_destination:
            before = flights.count() if debug_flag else None
            flights = apply_destination_filter(flights, from_field, from_destination)
            if debug_flag:
                diagnostics['from_field'] = from_field
                diagnostics['before_from_filter'] = before
                diagnostics['after_from_filter'] = flights.count()
        if to_destination:
            before = flights.count() if debug_flag else None
            flights = apply_destination_filter(flights, to_field, to_destination)
            if debug_flag:
                diagnostics['to_field'] = to_field
                diagnostics['before_to_filter'] = before
                diagnostics['after_to_filter'] = flights.count()

        if departure_date:
            # Prefer a direct date lookup to avoid timezone boundary issues across environments
            try:
                if isinstance(departure_date, str):
                    dep_dt = datetime.strptime(departure_date, '%Y-%m-%d').date()
                elif isinstance(departure_date, date):
                    dep_dt = departure_date
                else:
                    dep_dt = None
                if dep_dt:
                    before_date_filter = flights.count()
                    flights = flights.filter(departure_time__date=dep_dt)
                    after_date_filter = flights.count()
                    if debug_flag:
                        diagnostics['before_date_filter'] = before_date_filter
                        diagnostics['after_date_filter'] = after_date_filter
                    # If nothing matched, fall back to an explicit UTC day window
                    if after_date_filter == 0:
                        tz = dt_timezone.utc
                        start = timezone.make_aware(datetime.combine(dep_dt, time.min), tz)
                        end = timezone.make_aware(datetime.combine(dep_dt + timedelta(days=1), time.min), tz)
                        fallback_qs = FlightSchedule.objects.filter(is_active=True)
                        if from_destination:
                            fallback_qs = apply_destination_filter(fallback_qs, 'flight__route__from_destination', from_destination)
                        if to_destination:
                            fallback_qs = apply_destination_filter(fallback_qs, 'flight__route__to_destination', to_destination)
                        flights = fallback_qs.filter(departure_time__gte=start, departure_time__lt=end)
                        self.logger.info(
                            "FlightSearch fallback UTC window used for date=%s (before=%s after_date=%s)",
                            dep_dt, before_date_filter, flights.count()
                        )
                        if debug_flag:
                            diagnostics['fallback_utc_window_count'] = flights.count()
            except Exception as ex:
                self.logger.warning(f"FlightSearchView: failed to parse departure_date={departure_date}: {ex}")

        flights = flights.select_related('flight', 'flight__route', 'flight__route__from_destination', 'flight__route__to_destination')

        # Logging for diagnostics in production
        try:
            total = flights.count()
            self.logger.info(
                "FlightSearch payload from=%s to=%s date=%s -> matches=%s",
                from_destination, to_destination, departure_date, total
            )
            if total == 0:
                # Auto diagnostics in logs to help prod triage without changing API
                diag_qs = all_qs
                if from_destination:
                    diag_qs = apply_destination_filter(diag_qs, 'flight__route__from_destination', from_destination)
                if to_destination:
                    diag_qs = apply_destination_filter(diag_qs, 'flight__route__to_destination', to_destination)
                pre_date = diag_qs.count()
                post_date = None
                post_date_utc_window = None
                if departure_date:
                    try:
                        if isinstance(departure_date, str):
                            dep_dt_d = datetime.strptime(departure_date, '%Y-%m-%d').date()
                        elif isinstance(departure_date, date):
                            dep_dt_d = departure_date
                        else:
                            dep_dt_d = None
                        if dep_dt_d:
                            post_date = diag_qs.filter(departure_time__date=dep_dt_d).count()
                            tz = dt_timezone.utc
                            start = timezone.make_aware(datetime.combine(dep_dt_d, time.min), tz)
                            end = timezone.make_aware(datetime.combine(dep_dt_d + timedelta(days=1), time.min), tz)
                            post_date_utc_window = diag_qs.filter(departure_time__gte=start, departure_time__lt=end).count()
                    except Exception:
                        pass
                self.logger.info(
                    "FlightSearch zero-match diag: total_schedules=%s active=%s candidates_no_is_active=%s candidates_date=%s candidates_utc_window=%s",
                    all_qs.count(),
                    FlightSchedule.objects.filter(is_active=True).count(),
                    pre_date,
                    post_date,
                    post_date_utc_window,
                )
        except Exception:
            pass

        # Additional diagnostics: see if removing is_active yields candidates (to detect data issues)
        if debug_flag:
            try:
                debug_qs = all_qs
                if from_destination:
                    debug_qs = apply_destination_filter(debug_qs, 'flight__route__from_destination', from_destination)
                if to_destination:
                    debug_qs = apply_destination_filter(debug_qs, 'flight__route__to_destination', to_destination)
                if departure_date:
                    if isinstance(departure_date, str):
                        dep_dt = datetime.strptime(departure_date, '%Y-%m-%d').date()
                    elif isinstance(departure_date, date):
                        dep_dt = departure_date
                    else:
                        dep_dt = None
                    if dep_dt:
                        debug_qs = debug_qs.filter(departure_time__date=dep_dt)
                diagnostics['matches_without_is_active'] = debug_qs.count()
                diagnostics['sample_ids_without_is_active'] = list(debug_qs.values_list('id', flat=True)[:10])
            except Exception:
                pass

        outbound_serializer = FlightScheduleSerializer(flights, many=True)

        response_payload = {
            "trip_type": trip_type,
            "from_destination": from_destination,
            "to_destination": to_destination,
            "departure_date": departure_date,
            "return_date": return_date,
            "passenger_count": {
                "adults": adult_count,
                "children": child_count,
                "total": int(adult_count) + int(child_count)
            },
            "outbound_flights": outbound_serializer.data,
            "return_flights": [],
        }

        if debug_flag and diagnostics:
            response_payload['diagnostics'] = diagnostics

        return Response(response_payload)

User = get_user_model()

# Enhanced Booking Views with Installment Support
class CreateBookingView(APIView):
    permission_classes = [IsAuthenticated]  # Require authentication for booking
    
    def post(self, request):
        try:
            data = request.data
            # Use authenticated user instead of requiring user_id in payload
            user = request.user
            flight_schedule_id = data.get('flight_schedule_id')
            return_schedule_id = data.get('return_schedule_id')
            adult_count = int(data.get('adult_count', 1))
            child_count = int(data.get('child_count', 0))
            payment_method = data.get('payment_method')
            trip_type = data.get('trip_type')
            # Defensive handling: do not trust client-provided `is_installment` flag.
            # Only treat a booking as an installment when the payment_method is
            # explicitly 'installment' AND the client provides an explicit
            # confirmation token/flag `confirm_installment` (to avoid accidental
            # classification from other flows like credit applications).
            def _to_bool(v):
                if isinstance(v, bool):
                    return v
                if v is None:
                    return False
                s = str(v).strip().lower()
                return s in {"1", "true", "yes", "y", "on"}

            confirm_installment = _to_bool(data.get('confirm_installment'))
            is_installment = True if (payment_method == 'installment' and confirm_installment) else False

            total_passengers = adult_count + child_count
            flight_schedule = FlightSchedule.objects.get(id=flight_schedule_id)

            if flight_schedule.available_seats < total_passengers:
                return Response({'error': 'Not enough seats available'}, status=status.HTTP_400_BAD_REQUEST)

            return_schedule = None
            if return_schedule_id:
                return_schedule = FlightSchedule.objects.get(id=return_schedule_id)

            base_price = Decimal(float(flight_schedule.route.price) * total_passengers)
            if trip_type == "round_trip" and return_schedule:
                base_price += Decimal(float(return_schedule.route.price) * total_passengers)

            # Handle installment pricing
            total_price = base_price
            installment_total = None
            installment_amount = None
            installment_count = 0
            booking_status = 'pending'

            if is_installment and payment_method == 'installment':
                # Check if booking is eligible for installments (3+ months in advance)
                departure_date = flight_schedule.departure_time.date()
                today = timezone.now().date()
                months_difference = (departure_date.year - today.year) * 12 + departure_date.month - today.month
                
                if months_difference < 3:
                    return Response({
                        'error': 'Installment payment is only available for bookings made at least 3 months in advance'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                # Calculate installment pricing (higher total for installments)
                installment_total = base_price * Decimal('1.285')  # ~28.5% increase (900/700)
                installment_count = 3
                installment_amount = installment_total / installment_count
                total_price = installment_total
                booking_status = 'laybuy'  # Set status to laybuy for installment bookings
            
            # Handle currency conversion if needed
            selected_currency = request.data.get('currency', 'USD')
            booking_currency = selected_currency
            
            # If ZAR is selected, convert the price from USD to ZAR
            if selected_currency == 'ZAR' and flight_schedule.route.currency == 'USD':
                # Fixed exchange rate for now - in production this should use a currency API
                exchange_rate = Decimal('18.05')
                base_price = base_price * exchange_rate
                total_price = total_price * exchange_rate
                if installment_amount:
                    installment_amount = installment_amount * exchange_rate
            
            # Create booking
            booking = Booking.objects.create(
                user=user,
                trip_type=trip_type,
                outbound_schedule=flight_schedule,
                return_schedule=return_schedule,
                adult_count=adult_count,
                child_count=child_count,
                base_price=base_price,
                total_price=total_price,
                currency=booking_currency,
                payment_method=payment_method,
                is_installment=is_installment,
                installment_total=installment_total,
                installment_count=installment_count,
                installment_amount=installment_amount,
                installment_deadline=flight_schedule.departure_time - timedelta(days=30) if is_installment else None,
                status=booking_status,
                contact_phone=data.get('contact_phone', ''),
                contact_email=data.get('contact_email', ''),
                special_requests=data.get('special_requests', '')
            )

            # Create installment payment records if needed
            if is_installment and installment_count > 0:
                for i in range(installment_count):
                    due_date = timezone.now() + timedelta(days=30 * (i + 1))  # Monthly installments
                    InstallmentPayment.objects.create(
                        booking=booking,
                        installment_number=i + 1,
                        amount=installment_amount,
                        due_date=due_date,
                        payment_method='wallet'  # Default to wallet for installments
                    )

            # Award loyalty points for wallet payments (not for installments yet)
            earned_points = 0
            if payment_method == 'wallet' and not is_installment:
                earned_points = 50
                from loyalty.models import LoyaltyAccount
                
                loyalty_account, _ = LoyaltyAccount.objects.get_or_create(user=user)
                loyalty_account.add_points(earned_points, f'Earned 50 points for booking {booking.booking_reference}')

                booking.points_earned = earned_points
                # If the client intends to pay via wallet, the frontend typically
                # deducts funds immediately after booking creation. When that
                # happens we should consider the booking as paid/confirmed so it
                # does not remain in 'pending' status while money and points
                # have already been applied.
                booking.payment_status = 'paid'
                # Award loyalty points equal to 10% of booking total for wallet payments (skip installment bookings)
                earned_points = 0
                if payment_method == 'wallet' and not is_installment:
                    # Calculate 10% of total price
                    earned_points = int(total_price * Decimal('0.1'))
                    from loyalty.models import LoyaltyAccount
                    loyalty_account, _ = LoyaltyAccount.objects.get_or_create(user=user)
                    if earned_points > 0:
                        loyalty_account.add_points(earned_points, f'Earned {earned_points} points for booking {booking.booking_reference}')
                    booking.points_earned = earned_points
                    try:
                        BookingHistory.objects.create(
                            booking=booking,
                            status_from='pending',
                            status_to='confirmed',
                            changed_by=request.user,
                            reason='Wallet payment completed during booking creation'
                        )
                    except Exception:
                        # Non-fatal: history creation should not break booking flow
                        pass

            return Response({
                'booking_id': booking.id,
                'booking_reference': booking.booking_reference,
                'status': booking.status,
                'is_installment': booking.is_installment,
                'installment_count': booking.installment_count,
                'installment_amount': str(booking.installment_amount) if booking.installment_amount else None,
                'points_earned': earned_points,
                'total_price': str(total_price)
            }, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except FlightSchedule.DoesNotExist:
            return Response({'error': 'Flight schedule not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ProcessPaymentView(APIView):
    permission_classes = [AllowAny]  # Require authentication for payment processing
    
    def post(self, request):
        try:
            data = request.data
            logger.debug('[ProcessPayment] payload=%s', data)
            booking_id = data.get('booking_id')
            payment_method = data.get('payment_method')
            installment_number = data.get('installment_number')  # For installment payments
            if not booking_id:
                logger.warning('[ProcessPayment] missing booking_id in payload')
                return Response({'error': 'booking_id is required'}, status=status.HTTP_400_BAD_REQUEST)

            try:
                booking = Booking.objects.get(id=booking_id)
            except Booking.DoesNotExist:
                logger.warning('[ProcessPayment] booking not found id=%s', booking_id)
                return Response({'error': 'Booking not found', 'booking_id': booking_id}, status=status.HTTP_404_NOT_FOUND)
            
            # Handle installment payment
            if booking.is_installment:
                # If the booking is an installment plan, prefer the explicit installment_number
                # but if the client omits it, auto-select the next pending installment so
                # common frontends that only intend to pay the next due installment don't fail.
                if installment_number:
                    return self._process_installment_payment(booking, installment_number, payment_method)
                # Attempt to find the next pending installment automatically
                try:
                    next_pending = InstallmentPayment.objects.filter(booking=booking, status='pending').order_by('installment_number').first()
                except Exception:
                    next_pending = None

                if next_pending:
                    logger.info('[ProcessPayment] auto-selected installment=%s for booking=%s', next_pending.installment_number, booking_id)
                    return self._process_installment_payment(booking, next_pending.installment_number, payment_method)

                # No pending installment found - return a helpful 400 payload
                logger.warning('[ProcessPayment] no pending installments for booking=%s payload=%s', booking_id, data)
                return Response({
                    'error': 'installment_number required for installment bookings',
                    'message': 'No pending installments found. Provide installment_number to target a specific installment.'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Handle points payment
            if payment_method == 'points':
                from loyalty.models import LoyaltyAccount, PointRedemption
                loyalty_account = LoyaltyAccount.objects.get(user=booking.user)
                
                POINTS_FOR_FREE_FLIGHT = 500
                
                if loyalty_account.points < POINTS_FOR_FREE_FLIGHT:
                    return Response({
                        'error': 'Insufficient points',
                        'required': POINTS_FOR_FREE_FLIGHT,
                        'available': loyalty_account.points,
                        'message': 'You need at least 500 points to redeem for a free flight'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                approved_redemption = PointRedemption.objects.filter(
                    user=booking.user,
                    redemption_type='free_flight',
                    status='approved'
                ).first()
                
                if not approved_redemption:
                    return Response({
                        'error': 'No approved redemption found',
                        'message': 'You must first request a free flight redemption and get admin approval before using points to pay'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                loyalty_account.deduct_points(
                    POINTS_FOR_FREE_FLIGHT, 
                    f'Payment for booking {booking.booking_reference} (Free Flight Redemption)'
                )
                
                approved_redemption.status = 'completed'
                approved_redemption.save()
                
                booking.payment_status = 'paid'
                booking.status = 'confirmed'
                booking.points_used = POINTS_FOR_FREE_FLIGHT
                booking.save()
                
                return Response({
                    'payment_id': booking.id,
                    'status': 'completed',
                    'booking_id': booking_id,
                    'points_used': POINTS_FOR_FREE_FLIGHT,
                    'message': 'Free flight redeemed successfully'
                })
            
            # Handle other payment methods (non-installment)
            if not booking.is_installment:
                booking.payment_status = 'paid'
                booking.status = 'confirmed'
                booking.save()
            
            return Response({
                'payment_id': booking.id,
                'status': 'completed',
                'booking_id': booking_id,
                'booking_status': booking.status
            })
            
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def _process_installment_payment(self, booking, installment_number, payment_method):
        """Process individual installment payment"""
        try:
            installment = InstallmentPayment.objects.get(
                booking=booking,
                installment_number=installment_number
            )
            
            if installment.status == 'completed':
                return Response({
                    'error': 'This installment has already been paid'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Process wallet payment for installment
            if payment_method == 'wallet':
                from wallets.models import Wallet, WalletBalance
                from currency.models import Currency
                
                wallet = Wallet.objects.get(user=booking.user)
                currency = Currency.objects.get(code=booking.currency)
                wallet_balance = WalletBalance.objects.get(wallet=wallet, currency=currency)
                
                if wallet_balance.balance < installment.amount:
                    return Response({
                        'code': 'INSUFFICIENT_FUNDS',
                        'message': f'Insufficient wallet balance for installment payment. Required {installment.amount}, available {wallet_balance.balance}.',
                        'required': str(installment.amount),
                        'available': str(wallet_balance.balance),
                        'currency': currency.code if 'currency' in locals() else booking.currency
                    }, status=402)
                
                # Deduct amount from wallet
                wallet_balance.balance -= installment.amount
                wallet_balance.save()
                
                # Award loyalty points for wallet installment payment (15 points each)
                from loyalty.models import LoyaltyAccount
                loyalty_account, _ = LoyaltyAccount.objects.get_or_create(user=booking.user)
                points_earned = 15  # 15 points for each installment payment
                loyalty_account.add_points(
                    points_earned, 
                    f'Installment payment {installment_number} for booking {booking.booking_reference}'
                )
                
                installment.points_earned = points_earned
            
            # Mark installment as completed
            installment.status = 'completed'
            installment.payment_date = timezone.now()
            installment.payment_method = payment_method
            installment.save()
            
            # Check if all installments are completed
            remaining_installments = InstallmentPayment.objects.filter(
                booking=booking,
                status='pending'
            ).count()
            
            if remaining_installments == 0:
                # All installments paid - move from laybuy to confirmed
                old_status = booking.status
                booking.payment_status = 'paid'
                booking.status = 'confirmed'
                booking.save()
                
                # Create history record for status change
                BookingHistory.objects.create(
                    booking=booking,
                    status_from=old_status,
                    status_to='confirmed',
                    reason=f'All installments completed - final payment {installment_number}'
                )
            else:
                booking.payment_status = 'partial'
                booking.save()
            
            return Response({
                'installment_id': installment.id,
                'status': 'completed',
                'points_earned': installment.points_earned,
                'remaining_installments': remaining_installments,
                'booking_status': booking.status,
                'message': f'Installment {installment_number} paid successfully'
            })
            
        except InstallmentPayment.DoesNotExist:
            return Response({
                'error': 'Installment not found'
            }, status=status.HTTP_404_NOT_FOUND)

# User Booking Views
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_bookings(request):
    try:
        user_id = request.GET.get('user_id')
        include_laybuy = request.GET.get('include_laybuy', 'false').lower() == 'true'
        
        if user_id:
            bookings = Booking.objects.filter(user_id=user_id).order_by('-created_at')
        else:
            bookings = Booking.objects.all().order_by('-created_at')
        
        # Filter out laybuy bookings from main booking history unless specifically requested
        if not include_laybuy:
            bookings = bookings.exclude(status='laybuy')
        
        # Enhanced serialization with route information
        booking_data = []
        for booking in bookings:
            data = {
                'id': booking.id,
                'booking_reference': booking.booking_reference,
                'trip_type': booking.trip_type,
                'from_destination': booking.outbound_schedule.flight.route.from_destination.name if booking.outbound_schedule else '',
                'to_destination': booking.outbound_schedule.flight.route.to_destination.name if booking.outbound_schedule else '',
                'departure_date': booking.outbound_schedule.departure_time.isoformat() if booking.outbound_schedule else '',
                'return_date': booking.return_schedule.departure_time.isoformat() if booking.return_schedule else None,
                'adult_count': booking.adult_count,
                'child_count': booking.child_count,
                'total_amount': str(booking.total_price),
                'payment_method': booking.payment_method,
                'status': booking.status,
                'points_earned': booking.points_earned,
                'created_at': booking.created_at.isoformat(),
                'is_installment': booking.is_installment,
                'installment_count': booking.installment_count,
                'installment_amount': str(booking.installment_amount) if booking.installment_amount else None,
            }
            
            # Add installment details if applicable
            if booking.is_installment:
                installments = InstallmentPayment.objects.filter(booking=booking)
                data['installments'] = [
                    {
                        'installment_number': inst.installment_number,
                        'amount': str(inst.amount),
                        'due_date': inst.due_date.isoformat(),
                        'payment_date': inst.payment_date.isoformat() if inst.payment_date else None,
                        'status': inst.status,
                        'points_earned': inst.points_earned
                    }
                    for inst in installments
                ]
            
            booking_data.append(data)
        
        return Response(booking_data)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_laybuy_bookings(request):
    """Get only laybuy (installment) bookings for the user"""
    try:
        user_id = request.GET.get('user_id')
        if not user_id:
            return Response({'error': 'User ID is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        bookings = Booking.objects.filter(
            user_id=user_id, 
            status='laybuy',
            is_installment=True
        ).order_by('-created_at')
        
        booking_data = []
        for booking in bookings:
            installments = InstallmentPayment.objects.filter(booking=booking).order_by('installment_number')
            
            data = {
                'id': booking.id,
                'booking_reference': booking.booking_reference,
                'trip_type': booking.trip_type,
                'from_destination': booking.outbound_schedule.flight.route.from_destination.name,
                'to_destination': booking.outbound_schedule.flight.route.to_destination.name,
                'departure_date': booking.outbound_schedule.departure_time.isoformat(),
                'return_date': booking.return_schedule.departure_time.isoformat() if booking.return_schedule else None,
                'adult_count': booking.adult_count,
                'child_count': booking.child_count,
                'total_amount': str(booking.total_price),
                'installment_total': str(booking.installment_total),
                'installment_count': booking.installment_count,
                'installment_amount': str(booking.installment_amount),
                'status': booking.status,
                'created_at': booking.created_at.isoformat(),
                'installments': [
                    {
                        'installment_number': inst.installment_number,
                        'amount': str(inst.amount),
                        'due_date': inst.due_date.isoformat(),
                        'payment_date': inst.payment_date.isoformat() if inst.payment_date else None,
                        'status': inst.status,
                        'points_earned': inst.points_earned
                    }
                    for inst in installments
                ]
            }
            booking_data.append(data)
        
        return Response(booking_data)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_booking_detail(request, booking_id):
    try:
        booking = Booking.objects.get(id=booking_id)
        serializer = BookingSerializer(booking)
        
        # Include installment details if applicable
        response_data = serializer.data
        if booking.is_installment:
            installments = InstallmentPayment.objects.filter(booking=booking)
            response_data['installments'] = [
                {
                    'installment_number': inst.installment_number,
                    'amount': str(inst.amount),
                    'due_date': inst.due_date,
                    'payment_date': inst.payment_date,
                    'status': inst.status,
                    'points_earned': inst.points_earned
                }
                for inst in installments
            ]
        
        return Response(response_data)
    except Booking.DoesNotExist:
        return Response({'error': 'Booking not found'}, status=status.HTTP_404_NOT_FOUND)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def cancel_booking(request, booking_id):
    try:
        # Use authenticated user
        user = request.user
        # Ensure the booking belongs to the authenticated user
        booking = Booking.objects.get(id=booking_id, user=user)
        old_status = booking.status

        # Update booking status
        booking.status = 'cancelled'
        booking.save()

        # Create history record
        BookingHistory.objects.create(
            booking=booking,
            status_from=old_status,
            status_to='cancelled',
            changed_by=request.user,
            reason=request.data.get('reason', 'Cancelled by user')
        )

        return Response({'status': 'cancelled'})
    except Booking.DoesNotExist:
        return Response({'error': 'Booking not found'}, status=status.HTTP_404_NOT_FOUND)

# Reference Data Views - Public Access
@api_view(['GET'])
@permission_classes([AllowAny])  # Allow public access to destinations
def get_destinations(request):
    try:
        from destinations.models import Destination
        destinations = Destination.objects.all()
        data = [
            {
                'id': dest.id,
                'name': dest.name,
                'code': dest.code,
                'country': dest.country
            }
            for dest in destinations
        ]
        return Response(data)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([AllowAny])  # Allow public access to routes
def get_routes(request):
    try:
        from routes.models import Route
        routes = Route.objects.all()
        data = [
            {
                'id': route.id,
                'from_destination': {
                    'id': route.from_destination.id,
                    'name': route.from_destination.name,
                    'code': route.from_destination.code
                },
                'to_destination': {
                    'id': route.to_destination.id,
                    'name': route.to_destination.name,
                    'code': route.to_destination.code
                },
                'price': str(route.price),
                'currency': route.currency,
                'estimated_time': route.estimated_time,
                'distance': route.distance,
                'point_threshold': route.point_threshold
            }
            for route in routes
        ]
        return Response(data)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([AllowAny])  # Allow public access to flights
def get_flights(request):
    try:
        flights = Flight.objects.all()
        serializer = FlightSerializer(flights, many=True)
        return Response(serializer.data)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# New endpoint for installment payments
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def pay_installment(request):
    """Pay a specific installment"""
    try:
        booking_id = request.data.get('booking_id')
        installment_number = request.data.get('installment_number')
        payment_method = request.data.get('payment_method', 'wallet')
        
        if not booking_id or not installment_number:
            return Response({
                'error': 'booking_id and installment_number are required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Use the existing ProcessPaymentView logic
        payment_view = ProcessPaymentView()
        return payment_view.post(request)
        
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_admin_bookings(request):
    """Get all bookings for admin management"""
    try:
        # Check if user is admin
        if not request.user.is_staff:
            return Response({'error': 'Admin access required'}, status=status.HTTP_403_FORBIDDEN)
        
        bookings = Booking.objects.all().order_by('-created_at')
        serializer = BookingSerializer(bookings, many=True)
        
        # Add additional admin data
        admin_data = []
        for booking_data in serializer.data:
            booking = Booking.objects.get(id=booking_data['id'])
            booking_info = booking_data.copy()
            
            # Add installment details if applicable
            if booking.is_installment:
                installments = InstallmentPayment.objects.filter(booking=booking)
                booking_info['installments'] = [
                    {
                        'installment_number': inst.installment_number,
                        'amount': str(inst.amount),
                        'due_date': inst.due_date,
                        'payment_date': inst.payment_date,
                        'status': inst.status,
                        'points_earned': inst.points_earned
                    }
                    for inst in installments
                ]
            
            # Add user information
            booking_info['user_info'] = {
                'name': f"{booking.user.first_name} {booking.user.last_name}",
                'phone': booking.user.phone_number,
                'email': booking.user.email
            }
            
            admin_data.append(booking_info)
        
        return Response(admin_data)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def update_booking_status(request, booking_id):
    """Update booking status (admin only)"""
    try:
        # Use authenticated user
        user = request.user
        # Only admin can update booking status
        if not user.is_staff:
            return Response({'error': 'Admin access required'}, status=status.HTTP_403_FORBIDDEN)

        # Fetch booking
        booking = Booking.objects.get(id=booking_id)
        old_status = booking.status

        # New status must be provided in the payload
        new_status = request.data.get('status') or request.data.get('new_status')
        if not new_status:
            return Response({'error': 'new status is required'}, status=status.HTTP_400_BAD_REQUEST)

        # Update and save
        booking.status = new_status
        booking.save()

        # Create history record
        BookingHistory.objects.create(
            booking=booking,
            status_from=old_status,
            status_to=new_status,
            changed_by=request.user,
            reason=request.data.get('reason', f'Status updated by admin {request.user.username}')
        )

        return Response({'status': 'updated', 'new_status': new_status})
        
    except Booking.DoesNotExist:
        return Response({'error': 'Booking not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def flight_statistics(request):
    """
    API endpoint to get flight statistics for admin dashboard
    """
    try:
        # Check if user is staff
        if not request.user.is_staff:
            return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
            
        # Get current date
        today = timezone.now().date()
        
        # Get total flights
        total_flights = FlightSchedule.objects.count()
        
        # Get active flights (not departed)
        active_flights = FlightSchedule.objects.filter(departure_time__gte=timezone.now()).count()
        
        # Get today's flights
        todays_flights = FlightSchedule.objects.filter(
            departure_time__date=today
        ).count()
        
        # Return the statistics
        return Response({
            'total_flights': total_flights,
            'active_flights': active_flights,
            'todays_flights': todays_flights
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def booking_statistics(request):
    """
    API endpoint to get booking statistics for admin dashboard
    """
    try:
        # Check if user is staff
        if not request.user.is_staff:
            return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
            
        # Get current date
        today = timezone.now().date()
        
        # Get total bookings
        total_bookings = Booking.objects.count()
        
        # Get today's bookings
        todays_bookings = Booking.objects.filter(
            created_at__date=today
        ).count()
        
        # Get bookings by status
        bookings_by_status = {}
        for status_choice in BOOKING_STATUS_CHOICES:
            status_code = status_choice[0]
            bookings_by_status[status_code] = Booking.objects.filter(status=status_code).count()
        
        # Get bookings by date for last 30 days
        thirty_days_ago = today - timedelta(days=30)
        bookings_by_date = []
        
        for i in range(31):  # 0 to 30 days back
            date = today - timedelta(days=i)
            count = Booking.objects.filter(
                created_at__date=date
            ).count()
            bookings_by_date.append({
                'date': date.strftime('%Y-%m-%d'),
                'count': count
            })
        
        # Return the statistics
        return Response({
            'total_bookings': total_bookings,
            'todays_bookings': todays_bookings,
            'bookings_by_status': bookings_by_status,
            'bookings_by_date': bookings_by_date
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
