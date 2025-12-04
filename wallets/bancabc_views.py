"""
BancABC Dashboard Views
Provides frontend dashboard for BancABC integration monitoring and reporting
"""
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import JsonResponse, HttpResponse
from django.db.models import Sum, Count, Q, Avg
from django.utils import timezone
from datetime import datetime, timedelta
from wallets.models import ProcessedTransaction, WalletTransaction, WalletBalance
from django.core.paginator import Paginator
import csv
import json


def is_staff_or_superuser(user):
    """Check if user is staff or superuser"""
    return user.is_staff or user.is_superuser


@login_required
@user_passes_test(is_staff_or_superuser)
def bancabc_dashboard(request):
    """
    Main BancABC dashboard view
    """
    # Get date range from query params
    date_from = request.GET.get('date_from')
    date_to = request.GET.get('date_to')
    
    # Default to last 7 days if not specified
    if not date_from:
        date_from = (timezone.now() - timedelta(days=7)).strftime('%Y-%m-%d')
    if not date_to:
        date_to = timezone.now().strftime('%Y-%m-%d')
    
    # Parse dates
    try:
        start_date = datetime.strptime(date_from, '%Y-%m-%d')
        end_date = datetime.strptime(date_to, '%Y-%m-%d').replace(hour=23, minute=59, second=59)
    except ValueError:
        start_date = timezone.now() - timedelta(days=7)
        end_date = timezone.now()
    
    # Get transactions
    transactions = ProcessedTransaction.objects.filter(
        created_at__range=[start_date, end_date]
    ).select_related('user', 'currency').order_by('-created_at')
    
    # Calculate statistics
    stats = {
        'total_transactions': transactions.count(),
        'successful': transactions.filter(payment_status='SUCCESS').count(),
        'failed': transactions.filter(payment_status='FAILED').count(),
        'pending': transactions.filter(payment_status='PENDING').count(),
        'total_amount': transactions.filter(payment_status='SUCCESS').aggregate(
            total=Sum('amount')
        )['total'] or 0,
        'verified': transactions.filter(payment_verified=True).count(),
        'unverified': transactions.filter(
            payment_status='SUCCESS',
            payment_verified=False
        ).count(),
    }
    
    # Calculate success rate
    if stats['total_transactions'] > 0:
        stats['success_rate'] = (stats['successful'] / stats['total_transactions']) * 100
    else:
        stats['success_rate'] = 0
    
    # Branch performance
    branch_stats = transactions.values('branch_code').annotate(
        total=Count('id'),
        successful=Count('id', filter=Q(payment_status='SUCCESS')),
        failed=Count('id', filter=Q(payment_status='FAILED')),
        amount=Sum('amount', filter=Q(payment_status='SUCCESS'))
    ).order_by('-amount')[:10]
    
    # Recent transactions for display
    recent_transactions = transactions[:20]
    
    context = {
        'stats': stats,
        'branch_stats': branch_stats,
        'recent_transactions': recent_transactions,
        'date_from': date_from,
        'date_to': date_to,
    }
    
    return render(request, 'bancabc/dashboard.html', context)


@login_required
@user_passes_test(is_staff_or_superuser)
def bancabc_transactions(request):
    """
    Transactions list view with filtering
    """
    # Get filter parameters
    status = request.GET.get('status', '')
    payment_method = request.GET.get('payment_method', '')
    branch_code = request.GET.get('branch_code', '')
    verified = request.GET.get('verified', '')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    search = request.GET.get('search', '')
    
    # Base queryset
    transactions = ProcessedTransaction.objects.all().select_related('user', 'currency')
    
    # Apply filters
    if status:
        transactions = transactions.filter(payment_status=status)
    if payment_method:
        transactions = transactions.filter(payment_method=payment_method)
    if branch_code:
        transactions = transactions.filter(branch_code=branch_code)
    if verified == 'yes':
        transactions = transactions.filter(payment_verified=True)
    elif verified == 'no':
        transactions = transactions.filter(payment_verified=False)
    if date_from:
        transactions = transactions.filter(created_at__gte=date_from)
    if date_to:
        transactions = transactions.filter(created_at__lte=date_to)
    if search:
        transactions = transactions.filter(
            Q(bancabc_reference__icontains=search) |
            Q(transaction_id__icontains=search) |
            Q(user__phone_number__icontains=search) |
            Q(user__email__icontains=search) |
            Q(user__first_name__icontains=search) |
            Q(user__last_name__icontains=search)
        )
    
    # Order by most recent
    transactions = transactions.order_by('-created_at')
    
    # Pagination
    paginator = Paginator(transactions, 50)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    # Get unique branch codes for filter dropdown
    branches = ProcessedTransaction.objects.values_list('branch_code', flat=True).distinct().order_by('branch_code')
    
    context = {
        'page_obj': page_obj,
        'branches': [b for b in branches if b],
        'filters': {
            'status': status,
            'payment_method': payment_method,
            'branch_code': branch_code,
            'verified': verified,
            'date_from': date_from,
            'date_to': date_to,
            'search': search,
        }
    }
    
    return render(request, 'bancabc/transactions.html', context)


@login_required
@user_passes_test(is_staff_or_superuser)
def bancabc_transaction_detail(request, transaction_id):
    """
    Detailed view of a single transaction
    """
    transaction = ProcessedTransaction.objects.select_related(
        'user', 'currency'
    ).get(id=transaction_id)
    
    # Get related wallet transaction if exists
    wallet_txn = None
    if transaction.payment_verified and transaction.status == 'completed':
        wallet_txn = WalletTransaction.objects.filter(
            wallet__user=transaction.user,
            amount=transaction.amount,
            currency=transaction.currency,
            created_at__gte=transaction.created_at
        ).first()
    
    # Get wallet balance
    wallet_balance = None
    try:
        from wallets.models import Wallet
        wallet = Wallet.objects.get(user=transaction.user)
        wallet_balance = WalletBalance.objects.get(
            wallet=wallet,
            currency=transaction.currency
        )
    except:
        pass
    
    context = {
        'transaction': transaction,
        'wallet_txn': wallet_txn,
        'wallet_balance': wallet_balance,
    }
    
    return render(request, 'bancabc/transaction_detail.html', context)


@login_required
@user_passes_test(is_staff_or_superuser)
def bancabc_reports(request):
    """
    Reports page with various analytics
    """
    # Date range
    date_from = request.GET.get('date_from', (timezone.now() - timedelta(days=30)).strftime('%Y-%m-%d'))
    date_to = request.GET.get('date_to', timezone.now().strftime('%Y-%m-%d'))
    
    start_date = datetime.strptime(date_from, '%Y-%m-%d')
    end_date = datetime.strptime(date_to, '%Y-%m-%d').replace(hour=23, minute=59, second=59)
    
    transactions = ProcessedTransaction.objects.filter(
        created_at__range=[start_date, end_date]
    )
    
    # Branch performance report
    branch_report = transactions.values('branch_code').annotate(
        total_transactions=Count('id'),
        successful=Count('id', filter=Q(payment_status='SUCCESS')),
        failed=Count('id', filter=Q(payment_status='FAILED')),
        total_amount=Sum('amount', filter=Q(payment_status='SUCCESS')),
        avg_amount=Avg('amount', filter=Q(payment_status='SUCCESS'))
    ).order_by('-total_amount')
    
    # Payment method breakdown
    method_report = transactions.values('payment_method').annotate(
        count=Count('id'),
        amount=Sum('amount', filter=Q(payment_status='SUCCESS'))
    ).order_by('-count')
    
    # Daily trend
    daily_trend = transactions.extra(
        select={'day': 'DATE(created_at)'}
    ).values('day').annotate(
        count=Count('id'),
        successful=Count('id', filter=Q(payment_status='SUCCESS')),
        amount=Sum('amount', filter=Q(payment_status='SUCCESS'))
    ).order_by('day')
    
    # Top customers
    top_customers = transactions.filter(
        payment_status='SUCCESS'
    ).values(
        'user__first_name', 'user__last_name', 'user__phone_number'
    ).annotate(
        total_transactions=Count('id'),
        total_amount=Sum('amount')
    ).order_by('-total_amount')[:10]
    
    context = {
        'date_from': date_from,
        'date_to': date_to,
        'branch_report': branch_report,
        'method_report': method_report,
        'daily_trend': list(daily_trend),
        'top_customers': top_customers,
    }
    
    return render(request, 'bancabc/reports.html', context)


@login_required
@user_passes_test(is_staff_or_superuser)
def bancabc_export_csv(request):
    """
    Export transactions to CSV
    """
    # Get filter parameters
    date_from = request.GET.get('date_from')
    date_to = request.GET.get('date_to')
    status = request.GET.get('status')
    branch_code = request.GET.get('branch_code')
    
    # Query transactions
    transactions = ProcessedTransaction.objects.all().select_related('user', 'currency')
    
    if date_from:
        transactions = transactions.filter(created_at__gte=date_from)
    if date_to:
        transactions = transactions.filter(created_at__lte=date_to)
    if status:
        transactions = transactions.filter(payment_status=status)
    if branch_code:
        transactions = transactions.filter(branch_code=branch_code)
    
    transactions = transactions.order_by('-created_at')
    
    # Create CSV response
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="bancabc_transactions_{timezone.now().strftime("%Y%m%d_%H%M%S")}.csv"'
    
    writer = csv.writer(response)
    writer.writerow([
        'BancABC Reference', 'Transaction ID', 'Customer Name', 'Phone Number',
        'Amount', 'Currency', 'Payment Status', 'Payment Method', 'Branch Code',
        'Operator ID', 'Verified', 'Created Date', 'Payment Date', 'Remarks'
    ])
    
    for txn in transactions:
        writer.writerow([
            txn.bancabc_reference or txn.transaction_id,
            txn.bancabc_transaction_id or '',
            f"{txn.user.first_name} {txn.user.last_name}".strip() or txn.user.username,
            getattr(txn.user, 'phone_number', 'N/A'),
            txn.amount,
            txn.currency.code,
            txn.payment_status or txn.status,
            txn.payment_method or '',
            txn.branch_code or '',
            txn.operator_id or '',
            'Yes' if txn.payment_verified else 'No',
            txn.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            txn.payment_date.strftime("%Y-%m-%d %H:%M:%S") if txn.payment_date else '',
            txn.remarks or ''
        ])
    
    return response


@login_required
@user_passes_test(is_staff_or_superuser)
def bancabc_api_stats(request):
    """
    API endpoint for dashboard statistics (AJAX)
    """
    date_from = request.GET.get('date_from', (timezone.now() - timedelta(days=7)).strftime('%Y-%m-%d'))
    date_to = request.GET.get('date_to', timezone.now().strftime('%Y-%m-%d'))
    
    start_date = datetime.strptime(date_from, '%Y-%m-%d')
    end_date = datetime.strptime(date_to, '%Y-%m-%d').replace(hour=23, minute=59, second=59)
    
    transactions = ProcessedTransaction.objects.filter(
        created_at__range=[start_date, end_date]
    )
    
    stats = {
        'total': transactions.count(),
        'successful': transactions.filter(payment_status='SUCCESS').count(),
        'failed': transactions.filter(payment_status='FAILED').count(),
        'pending': transactions.filter(payment_status='PENDING').count(),
        'amount': float(transactions.filter(payment_status='SUCCESS').aggregate(
            total=Sum('amount')
        )['total'] or 0),
        'verified': transactions.filter(payment_verified=True).count(),
        'unverified': transactions.filter(
            payment_status='SUCCESS',
            payment_verified=False
        ).count(),
    }
    
    if stats['total'] > 0:
        stats['success_rate'] = round((stats['successful'] / stats['total']) * 100, 1)
    else:
        stats['success_rate'] = 0
    
    return JsonResponse(stats)


@login_required
@user_passes_test(is_staff_or_superuser)
def bancabc_verify_transaction(request, transaction_id):
    """
    Manually verify a transaction
    """
    if request.method == 'POST':
        try:
            transaction = ProcessedTransaction.objects.get(id=transaction_id)
            transaction.payment_verified = True
            transaction.save()
            
            return JsonResponse({
                'status': 'success',
                'message': 'Transaction verified successfully'
            })
        except ProcessedTransaction.DoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': 'Transaction not found'
            }, status=404)
    
    return JsonResponse({
        'status': 'error',
        'message': 'Invalid request method'
    }, status=405)
