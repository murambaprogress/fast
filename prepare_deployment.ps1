# BancABC Integration - Deployment Preparation Script
# This script prepares the system for cloud deployment

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  FASTJET BANCABC - DEPLOYMENT PREPARATION" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Check Python environment
Write-Host "[1/8] Checking Python environment..." -ForegroundColor Yellow
python --version
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Python not found!" -ForegroundColor Red
    exit 1
}
Write-Host "✓ Python detected" -ForegroundColor Green
Write-Host ""

# Step 2: Install/Update dependencies
Write-Host "[2/8] Installing dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt --quiet
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Dependencies installed" -ForegroundColor Green
} else {
    Write-Host "⚠ Warning: Some dependencies may have failed" -ForegroundColor Yellow
}
Write-Host ""

# Step 3: Create migrations for updated models
Write-Host "[3/8] Creating database migrations..." -ForegroundColor Yellow
python manage.py makemigrations wallets
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Migrations created" -ForegroundColor Green
} else {
    Write-Host "⚠ No new migrations needed or error occurred" -ForegroundColor Yellow
}
Write-Host ""

# Step 4: Show migration plan
Write-Host "[4/8] Showing migration plan..." -ForegroundColor Yellow
python manage.py showmigrations wallets
Write-Host ""

# Step 5: Collect static files
Write-Host "[5/8] Collecting static files..." -ForegroundColor Yellow
python manage.py collectstatic --noinput
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Static files collected" -ForegroundColor Green
} else {
    Write-Host "⚠ Static collection failed" -ForegroundColor Yellow
}
Write-Host ""

# Step 6: Check for missing migrations
Write-Host "[6/8] Checking for unapplied migrations..." -ForegroundColor Yellow
python manage.py migrate --check
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ All migrations are up to date" -ForegroundColor Green
} else {
    Write-Host "⚠ There are unapplied migrations" -ForegroundColor Yellow
    Write-Host "Run 'python manage.py migrate' on production server" -ForegroundColor Cyan
}
Write-Host ""

# Step 7: Run system checks
Write-Host "[7/8] Running Django system checks..." -ForegroundColor Yellow
python manage.py check --deploy
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ System checks passed" -ForegroundColor Green
} else {
    Write-Host "⚠ System checks found issues" -ForegroundColor Yellow
}
Write-Host ""

# Step 8: Generate deployment checklist
Write-Host "[8/8] Generating deployment checklist..." -ForegroundColor Yellow

$checklist = @"
============================================
   DEPLOYMENT CHECKLIST - BANCABC INTEGRATION
============================================

PRE-DEPLOYMENT:
--------------
□ Update .env file on production server
  - BASE_URL=https://fastjet.pythonanywhere.com
  - BANCABC_API_KEY=bancabc_prod_2024_7f8e9d2a1b3c4e5f
  - BANCABC_SECRET_KEY=sk_bancabc_hmac_9x8y7z6w5v4u3t2s1r0q
  
□ Database configuration
  - Update DATABASES settings for production MySQL
  - Ensure remote database is accessible
  
□ Security settings
  - DEBUG=False in settings.py
  - Update ALLOWED_HOSTS
  - Configure CORS settings
  
□ SSL/HTTPS
  - Ensure SSL certificate is valid
  - Force HTTPS in production

DEPLOYMENT STEPS:
----------------
1. Upload code to PythonAnywhere:
   - Upload all files via Git or Files tab
   - Or use: git push origin main

2. Run migrations on production:
   python manage.py migrate

3. Create superuser (if not exists):
   python manage.py createsuperuser

4. Collect static files:
   python manage.py collectstatic --noinput

5. Reload web app:
   - Click "Reload" button in PythonAnywhere Web tab

POST-DEPLOYMENT:
---------------
□ Test all 4 BancABC APIs:
  ✓ POST /api/wallets/bancabc/wallet/validate/
  ✓ POST /api/wallets/bancabc/payment/notify/
  ✓ POST /api/wallets/bancabc/wallet/credit/
  ✓ GET  /api/wallets/bancabc/transactions/report/

□ Access Admin Interface:
  - URL: https://fastjet.pythonanywhere.com/admin/
  - Navigate to: Wallets > Processed Transactions
  - Verify BancABC transaction dashboard

□ Test with BancABC credentials:
  - Username: bancabc_api_user
  - API Key: bancabc_prod_2024_7f8e9d2a1b3c4e5f
  - Secret Key: sk_bancabc_hmac_9x8y7z6w5v4u3t2s1r0q

□ Monitor logs:
  - Check error logs for any issues
  - Monitor transaction processing
  - Review rate limiting

□ Share with BancABC:
  - Send BANCABC_API_DOCUMENTATION.md
  - Provide production credentials
  - Share test customer: +263784454242

ADMIN INTERFACE FEATURES:
------------------------
✓ Transaction Dashboard
  - View all BancABC transactions
  - Filter by status, branch, date
  - Search by customer, reference

✓ Reports
  - Export to CSV
  - Branch performance reports
  - Transaction summaries
  - Success/failure rates

✓ Notifications
  - Payment status alerts
  - Failed transaction notices
  - Reconciliation reports

✓ Management Actions
  - Verify payments manually
  - Mark as reconciled
  - Send status notifications
  - Generate branch reports

MONITORING:
----------
□ Set up monitoring for:
  - API response times
  - Success/failure rates
  - Rate limit violations
  - Payment verification delays

□ Daily reconciliation:
  - Compare BancABC records with Fastjet
  - Review failed transactions
  - Generate daily reports

SUPPORT:
-------
- Technical Support: murambaprogress@gmail.com
- Admin URL: https://fastjet.pythonanywhere.com/admin/
- API Base: https://fastjet.pythonanywhere.com/api/wallets/bancabc

============================================
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
============================================
"@

$checklist | Out-File -FilePath "DEPLOYMENT_CHECKLIST.txt" -Encoding UTF8
Write-Host "✓ Deployment checklist created: DEPLOYMENT_CHECKLIST.txt" -ForegroundColor Green
Write-Host ""

# Summary
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  DEPLOYMENT PREPARATION COMPLETE" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "1. Review DEPLOYMENT_CHECKLIST.txt" -ForegroundColor White
Write-Host "2. Update production .env file" -ForegroundColor White
Write-Host "3. Push code to production server" -ForegroundColor White
Write-Host "4. Run migrations on production" -ForegroundColor White
Write-Host "5. Test BancABC APIs" -ForegroundColor White
Write-Host "6. Access admin at /admin/" -ForegroundColor White
Write-Host ""
Write-Host "Admin Features Available:" -ForegroundColor Yellow
Write-Host "• Transaction monitoring dashboard" -ForegroundColor White
Write-Host "• CSV export for reconciliation" -ForegroundColor White
Write-Host "• Branch performance reports" -ForegroundColor White
Write-Host "• Payment verification tools" -ForegroundColor White
Write-Host "• Real-time status tracking" -ForegroundColor White
Write-Host ""
Write-Host "Ready for deployment! 🚀" -ForegroundColor Green
