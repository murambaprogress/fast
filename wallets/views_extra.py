
@api_view(['GET'])
@permission_classes([AllowAny])
def innbucks_simulate_scan(request, innbucks_code, transaction_id):
    """
    Simulates a QR code scan and marks the payment as complete.
    This is only for demo purposes and will display a success page when the QR code is scanned.
    """
    try:
        # Find the processed transaction
        processed_txn = ProcessedTransaction.objects.filter(
            transaction_id=transaction_id,
            bancabc_transaction_id=innbucks_code,  # We stored the innbucks code here
            status='processing'
        ).first()

        if not processed_txn:
            html_content = """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>FastJet InnBucks Payment</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 0; padding: 20px; text-align: center; background-color: #f7f7f7; }
                    .container { max-width: 500px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                    .error { color: #d9534f; }
                    h1 { color: #333; }
                    p { color: #555; line-height: 1.5; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1 class="error">Transaction Not Found</h1>
                    <p>The payment could not be processed because the transaction was not found or has already been completed.</p>
                    <p>Please close this window and try again.</p>
                </div>
            </body>
            </html>
            """
            return HttpResponse(html_content, content_type='text/html')

        # Mark transaction as "Claimed" to simulate payment in progress
        processed_txn.response_data = processed_txn.response_data or {}
        processed_txn.response_data['payment_status'] = 'Claimed'
        processed_txn.response_data['scanned_at'] = timezone.now().isoformat()
        processed_txn.save()
        
        # Return a nice HTML page that redirects back to the app after a few seconds
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>FastJet InnBucks Payment</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; text-align: center; background-color: #f7f7f7; }
                .container { max-width: 500px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                .success { color: #5cb85c; }
                h1 { color: #333; }
                p { color: #555; line-height: 1.5; }
                .spinner { 
                    border: 5px solid #f3f3f3; 
                    border-top: 5px solid #5cb85c; 
                    border-radius: 50%;
                    width: 40px;
                    height: 40px;
                    animation: spin 1s linear infinite;
                    margin: 20px auto;
                }
                @keyframes spin {
                    0% { transform: rotate(0deg); }
                    100% { transform: rotate(360deg); }
                }
                .logo {
                    max-width: 150px;
                    margin-bottom: 20px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1 class="success">Payment in Progress</h1>
                <div class="spinner"></div>
                <p>Your InnBucks payment is being processed.</p>
                <p>Please wait while we complete your transaction...</p>
                <p><strong>Amount:</strong> """ + str(processed_txn.amount) + " " + processed_txn.currency.code + """</p>
                <p><strong>Reference:</strong> """ + transaction_id + """</p>
                <p><small>You can close this window and return to the FastJet app.</small></p>
            </div>
            <script>
                // After 5 seconds, we'll mark this transaction as paid
                setTimeout(function() {
                    fetch('/api/wallets/innbucks/check-status/', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            'innbucks_code': '""" + innbucks_code + """',
                            'transaction_id': '""" + transaction_id + """'
                        })
                    });
                }, 5000);
            </script>
        </body>
        </html>
        """
        return HttpResponse(html_content, content_type='text/html')

    except Exception as e:
        logger.error(f"InnBucks simulate scan error: {str(e)}")
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>FastJet InnBucks Payment</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; text-align: center; background-color: #f7f7f7; }
                .container { max-width: 500px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                .error { color: #d9534f; }
                h1 { color: #333; }
                p { color: #555; line-height: 1.5; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1 class="error">Error Processing Payment</h1>
                <p>There was an error processing your payment. Please try again or contact support.</p>
                <p>Error reference: """ + str(timezone.now().timestamp()) + """</p>
            </div>
        </body>
        </html>
        """
        return HttpResponse(html_content, content_type='text/html')