from django.core.mail import send_mail, EmailMessage  # add EmailMessage import
from django.template.loader import render_to_string
from django.conf import settings
import logging
import re  # import re for regular expression
import os

logger = logging.getLogger(__name__)

class EmailService:
    @staticmethod
    def send_credit_booking_notification(booking_data, bank_email, admin_email, pdf_file=None):
        try:
            # Build a publicly reachable logo URL if FRONTEND_BASE_URL is configured.
            frontend_base = getattr(settings, 'FRONTEND_BASE_URL', '') or ''
            frontend_base = frontend_base.rstrip('/') if frontend_base else ''
            # Default to an expected public path under the frontend dist; may be empty if not configured.
            logo_url = f"{frontend_base}/lovable-uploads/fastjet-logo.png" if frontend_base else ''

            # Ensure some commonly used formatted fields exist so templates can render nicely.
            try:
                if 'base_amount' in booking_data and booking_data['base_amount'] is not None:
                    booking_data['base_amount_formatted'] = f"{booking_data.get('currency','') } {booking_data['base_amount']}"
                if 'total_amount' in booking_data and booking_data['total_amount'] is not None:
                    booking_data['total_amount_formatted'] = f"{booking_data.get('currency','') } {booking_data['total_amount']}"
            except Exception:
                # best-effort only
                pass
            # Admin notification
            admin_subject = f"New Credit Booking Application - Ref: {booking_data['reference']}"
            admin_html = render_to_string('emails/admin_credit_booking.html', {
                'booking': booking_data,
                'logo_url': logo_url,
            })
            # Provide a plain-text version to avoid being blocked by strict email policies
            admin_text = re.sub(r'<[^>]+>', '', admin_html)
            # Build email with attachment support
            msg = EmailMessage(
                subject=admin_subject,
                body=admin_text,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[admin_email]
            )
            msg.attach_alternative(admin_html, "text/html")
            # Attach provided PDF if available
            if pdf_file:
                pdf_name = getattr(pdf_file, 'name', f"booking_{booking_data['reference']}.pdf")
                msg.attach(pdf_name, pdf_file.read(), 'application/pdf')
            msg.send(fail_silently=False)

            # Bank notification
            bank_subject = f"FastJet Credit Application - {booking_data['customer_name']} - Ref: {booking_data['reference']}"
            bank_html = render_to_string('emails/bank_credit_booking.html', {
                'booking': booking_data,
                'logo_url': logo_url,
            })
            # Provide plain-text fallback and send simple notification (no PDF)
            bank_text = re.sub(r'<[^>]+>', '', bank_html)
            send_mail(
                subject=bank_subject,
                message=bank_text,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[bank_email],
                html_message=bank_html,
                fail_silently=False,
            )

            return True, "Notifications sent successfully"
            
        except Exception as e:
            logger.error(f"Failed to send credit booking notifications: {str(e)}")
            return False, str(e)

    @staticmethod
    def send_existing_pdf(recipient_email, subject, body_html=None, pdf_relative_path=None):
        """Send an email to recipient_email attaching a PDF stored under MEDIA_ROOT.

        - pdf_relative_path: path relative to settings.MEDIA_ROOT (e.g. 'documents/vat_certificates/letter_head.pdf').
          If not provided, the method will try a sensible default: 'documents/vat_certificates/letter_head.pdf'.
        - body_html: optional HTML body; if provided a plain-text fallback is generated.
        Returns (True, msg) on success or (False, error_str) on failure.
        """
        try:
            if not pdf_relative_path:
                pdf_relative_path = os.path.join('documents', 'vat_certificates', 'letter_head.pdf')

            # Resolve full file path using MEDIA_ROOT if available, else BASE_DIR/media
            media_root = getattr(settings, 'MEDIA_ROOT', None)
            if media_root:
                pdf_path = os.path.join(media_root, pdf_relative_path)
            else:
                base_dir = getattr(settings, 'BASE_DIR', None)
                if base_dir:
                    pdf_path = os.path.join(base_dir, 'media', pdf_relative_path)
                else:
                    pdf_path = pdf_relative_path

            if not os.path.isfile(pdf_path):
                err = f"PDF not found at path: {pdf_path}"
                logger.error(err)
                return False, err

            # Prepare email
            text_body = ''
            if body_html:
                text_body = re.sub(r'<[^>]+>', '', body_html)
            else:
                text_body = 'Please find the attached PDF.'

            msg = EmailMessage(
                subject=subject,
                body=text_body,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[recipient_email]
            )
            if body_html:
                msg.attach_alternative(body_html, 'text/html')

            with open(pdf_path, 'rb') as f:
                pdf_data = f.read()
                pdf_name = os.path.basename(pdf_path)
                msg.attach(pdf_name, pdf_data, 'application/pdf')

            msg.send(fail_silently=False)
            return True, f"Email sent to {recipient_email} with attachment {pdf_name}"

        except Exception as e:
            logger.error(f"Failed to send existing PDF: {str(e)}")
            return False, str(e)
