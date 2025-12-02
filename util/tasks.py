from __future__ import absolute_import, unicode_literals
from celery import shared_task
from django.core.mail import EmailMessage
from django.conf import settings
import logging
import os
import shutil
from .models import EncryptedFile, EmailLog


@shared_task
def send_email_task(email, encrypted_file_id):
    """
    Send an email with an attachment and log the result.
    """
    try:
        encrypted_file = EncryptedFile.objects.get(pk=encrypted_file_id)
        file_path = encrypted_file.file.path  # FileField path

        email_subject = "Your Encrypted File"
        email_body = f"Please find your encrypted file attached.\nFrom: {encrypted_file.owner_email}"
        email_message = EmailMessage(
            email_subject,
            email_body,
            settings.EMAIL_HOST_USER,
            [email],
            cc=[encrypted_file.owner_email],
        )
        email_message.attach_file(file_path)
        email_message.send(fail_silently=False)

        EmailLog.objects.create(
            recipient=email,
            encrypted_file=encrypted_file,
            status="sent",
        )
        logging.info(f"Successfully sent encrypted file to {email}")

    except Exception as e:
        logging.error(f"Failed to send email: {e}")
        try:
            encrypted_file = EncryptedFile.objects.get(pk=encrypted_file_id)
            EmailLog.objects.create(
                recipient=email,
                encrypted_file=encrypted_file,
                status=f"failed: {str(e)}",
            )
        except EncryptedFile.DoesNotExist:
            logging.error(
                f"EncryptedFile {encrypted_file_id} not found while logging email failure."
            )


@shared_task
def cleanup_encrypted_file_task(encrypted_file_id):
    """
    Delete the encrypted file from disk and mark it as DELETED.
    """
    try:
        encrypted_file = EncryptedFile.objects.get(pk=encrypted_file_id)
        file_path = encrypted_file.file.path

        if os.path.exists(file_path):
            os.remove(file_path)
            logging.info(f"Deleted encrypted file: {file_path}")
        else:
            logging.warning(f"Encrypted file not found on disk: {file_path}")

        # Update DB status
        encrypted_file.status = EncryptedFile.Status.DELETED
        encrypted_file.save(update_fields=["status"])
        logging.info(f"Marked EncryptedFile {encrypted_file_id} as DELETED")

    except EncryptedFile.DoesNotExist:
        logging.warning(f"EncryptedFile {encrypted_file_id} does not exist")
    except Exception as e:
        logging.error(f"Failed to cleanup EncryptedFile {encrypted_file_id}: {e}")


@shared_task
def cleanup_files_task(path_to_delete):
    """
    Generic cleanup for directories / files (e.g., temp keys, temp decrypted file).
    """
    try:
        if os.path.isdir(path_to_delete):
            shutil.rmtree(path_to_delete)
            logging.info(f"Successfully deleted directory: {path_to_delete}")
        elif os.path.isfile(path_to_delete):
            os.remove(path_to_delete)
            logging.info(f"Successfully deleted file: {path_to_delete}")
    except Exception as e:
        logging.error(f"Failed to clean up path {path_to_delete}: {e}")
