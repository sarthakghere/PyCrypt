from __future__ import absolute_import, unicode_literals
from celery import shared_task
from django.core.mail import EmailMessage
from django.conf import settings
import logging
import os
import shutil

@shared_task
def send_email_task(email, file_path):
    """
    A Celery task to send an email with an attachment.
    """
    try:
        email_subject = "Your Encrypted File"
        email_body = "Please find your encrypted file attached."
        email_message = EmailMessage(
            email_subject,
            email_body,
            settings.EMAIL_HOST_USER,
            [email],
        )
        email_message.attach_file(file_path)
        email_message.send(fail_silently=False)
        logging.info(f"Successfully sent encrypted file to {email}")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")

@shared_task
def cleanup_files_task(path_to_delete):
    """
    A Celery task to clean up files or directories.
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
