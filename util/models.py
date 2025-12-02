from django.db import models

# Create your models here.
class EncryptedFile(models.Model):

    class Status(models.TextChoices):
        ACTIVE = 'active', 'Active'
        DELETED = 'deleted', 'Deleted'

    file = models.FileField(upload_to='encrypted_files/', verbose_name="Encrypted File", null=True, blank=True)
    owner_email = models.EmailField(null=False, blank=False, verbose_name="Owner Email")
    uploaded_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=50, verbose_name="File Status", choices=Status.choices)
    
    def __str__(self):
        return f"Encrypted File {self.id}: {self.status}"
    
class EmailLog(models.Model):
    recipient = models.EmailField(null=False, blank=False, verbose_name="Recipient Email")
    encrypted_file = models.ForeignKey(EncryptedFile, on_delete=models.CASCADE, verbose_name="Associated Encrypted File", related_name='email_logs')
    sent_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=50, verbose_name="Email Status")

    def __str__(self):
        return f"Email to {self.recipient} at {self.sent_at}"