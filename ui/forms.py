from django import forms

class FileEncryptForm(forms.Form):
    file = forms.FileField(label='File to encrypt', required=True)
    publicKey = forms.FileField(label='Receiver\'s Public Key', required=True)
    owner_email = forms.EmailField(label='Your Email', required=True)
    recipient_email = forms.EmailField(label='Recipient Email (Optional)', required=False, help_text='Optional: Enter email to send the encrypted file.', empty_value=None, )

class FileDecryptForm(forms.Form):
    file = forms.FileField(label='File to decrypt')
    privateKey = forms.FileField(label='Your Private Key')
