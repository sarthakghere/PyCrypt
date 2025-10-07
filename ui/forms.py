from django import forms

class FileEncryptForm(forms.Form):
    file = forms.FileField(label='File to encrypt')
    publicKey = forms.FileField(label='Receiver\'s Public Key')
    email = forms.EmailField(label='Recipient Email')

class FileDecryptForm(forms.Form):
    file = forms.FileField(label='File to decrypt')
    privateKey = forms.FileField(label='Your Private Key')
