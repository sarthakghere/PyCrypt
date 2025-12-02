from django.shortcuts import render, redirect
from django.http import HttpResponse
from .forms import FileEncryptForm, FileDecryptForm
from util.models import EncryptedFile


# Create your views here.
def index(request):
    return render(request, 'ui/index.html')

def encrypt_ui(request):
    form = FileEncryptForm()
    return render(request, 'ui/encrypt.html', {'form': form})

def success(request):
    encrypted_file_id = request.session.pop('encrypted_file_id', None)
    decrypted_file_path = request.session.pop('decrypted_file_path', None)

    context = {'encrypted_file_id': encrypted_file_id,
               'decrypted_file_path': decrypted_file_path}
    return render(request, 'ui/success.html', context)

def decrypt_ui(request):
    form = FileDecryptForm()
    return render(request, 'ui/decrypt.html', {'form': form})
