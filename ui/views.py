from django.shortcuts import render, redirect
from django.http import HttpResponse
from .forms import FileEncryptForm, FileDecryptForm


# Create your views here.
def index(request):
    return render(request, 'ui/index.html')

def encrypt_ui(request):
    form = FileEncryptForm()
    return render(request, 'ui/encrypt.html', {'form': form})

def success(request):
    encrypted_file_path = request.session.get('encrypted_file_path')
    decrypted_file_path = request.session.get('decrypted_file_path')
    context = {'encrypted_file_path': encrypted_file_path,
               'decrypted_file_path': decrypted_file_path}
    return render(request, 'ui/success.html', context)

def decrypt_ui(request):
    form = FileDecryptForm()
    return render(request, 'ui/decrypt.html', {'form': form})
