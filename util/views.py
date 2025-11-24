from django.shortcuts import render, redirect
from django.http import FileResponse
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.core.files.storage import FileSystemStorage
import os
import shutil
import datetime
import logging
from django.conf import settings
from ui.forms import FileEncryptForm, FileDecryptForm
from .tasks import send_email_task, cleanup_files_task

# Create your views here.
def generate_keys(request):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    now = datetime.datetime.now()
    directory = f'util/media/keys/user_keys_{now.strftime("%Y%m%d%H%M%S")}'
    public_key = private_key.public_key()
    
    private_key_path = os.path.join(directory, 'private_key.pem')
    public_key_path = os.path.join(directory, 'public_key.pem')

    os.makedirs(directory, exist_ok=True)

    # Save the private key
    with open(f"{private_key_path}", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save the public key
    with open(f"{public_key_path}", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    zip_file_path = f"{directory}.zip"
    shutil.make_archive(directory, 'zip', directory)
    
    # Schedule the cleanup of the directory
    cleanup_files_task.apply_async(args=[directory], countdown=10)

    # Set the file path to be deleted after the response
    request.delete_after_response = zip_file_path
    
    return FileResponse(open(zip_file_path, 'rb'), content_type='application/zip')

def encrypt(request):
    if request.method == 'POST':
        form = FileEncryptForm(request.POST, request.FILES)
        if form.is_valid():
            file = form.cleaned_data['file']
            public_key = form.cleaned_data['publicKey']
            email = form.cleaned_data['email']

            fs = FileSystemStorage()
            file_name = fs.save(file.name, file)
            public_key_name = fs.save(public_key.name, public_key)
            
            # Encrypt the file
            encrypt_file_path = encrypt_file(file_name, public_key_name)
            
            # Send the encrypted file via email
            send_email_task.delay(email, encrypt_file_path)

            # Save the path to the encrypted file in the session
            request.session['encrypted_file_path'] = encrypt_file_path
            
            # Redirect to the success page
            return redirect('ui:success')
    return redirect('ui:encrypt')

def encrypt_file(file_name, public_key_name):
    media_path = 'media/'
    
    with open(os.path.join(media_path, public_key_name), "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    # Generate a random AES key
    aes_key = AESGCM.generate_key(bit_length=256)

    # Encrypt the AES key with the recipient's public key
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Read the file data
    with open(os.path.join(media_path, file_name), "rb") as f:
        file_data = f.read()

    # Encrypt the file data with the AES key
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    encrypted_data = aesgcm.encrypt(nonce, file_data, None)

    # Save the encrypted AES key, nonce, original file extension, and encrypted data to the output file
    encrypt_file_directory = 'util/media/encrypted_files'
    os.makedirs(encrypt_file_directory, exist_ok=True)
    original_file_extension = os.path.splitext(file_name)[1]  # Get the file extension
    encrypt_file_path = os.path.join(encrypt_file_directory, f'{os.path.splitext(file_name)[0]}.enc')
    with open(encrypt_file_path, "wb") as f:
        # Write the encrypted AES key, nonce, and original file extension length
        f.write(encrypted_aes_key + nonce + len(original_file_extension.encode()).to_bytes(1, 'big'))
        # Write the original file extension
        f.write(original_file_extension.encode())
        # Write the encrypted data
        f.write(encrypted_data)
    
    # Schedule the cleanup of the media directory
    cleanup_files_task.apply_async(args=[media_path], countdown=3600)

    return encrypt_file_path

def decrypt(request):
    if request.method == 'POST':
        form = FileDecryptForm(request.POST, request.FILES)
        if form.is_valid():
            file = form.cleaned_data['file']
            private_key = form.cleaned_data['privateKey']

            fs = FileSystemStorage()
            file_name = fs.save(file.name, file)
            private_key_name = fs.save(private_key.name, private_key)
            
            # Decrypt the file
            decrypt_file_path = decrypt_file(file_name, private_key_name)
            
            # Save the path to the decrypted file in the session
            request.session['decrypted_file_path'] = decrypt_file_path
            
            # Redirect to the success page
            return redirect('ui:success')
    return redirect('ui:decrypt')

def decrypt_file(file_name, private_key_name):
    try:
        media_path = 'media/'
        encrypted_file_path = os.path.join(media_path, file_name)
        logging.debug(f'Encrypted file path: {encrypted_file_path}')

        with open(os.path.join(media_path, private_key_name), "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None)

        with open(encrypted_file_path, "rb") as f:
            encrypted_aes_key = f.read(private_key.key_size // 8)
            nonce = f.read(12)
            original_file_extension_length = int.from_bytes(f.read(1), 'big')
            original_file_extension = f.read(original_file_extension_length).decode()
            encrypted_data = f.read()
        
        logging.debug(f'Encrypted AES key: {encrypted_aes_key}')
        logging.debug(f'Nonce: {nonce}')
        logging.debug(f'Original file extension: {original_file_extension}')
        logging.debug(f'Encrypted data length: {len(encrypted_data)}')

        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        aesgcm = AESGCM(aes_key)
        decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)

        decrypted_file_directory = 'util/media/decrypted_files'
        os.makedirs(decrypted_file_directory, exist_ok=True)
        decrypted_file_path = os.path.join(decrypted_file_directory, f'decrypted_{os.path.basename(file_name).replace(".enc", original_file_extension)}')
        with open(decrypted_file_path, "wb") as f:
            f.write(decrypted_data)

        # Schedule the cleanup of the media directory
        cleanup_files_task.apply_async(args=[media_path], countdown=3600)
        return decrypted_file_path
    except Exception as e:
        logging.error(f"Decryption failed: {e}")
        raise

def download_file(request):
    file_path = request.GET.get('file')
    if file_path and os.path.exists(file_path):
        request.delete_after_response = file_path
        return FileResponse(open(file_path, 'rb'), as_attachment=True, filename=os.path.basename(file_path))
    else:
        return redirect('ui:success')
