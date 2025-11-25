PyCrypt

## Overview

PyCrypt is a Django-based web application that allows users to securely encrypt and decrypt files using RSA and AES encryption algorithms. Users can generate RSA key pairs, encrypt files with a public key, and decrypt files with a private key.

## Features

- **RSA Key Generation**: Generate RSA public and private key pairs.
- **File Encryption**: Encrypt files using a combination of RSA and AES encryption.
- **File Decryption**: Decrypt files using the corresponding RSA private key.
- **File Download**: Download encrypted and decrypted files.

## Installation

1. **Create a `.env` file from the example:**

    ```sh
    cp .env.example .env
    ```

2. **Run the docker containers:**

    ```sh
    docker-compose up -d
    ```

3. **Run migrations:**

    ```sh
    docker-compose exec django python manage.py migrate
    ```

4. **Access the application:**

    Open your web browser and navigate to `localhost`.

## Usage

### Generate Keys

1. Navigate to the "Generate Keys" page.
2. Click the "Generate Keys" button.
3. It downloads the generated ZIP file containing your public and private keys.

### Encrypt a File

1. Navigate to the "Encrypt File" page.
2. Upload the file you want to encrypt.
3. Upload the public key of the receiver for encryption.
4. Click the "Encrypt File" button.
5. Download the encrypted file.

### Decrypt a File

1. Navigate to the "Decrypt File" page.
2. Upload the file you want to decrypt.
3. Upload the private key for decryption.
4. Click the "Decrypt File" button.
5. Download the decrypted file.

