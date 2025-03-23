
# Cryptographic API Implementation

This project implements a Cryptographic API using FastAPI and the Cryptography library in Python. It supports the following functionalities:

- **Key Generation:**  
  - **AES:** Generates a random symmetric key.
  - **RSA:** Generates an RSA private key and returns it in PEM format.
- **Encryption/Decryption:**  
  - **AES Encryption:** Uses AES in CBC mode with PKCS7 padding.
  - **RSA Encryption:** Uses OAEP padding with SHA-256.
- **Hashing & Verification:**  
  - Generates a hash using SHA-256 or SHA-512.
  - Verifies if the provided hash matches the data.

## Table of Contents

- [Overview](#overview)
- [Implementation Details](#implementation-details)
- [Installation and Setup](#installation-and-setup)
  - [Using Virtual Environment (venv)](#using-virtual-environment-venv)
  - [Using Conda](#using-conda)
- [Running the API Locally](#running-the-api-locally)
- [API Endpoints](#api-endpoints)
- [Testing the API](#testing-the-api)
- [Deployment](#deployment)
- [Notes](#notes)


## Overview

This project was developed as part of the milestone requirements for a cryptographic API implementation assignment. It offers endpoints for key generation, encryption/decryption, hash generation, and hash verification.

## Implementation Details

- **Key Generation:**  
  - **AES:** Generates a key using `os.urandom` based on the specified key size.
  - **RSA:** Uses the RSA algorithm to generate a private key. The key is then serialized to PEM format and encoded in Base64.
- **Encryption & Decryption:**  
  - **AES:** Utilizes CBC mode with PKCS7 padding.
  - **RSA:** Encrypts data using the RSA public key with OAEP padding (SHA-256 is used for both the mask generation function and the algorithm).
- **Hashing & Verification:**  
  - Supports SHA-256 and SHA-512 hashing.
  - Verifies data integrity by comparing the computed hash with a provided hash.

## Installation and Setup

### Using Virtual Environment (venv)

1. **Clone the Repository:**
   ```bash
   git clone <repository_url>
   cd <repository_directory>
   ```

2. **Create a Virtual Environment:**
   ```bash
   python -m venv venv
   ```

3. **Activate the Virtual Environment:**
   - **Windows:**
     ```bash
     venv\Scripts\activate
     ```
   - **macOS/Linux:**
     ```bash
     source venv/bin/activate
     ```

4. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

### Using Conda

1. **Clone the Repository:**
   ```bash
   git clone <repository_url>
   cd <repository_directory>
   ```

2. **Create a Conda Environment:**
   ```bash
   conda create -n crypto_api python=3.9
   ```

3. **Activate the Conda Environment:**
   ```bash
   conda activate crypto_api
   ```

4. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Running the API Locally

After installing the dependencies, run the API server using Uvicorn:

```bash
uvicorn main:app --reload --port 8000
```

Now the API will be available at:  
```
http://127.0.0.1:8000
```

## API Endpoints

### 1. Generate Key

- **Endpoint:** `POST /generate-key`
- **Request Body:**
  ```json
  {
      "key_type": "AES",
      "key_size": 256
  }
  ```
  For RSA, use:
  ```json
  {
      "key_type": "RSA",
      "key_size": 2048
  }
  ```
- **Response:**
  ```json
  {
      "key_id": "1",
      "key_value": "base64-encoded-key"
  }
  ```

### 2. Encrypt

- **Endpoint:** `POST /encrypt`
- **Request Body:**
  ```json
  {
      "key_id": "1",
      "plaintext": "Hello, World!",
      "algorithm": "AES"
  }
  ```
  For RSA encryption, set `"algorithm": "RSA"`.
- **Response:**
  ```json
  {
      "ciphertext": "base64-encoded-ciphertext"
  }
  ```

### 3. Decrypt

- **Endpoint:** `POST /decrypt`
- **Request Body:**
  ```json
  {
      "key_id": "1",
      "ciphertext": "base64-encoded-ciphertext",
      "algorithm": "AES"
  }
  ```
  For RSA decryption, set `"algorithm": "RSA"`.
- **Response:**
  ```json
  {
      "plaintext": "original message"
  }
  ```

### 4. Generate Hash

- **Endpoint:** `POST /generate-hash`
- **Request Body:**
  ```json
  {
      "data": "Hello, World!",
      "algorithm": "SHA-256"
  }
  ```
- **Response:**
  ```json
  {
      "hash_value": "base64-encoded-hash",
      "algorithm": "SHA-256"
  }
  ```

### 5. Verify Hash

- **Endpoint:** `POST /verify-hash`
- **Request Body:**
  ```json
  {
      "data": "Hello, World!",
      "hash_value": "base64-encoded-hash",
      "algorithm": "SHA-256"
  }
  ```
- **Response:**
  ```json
  {
      "is_valid": true,
      "message": "Hash matches the data."
  }
  ```

## Testing the API

You can test these endpoints using Postman. Use the raw JSON provided above for each endpoint to verify the functionality of this API.

You can also test these endpoints using the following URL:
<!-- ## Deployment

To deploy this API publicly (for example, on Heroku), follow these steps:

1. **Prepare Deployment Files:**
   - **Procfile:** Create a file named `Procfile` with:
     ```
     web: uvicorn main:app --host=0.0.0.0 --port=${PORT:-5000}
     ```
   - **requirements.txt:** Ensure all dependencies are listed.

2. **Deploy to Heroku:**
   - **Login to Heroku:**
     ```bash
     heroku login
     ```
   - **Create a New Heroku App:**
     ```bash
     heroku create your-app-name
     ```
   - **Push the Code to Heroku:**
     ```bash
     git push heroku main
     ```
   - **Access the API:**  
     Your API will be accessible at `https://your-app-name.herokuapp.com`. -->

## Notes

- **Key Storage:**  
  Keys are stored in memory (for demo purposes). For production, consider using persistent storage.

