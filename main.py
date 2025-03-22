from fastapi import FastAPI, HTTPException
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.backends import default_backend
from pydantic import BaseModel
import base64
import os

app = FastAPI()

# Dictionary to store keys
keys = {}


# Request Body Models
class KeyRequest(BaseModel):
    key_type: str
    key_size: int


class EncryptRequest(BaseModel):
    key_id: str
    plaintext: str
    algorithm: str


class DecryptRequest(BaseModel):
    key_id: str
    ciphertext: str
    algorithm: str


class HashRequest(BaseModel):
    data: str
    algorithm: str


class VerifyHashRequest(BaseModel):
    data: str
    hash_value: str
    algorithm: str


# Generate Key API
@app.post("/generate-key")
async def generate_key(request: KeyRequest):
    if request.key_type.upper() == "AES":
        key = os.urandom(request.key_size // 8)
        key_value = base64.b64encode(key).decode()
    elif request.key_type.upper() == "RSA":
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=request.key_size,
            backend=default_backend()
        )
        key_value = base64.b64encode(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )).decode()
    else:
        raise HTTPException(status_code=400, detail="Unsupported key type")

    key_id = str(len(keys) + 1)  # Assign numeric key_id (1, 2, 3...)
    keys[key_id] = key  # Store the key in memory
    return {"key_id": key_id, "key_value": key_value}


# Encryption API
@app.post("/encrypt")
async def encrypt(request: EncryptRequest):
    if request.key_id not in keys:
        raise HTTPException(status_code=404, detail="Key not found")

    key = keys[request.key_id]
    if request.algorithm.upper() == "AES":
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_plaintext = padder.update(request.plaintext.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        return {"ciphertext": base64.b64encode(iv + ciphertext).decode()}

    elif request.algorithm.upper() == "RSA":
        if not isinstance(key, rsa.RSAPrivateKey):
            raise HTTPException(status_code=400, detail="Key is not RSA type")
        public_key = key.public_key()
        ciphertext = public_key.encrypt(
            request.plaintext.encode(),
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return {"ciphertext": base64.b64encode(ciphertext).decode()}

    else:
        raise HTTPException(status_code=400, detail="Unsupported algorithm")


# Decryption API
@app.post("/decrypt")
async def decrypt(request: DecryptRequest):
    if request.key_id not in keys:
        raise HTTPException(status_code=404, detail="Key not found")

    key = keys[request.key_id]
    if request.algorithm.upper() == "AES":
        data = base64.b64decode(request.ciphertext)
        iv, encrypted_text = data[:16], data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_text = decryptor.update(encrypted_text) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(decrypted_text) + unpadder.finalize()
        return {"plaintext": plaintext.decode()}

    elif request.algorithm.upper() == "RSA":
        if not isinstance(key, rsa.RSAPrivateKey):
            raise HTTPException(status_code=400, detail="Key is not RSA type")
        ciphertext = base64.b64decode(request.ciphertext)
        plaintext = key.decrypt(
            ciphertext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return {"plaintext": plaintext.decode()}

    else:
        raise HTTPException(status_code=400, detail="Unsupported algorithm")


# Hash Generation API
@app.post("/generate-hash")
async def generate_hash(request: HashRequest):
    if request.algorithm.upper() == "SHA-256":
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    elif request.algorithm.upper() == "SHA-512":
        digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    else:
        raise HTTPException(status_code=400, detail="Unsupported hashing algorithm")

    digest.update(request.data.encode())
    hash_value = digest.finalize()
    return {"hash_value": base64.b64encode(hash_value).decode(), "algorithm": request.algorithm}


# Hash Verification API
@app.post("/verify-hash")
async def verify_hash(request: VerifyHashRequest):
    new_hash = await generate_hash(HashRequest(data=request.data, algorithm=request.algorithm))
    is_valid = new_hash["hash_value"] == request.hash_value
    return {"is_valid": is_valid, "message": "Hash matches the data." if is_valid else "Hash does not match."}
