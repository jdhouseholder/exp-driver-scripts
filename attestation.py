import os
import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


def generate_keys(private_key_path: str):
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    if os.path.exists(private_key_path):
        pass
    else:
        with open(private_key_path, "wb") as f:
            f.write(pem_private)

    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open("public_key.pem", "wb") as f:
        f.write(pem_public)


def create_canonical_data(request: dict, response: dict) -> bytes:
    data_to_sign = {"request": request, "response": response}
    canonical_json = json.dumps(data_to_sign, sort_keys=True, separators=(",", ":"))
    return canonical_json.encode("utf-8")


def sign_data(private_key_path: str, bytes) -> str:
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    signature = private_key.sign(data)
    return base64.urlsafe_b64encode(signature).decode("utf-8")


def verify_signature(public_key_path: str, signature_b64: str, bytes) -> bool:
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    try:
        signature_bytes = base64.urlsafe_b64decode(signature_b64)
        public_key.verify(signature_bytes, data)
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        return False
