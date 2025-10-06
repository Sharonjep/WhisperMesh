import os, base64, json, uuid
from typing import Tuple, Any, Dict
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


def base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

def unbase64url(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)


def is_uuid(s: str) -> bool:
    try:
        uuid.UUID(str(s))
        return True
    except Exception:
        return False

def ensure_uuid(s: str) -> str:
    """
    Return lowercase UUID if 's' is already a UUID; otherwise generate a fresh UUIDv4.
    Empty strings also get a fresh UUID.
    """
    s = (s or "").strip().lower()
    return s if is_uuid(s) else str(uuid.uuid4())


def _key_paths(user_id: str) -> Tuple[str, str]:
    os.makedirs("keys", exist_ok=True)
    return f"keys/{user_id}_priv.pem", f"keys/{user_id}_pub.pem"

def get_or_create_user_keys(user_id: str) -> Tuple[RSAPrivateKey, RSAPublicKey]:
    priv_p, pub_p = _key_paths(user_id)
    if not (os.path.exists(priv_p) and os.path.exists(pub_p)):
        priv = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        pub = priv.public_key()
        with open(priv_p, "wb") as f:
            f.write(priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(pub_p, "wb") as f:
            f.write(pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    return load_user_keys(user_id)

def load_user_keys(user_id: str) -> Tuple[RSAPrivateKey, RSAPublicKey]:
    priv_p, pub_p = _key_paths(user_id)
    with open(priv_p, "rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=None)
    with open(pub_p, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())
    return priv, pub

def pub_to_b64url_der(pub: RSAPublicKey) -> str:
    der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64url(der)

def b64url_der_to_pub(b64: str) -> RSAPublicKey:
    der = unbase64url(b64)
    return serialization.load_der_public_key(der)

def rsa_encrypt(pub: RSAPublicKey, plaintext: bytes) -> str:
    ct = pub.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )
    return base64url(ct)

def rsa_decrypt(priv: RSAPrivateKey, ciphertext_b64: str) -> bytes:
    ct = unbase64url(ciphertext_b64)
    return priv.decrypt(
        ct,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )

def sign(priv: RSAPrivateKey, message: bytes) -> str:
    sig = priv.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return base64url(sig)

def verify(pub: RSAPublicKey, message: bytes, sig_b64: str) -> bool:
    try:
        pub.verify(
            unbase64url(sig_b64), message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def canonical_json(obj: Dict[str, Any]) -> bytes:
    """Canonical JSON for signing: sorted keys, compact separators."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
