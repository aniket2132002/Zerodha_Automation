import os
from cryptography.fernet import Fernet
from pathlib import Path

ACCESS_TOKEN_DIR = Path("tokens")
ACCESS_TOKEN_DIR.mkdir(exist_ok=True)

def _get_fernet():
    key = os.getenv("FERNET_KEY")
    if not key:
        raise RuntimeError("FERNET_KEY not set in environment")
    return Fernet(key.encode())

def save_encrypted_token(client_id: str, token: str):
    f = _get_fernet()
    token_b = token.encode()
    enc = f.encrypt(token_b)
    path = ACCESS_TOKEN_DIR / f"{client_id}_access_token.enc"
    path.write_bytes(enc)
    # Restrict permissions (Unix)
    try:
        path.chmod(0o600)
    except Exception:
        pass

def load_encrypted_token(client_id: str) -> str:
    path = ACCESS_TOKEN_DIR / f"{client_id}_access_token.enc"
    if not path.exists():
        raise FileNotFoundError("Encrypted token not found for client: " + client_id)
    f = _get_fernet()
    enc = path.read_bytes()
    return f.decrypt(enc).decode()

def delete_encrypted_token(client_id: str):
    path = ACCESS_TOKEN_DIR / f"{client_id}_access_token.enc"
    if path.exists():
        path.unlink()
