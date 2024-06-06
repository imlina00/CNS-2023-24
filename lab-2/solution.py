import os
from base64 import b64decode, b64encode

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from pydantic import BaseModel


class Ciphertext(BaseModel):
    ciphertext: str


class Challenge(BaseModel):
    iv: str
    ciphertext: str


def encrypt_challenge(key: bytes, challenge: str) -> Challenge:
    """Encrypts challenge in CBC mode using the provided key."""
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(challenge.encode())
    padded_data += padder.finalize()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data)
    ciphertext += encryptor.finalize()

    encoded_iv = b64encode(iv)
    encoded_ciphertext = b64encode(ciphertext)
    return Challenge(iv=encoded_iv, ciphertext=encoded_ciphertext)


def decrypt_challenge(key: bytes, challenge: Challenge) -> str:
    """Decrypts encrypted challenge; reveals a password that can be
    used to unlock the next task/challenge.
    """
    iv = b64decode(challenge.iv)
    ciphertext = b64decode(challenge.ciphertext)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext)
    plaintext += decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(plaintext)
    plaintext += unpadder.finalize()
    return plaintext.decode()

def derive_key(key_seed: str, key_length=32) -> bytes:
    """Derives encryption/decryption key from the given key_seed.
    Uses modern key derivation function (KDF) scrypt.
    """
    kdf = Scrypt(
        salt=b"",
        length=key_length,
        n=2**14,
        r=8,
        p=1,
    )
    key = kdf.derive(key_seed.encode())
    return key

if __name__== "__main__":
    cookie = "stomasheprnofout"
    key = derive_key(key_seed=cookie)
    print(f"key: {key}")

    challenge = Challenge(iv = "lRzDC6J9Kuqmz/+ubOoB/Q==", ciphertext="iJGDpHpDWEex2o2Tk3rK4MbTdH8RKbHAw+AHsLXwuJfWXVfXOPPRXx+QLvHiH2u4B/iHE1m068pRA60b4Z+pbi/waRDUdN09ogpIuOHGrvTVAJuKDKKsvZ6GmYWVy45NUMl654UHBcQcEykQzJlbEUSw/EXGaIobmHrvmUpXwMFM8jpFM7BvUY1LYuZmPFWg4k/FoPSBW7lTRQEyDSaVRSrRQVHpLH/y0YxlaIjXn/s=")

    plaintext=decrypt_challenge(key, challenge)
    print(f"Decrypted challenge: {plaintext}")