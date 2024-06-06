import os
from base64 import b64decode, b64encode
import requests
import string
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from pydantic import BaseModel


class Ciphertext(BaseModel):
    ciphertext: str


class Challenge(BaseModel):
    iv: str
    ciphertext: str

def get_access_token(username, password, url):
    response = requests.post(
        url,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={"username": username, "password": password}
    )
    response.raise_for_status()
    return response.json().get("access_token")


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


def encrypt_chosen_plaintext(plaintext: str, token: str, url: str) -> str:
    response = requests.post(
        url=url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        },    
        json={"plaintext": plaintext}
    )

    response.raise_for_status()
    return response.json().get("ciphertext")

def get_challenge(url):
    response = requests.get(
        url,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    response.raise_for_status()
    return response.json()

if __name__ == "__main__":
    username = "mlinarevic_ivona"
    password = "itcathenad"
    url1 = "http://10.0.15.2/ecb/token"
    url2 = "http://10.0.15.2/ecb/challenge"
    url3 = "http://10.0.15.2/ecb/"

    # Step 1: Get the token
    token = get_access_token(username, password, url1)
    COOKIE = ""
    lowercase_alphabet = string.ascii_lowercase
    for i in range (1,17):
        plaintext = "x"*(16-i)
        ciphertext_test = encrypt_chosen_plaintext(plaintext, token, url3)
        ciphertext_test = ciphertext_test[:20]

        for letter in lowercase_alphabet:
            print(letter)
            ciphertext = encrypt_chosen_plaintext(plaintext + COOKIE + letter, token, url3)
            ciphertext = ciphertext[:20]

            if ciphertext == ciphertext_test:
                COOKIE += letter
                break

    print(COOKIE)
   
    response = get_challenge(url2)
    challenge = Challenge(**response)

    key = derive_key(key_seed=COOKIE)
    print(f"Key: {key}")

    recovered_plaintext = decrypt_challenge(key=key, challenge=challenge)
    print(f"Decrypted challenge: {recovered_plaintext}")
