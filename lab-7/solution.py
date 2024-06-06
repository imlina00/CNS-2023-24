from base64 import b64decode

import requests
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from pydantic import BaseModel


class Ciphertext(BaseModel):
    iv: str
    ciphertext: str


class Challenge(BaseModel):
    iv: str
    ciphertext: str


def get_access_token(username, password, url):
    response = requests.post(
        url,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={"username": username, "password": password},
    )
    response.raise_for_status()
    return response.json().get("access_token")


def encrypt_chosen_plaintext(plaintext: str, token: str, url: str) -> str:
    response = requests.post(
        url=url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json={"plaintext": plaintext},
    )

    response.raise_for_status()
    return response.json()


def get_challenge(url):
    response = requests.get(
        url,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    response.raise_for_status()
    return response.json()


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


def exchange_RSA_keys_and_DH_params(url, token, public_RSA_key):
    if isinstance(public_RSA_key, bytes):
            public_RSA_key=public_RSA_key.decode()
            
    response = requests.post(
            url=url,
            headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json={"key": public_RSA_key},
    )

    response.raise_for_status()
    key = response.json().get("key")
    dh_params = response.json().get("dh_params")
    return key, dh_params


if __name__ == "__main__":
    username = "mlinarevic_ivona"
    password = "sonsitiewh"
    url = "http://10.0.15.2/asymmetric/token"

    # Step 1: Get the token
    token = get_access_token(username, password, url)
    print(f"Token: {token}")

    #========================================
    # PROTOCOL IMPLEMENTATION
    #========================================
    
    #----------------------------------------
    # Step 2: Generate client RSA key pair
    #----------------------------------------
    client_RSA_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_RSA_public = client_RSA_private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    print(f"Client RSA public:\n{client_RSA_public.decode()}")
    
    #---------------------------------------------------
    # Step 3: Exchange public RSA keys and DH parameters
    #---------------------------------------------------
    url = "http://10.0.15.2/asymmetric/exchange/rsa-dh-params"
    
    server_RSA_public, DH_parameters = exchange_RSA_keys_and_DH_params(
         url=url, token=token, public_RSA_key=client_RSA_public
         )
    
    print(f"Server RSA public:\n{server_RSA_public}")
    print(f"DH parameters:\n{DH_parameters}")
    
    #De-serilization of RSA key and DH params
    server_RSA_public = serialization.load_pem_public_key(server_RSA_public.encode())
    DH_parameters = serialization.load_pem_parameters(DH_parameters.encode())
    
    print(f"Prime modulus p:", DH_parameters.parameter_numbers().p)
    print(f"The group generator g:", DH_parameters.parameter_numbers().g)   
   

    #-------------------------------------------------------------------
    # Step 4: Generate client DH key pair (based on the DH parameters)
    #-------------------------------------------------------------------


    #----------------------------------------------------------
    # Step 5: Sign client DH public key with client RSA private
    #----------------------------------------------------------


    #------------------------------------------------
    # Step 6: Authenticated DH key exchange/agreement
    #------------------------------------------------


    #---------------------------------------------------------------------------
    # Step 7: Verify authenticitiy of the server's DH public key and other info
    #---------------------------------------------------------------------------


    #----------------------------------------
    # Step 8: Calculate DH shared secret
    #----------------------------------------
    
    
    #----------------------------------------
    # Step 9: Derive 256 bit decryption key K
    #----------------------------------------
    
        
    #--------------------------------------------------
    # Step 10: Get the challenge and decrypt it using K
    #--------------------------------------------------