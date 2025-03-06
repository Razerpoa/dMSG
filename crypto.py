from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os
import sys

class DoubleRatchet:
    def __init__(self):
        self.root_key = os.urandom(32)
        self.chain_key = os.urandom(32)
        self.message_key = None
        self.ratchet_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

    def encrypt_message(self, plaintext):
        self.message_key = self.kdf(self.chain_key)
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(self.message_key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return nonce + encryptor.tag + ciphertext

    def decrypt_message(self, ciphertext):
        self.message_key = self.kdf(self.chain_key)
        nonce = ciphertext[:12]
        tag = ciphertext[12:28]
        ciphertext = ciphertext[28:]
        cipher = Cipher(algorithms.AES(self.message_key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        self.chain_key = self.kdf(self.chain_key)  # Update chain key after decryption
        return plaintext

    def kdf(self, key_material):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data'
        )
        return hkdf.derive(key_material)

    def ratchet_step(self):
        self.ratchet_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.root_key = self.kdf(self.root_key + self.ratchet_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))