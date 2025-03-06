from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os
import struct

class DoubleRatchet:
    def __init__(self, shared_secret=None):
        """Initialize a Double Ratchet session
        
        Args:
            shared_secret: Optional initial shared secret from X3DH or other key agreement
        """
        # Initialize DH keys
        self.dh_private = x25519.X25519PrivateKey.generate()
        self.dh_public = self.dh_private.public_key()
        self.dh_remote_public = None
        
        # Chain keys
        self.root_key = shared_secret or os.urandom(32)
        self.send_chain_key = None
        self.recv_chain_key = None
        
        # Message counters
        self.send_count = 0
        self.recv_count = 0
        self.skipped_message_keys = {}  # (ratchet_public_key, message_number) -> message_key
        
        # Max skipped message keys to store (prevent DOS attacks)
        self.max_skip = 100

    def serialize_public_key(self, key):
        """Convert a public key to bytes for transmission"""
        return key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def deserialize_public_key(self, key_bytes):
        """Convert bytes to a public key object"""
        return x25519.X25519PublicKey.from_public_bytes(key_bytes)
    
    def dh(self, private_key, public_key):
        """Perform a Diffie-Hellman key exchange"""
        return private_key.exchange(public_key)
    
    def kdf_rk(self, root_key, dh_output):
        """Key derivation for the root key and chain key"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,  # Generate 64 bytes: 32 for root_key, 32 for chain_key
            salt=root_key,
            info=b'DoubleRatchet v1 Root'
        )
        output = hkdf.derive(dh_output)
        return output[:32], output[32:]  # New root_key, new chain_key
    
    def kdf_ck(self, chain_key):
        """Key derivation for chain keys to message keys"""
        hmac = hashes.Hash(hashes.HMAC(hashes.SHA256()))
        hmac.update(chain_key)
        hmac.update(b'\x01')  # Different input for message key
        message_key = hmac.finalize()
        
        hmac = hashes.Hash(hashes.HMAC(hashes.SHA256()))
        hmac.update(chain_key)
        hmac.update(b'\x02')  # Different input for next chain key
        next_chain_key = hmac.finalize()
        
        return next_chain_key, message_key
    
    def ratchet_dh_step(self, remote_public):
        """Perform a DH ratchet step with a new remote public key"""
        # Store remote public key
        self.dh_remote_public = remote_public
        
        # Calculate new shared secret
        dh_output = self.dh(self.dh_private, self.dh_remote_public)
        
        # Derive new root key and receive chain key
        self.root_key, self.recv_chain_key = self.kdf_rk(self.root_key, dh_output)
        
        # Generate new DH key pair
        self.dh_private = x25519.X25519PrivateKey.generate()
        self.dh_public = self.dh_private.public_key()
        
        # Calculate another DH output with new key pair
        dh_output = self.dh(self.dh_private, self.dh_remote_public)
        
        # Derive new root key and sending chain key
        self.root_key, self.send_chain_key = self.kdf_rk(self.root_key, dh_output)
        
        # Reset message counters
        self.send_count = 0
        self.recv_count = 0
    
    def encrypt_message(self, plaintext):
        """Encrypt a message using the current sending chain key"""
        if not self.send_chain_key:
            raise ValueError("No sending chain key established")
        
        # Derive next chain key and message key
        self.send_chain_key, message_key = self.kdf_ck(self.send_chain_key)
        
        # Encrypt the message
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(message_key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        
        # Include header data in associated data
        header = struct.pack('!QI', 
                            int.from_bytes(self.serialize_public_key(self.dh_public), byteorder='big'), 
                            self.send_count)
        encryptor.authenticate_additional_data(header)
        
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        # Increment message counter
        self.send_count += 1
        
        # Return header, nonce, tag, and ciphertext
        return {
            'dh_public': self.serialize_public_key(self.dh_public),
            'counter': self.send_count - 1,
            'nonce': nonce,
            'tag': encryptor.tag,
            'ciphertext': ciphertext
        }
    
    def try_skipped_message_keys(self, remote_dh_public, counter, nonce, tag, ciphertext, associated_data):
        """Try to decrypt with a skipped message key"""
        key_id = (remote_dh_public, counter)
        if key_id in self.skipped_message_keys:
            message_key = self.skipped_message_keys.pop(key_id)
            return self._decrypt_with_key(message_key, nonce, tag, ciphertext, associated_data)
        return None
    
    def _decrypt_with_key(self, message_key, nonce, tag, ciphertext, associated_data):
        """Helper to decrypt with a specific message key"""
        try:
            cipher = Cipher(algorithms.AES(message_key), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()
            if associated_data:
                decryptor.authenticate_additional_data(associated_data)
            return decryptor.update(ciphertext) + decryptor.finalize()
        except Exception as e:
            print(f"Decryption error: {e}")
            return None
    
    def _skip_message_keys(self, until_counter):
        """Skip message keys in the current receiving chain"""
        if not self.recv_chain_key:
            return
        
        # Don't skip too many keys to avoid DoS
        if until_counter > self.recv_count + self.max_skip:
            raise ValueError(f"Too many skipped messages: {until_counter - self.recv_count}")
        
        # Skip keys and store them
        while self.recv_count < until_counter:
            chain_key, message_key = self.kdf_ck(self.recv_chain_key)
            self.recv_chain_key = chain_key
            self.skipped_message_keys[(self.dh_remote_public, self.recv_count)] = message_key
            self.recv_count += 1
    
    def decrypt_message(self, message_dict):
        """Decrypt a message using Double Ratchet protocol"""
        remote_dh_public_bytes = message_dict['dh_public']
        remote_dh_public = self.deserialize_public_key(remote_dh_public_bytes)
        counter = message_dict['counter']
        nonce = message_dict['nonce']
        tag = message_dict['tag']
        ciphertext = message_dict['ciphertext']
        
        # Prepare header for authenticated additional data
        header = struct.pack('!QI', 
                            int.from_bytes(remote_dh_public_bytes, byteorder='big'), 
                            counter)
        
        # Case 1: Is this a message from a skipped key?
        plaintext = self.try_skipped_message_keys(
            remote_dh_public_bytes, counter, nonce, tag, ciphertext, header)
        if plaintext:
            return plaintext
        
        # Case 2: Is this a message from a new ratchet?
        if remote_dh_public != self.dh_remote_public:
            # Perform DH ratchet step with new remote key
            self.ratchet_dh_step(remote_dh_public)
        
        # Case 3: Handle out-of-order messages by skipping keys
        if counter > self.recv_count:
            self._skip_message_keys(counter)
        
        # Case 4: Normal case - derive message key and decrypt
        if counter == self.recv_count:
            if not self.recv_chain_key:
                raise ValueError("No receiving chain key established")
            
            # Derive next chain key and message key
            self.recv_chain_key, message_key = self.kdf_ck(self.recv_chain_key)
            self.recv_count += 1
            
            # Decrypt
            return self._decrypt_with_key(message_key, nonce, tag, ciphertext, header)
        
        # Case 5: Message counter is lower than expected (already processed)
        return None