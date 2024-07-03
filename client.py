import time
import random
from rsa import RSA

class ClientEntity:
    def __init__(self, client_identifier, private_key, public_key, pkda_public_key):
        self.public_key_mappings = {}
        self.client_identifier = client_identifier
        self.private_key = private_key
        self.public_key = public_key
        self.pkda_public_key = pkda_public_key
    
    def generate_message_for_pkda(self, requested_client_id: int):
        nonce = self.generate_nonce()
        timestamp = self.generate_timestamp()
        message = (requested_client_id, timestamp, nonce)
        return RSA.encrypt(message, self.pkda_public_key)
    
    def process_message_from_pkda(self, encrypted_message):
        e, n, client_id, timestamp, nonce = RSA.decrypt(encrypted_message, self.pkda_public_key)
        self.public_key_mappings[client_id] = (e, n)
        return (e, n, client_id, timestamp, nonce)

    def generate_message_for_client(self, receiver_client_id: int, text_message: str, nonce=None):
        timestamp = self.generate_timestamp()
        if nonce is None:
            nonce = self.generate_nonce()
        message = [timestamp, nonce, self.client_identifier] + list(RSA.rsa_encode_string(text_message))
        return RSA.encrypt(tuple(message), rsa_key=self.public_key_mappings.get(receiver_client_id))

    def process_message_from_client(self, encrypted_message):
        decrypted_tuple = RSA.decrypt(encrypted_message, self.private_key)
        timestamp = decrypted_tuple[0]
        nonce = decrypted_tuple[1]
        sender_client_id = decrypted_tuple[2]
        decoded_text_message = RSA.rsa_decode_string(decrypted_tuple[3:])
        return (timestamp, nonce, sender_client_id, decoded_text_message)

    def generate_nonce(self):
        lower_limit = 1
        upper_limit = self.public_key[1] - 2
        return random.randint(lower_limit, upper_limit)
    
    def generate_timestamp(self):
        return int(time.time())
