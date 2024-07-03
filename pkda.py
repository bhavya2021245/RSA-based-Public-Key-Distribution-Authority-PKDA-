import time
from rsa import RSA

class PublicKeyDirectoryAuthority:
    def __init__(self, client_public_keys, private_key, public_key):
        self.client_public_keys = client_public_keys
        self.private_key = private_key
        self.public_key = public_key
    
    def process_client_request(self, encrypted_request):
        client_id, timestamp, nonce = RSA.decrypt(encrypted_request, self.private_key)
        requested_public_key = self.client_public_keys.get(client_id)
        e, n = requested_public_key
        response_nonce = self.generate_response_nonce(nonce)
        response_timestamp = self.generate_current_timestamp()
        encrypted_response = RSA.encrypt((e, n, client_id, response_timestamp, response_nonce), self.private_key)
        return encrypted_response
    
    def generate_response_nonce(self, nonce):
        return nonce + 1
    
    def generate_current_timestamp(self):
        return int(time.time())
