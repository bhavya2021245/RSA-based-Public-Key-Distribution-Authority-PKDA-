from pkda import PublicKeyDirectoryAuthority
from client import ClientEntity

if __name__ == "__main__":
    global_public_key_mappings = {1: (29, 91), 2: (17, 91)}

    pkda = PublicKeyDirectoryAuthority(global_public_key_mappings, private_key=(13, 119), public_key=(37, 119))
    client_A = ClientEntity(client_identifier=1, private_key=(5, 91), public_key=(29, 91), pkda_public_key=pkda.public_key)
    client_B = ClientEntity(client_identifier=2, private_key=(17, 91), public_key=(17, 91), pkda_public_key=pkda.public_key)

    encrypted_request = client_A.generate_message_for_pkda(requested_client_id=2)
    encrypted_response = pkda.process_client_request(encrypted_request=encrypted_request)
    print("client_A's request for client_B's public key:", client_A.process_message_from_pkda(encrypted_message=encrypted_response))

    encrypted_request = client_B.generate_message_for_pkda(requested_client_id=1)
    encrypted_response = pkda.process_client_request(encrypted_request=encrypted_request)
    print("client_B's request for client_A's public key:", client_B.process_message_from_pkda(encrypted_message=encrypted_response))

    encrypted_message1 = client_A.generate_message_for_client(receiver_client_id=client_B.client_identifier, text_message="Hi1")
    encrypted_message2 = client_A.generate_message_for_client(receiver_client_id=client_B.client_identifier, text_message="Hi2")
    encrypted_message3 = client_A.generate_message_for_client(receiver_client_id=client_B.client_identifier, text_message="Hi3")

    timestamp1, nonce1, sender_client_id1, decoded_text_message1 = client_B.process_message_from_client(encrypted_message=encrypted_message1)
    print("client_B's processing of client_A's first message:", timestamp1, nonce1, sender_client_id1, decoded_text_message1)

    timestamp2, nonce2, sender_client_id2, decoded_text_message2 = client_B.process_message_from_client(encrypted_message=encrypted_message2)
    print("client_B's processing of client_A's second message:", timestamp2, nonce2, sender_client_id2, decoded_text_message2)

    timestamp3, nonce3, sender_client_id3, decoded_text_message3 = client_B.process_message_from_client(encrypted_message=encrypted_message3)
    print("client_B's processing of client_A's third message:", timestamp3, nonce3, sender_client_id3, decoded_text_message3)

    encrypted_response1 = client_B.generate_message_for_client(receiver_client_id=client_A.client_identifier, text_message="GotIt1", nonce=nonce1)
    encrypted_response2 = client_B.generate_message_for_client(receiver_client_id=client_A.client_identifier, text_message="GotIt2", nonce=nonce2)
    encrypted_response3 = client_B.generate_message_for_client(receiver_client_id=client_A.client_identifier, text_message="GotIt3", nonce=nonce3)

    print("client_A's processing of client_B's first response:", client_A.process_message_from_client(encrypted_message=encrypted_response1))
    print("client_A's processing of client_B's second response:", client_A.process_message_from_client(encrypted_message=encrypted_response2))
    print("client_A's processing of client_B's third response:", client_A.process_message_from_client(encrypted_message=encrypted_response3))
