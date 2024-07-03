import random
import time

class RSA:
    @staticmethod
    def encrypt(input_message: tuple, rsa_key: tuple):
        """
        Encrypts the 'input_message'=(m1,m2,...) via RSA algorithm using the 'rsa_key'=(e,n)
        """
        exponent, modulus = rsa_key
        encrypted_message = [RSA.rsa_core_operation(element, exponent, modulus) for element in input_message]
        return tuple(encrypted_message)

    @staticmethod
    def decrypt(input_message: tuple, rsa_key: tuple):
        """
        Decrypts the 'input_message'=(m1,m2,...) via RSA algorithm using the 'rsa_key'=(d,n)
        """
        exponent, modulus = rsa_key
        decrypted_message = [RSA.rsa_core_operation(element, exponent, modulus) for element in input_message]
        return tuple(decrypted_message)

    @staticmethod
    def rsa_core_operation(element, exponent, modulus):
        """
        Returns element^exponent (mod modulus) which is the core operation in RSA encryption/decryption.
        """
        result = 1
        while exponent > 0:
            if exponent % 2 == 1:
                result = (result * element) % modulus
            element = (element * element) % modulus
            exponent //= 2
        return result

    @staticmethod
    def rsa_encode_string(input_string):
        """
        Encodes a string into a tuple of ASCII values.
        """
        ascii_tuple = tuple(ord(char) - ord("a") if char.isalpha() else 26 + ord(char) - ord("0") for char in input_string.lower())
        return ascii_tuple

    @staticmethod
    def rsa_decode_string(ascii_tuple):
        """
        Decodes a tuple of ASCII values into a string.
        """
        decoded_string = "".join(chr(num + ord("a")) if num < 26 else chr(num - 26 + ord("0")) for num in ascii_tuple)
        return decoded_string
