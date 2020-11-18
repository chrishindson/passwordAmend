#!/usr/bin/python3
#  File: text_encryption.py
#  Description: Encryption/Decryption information for package
#  Author: Christopher Hindson
#  Date: 31/10/2020

# Imports
from passlib.context import CryptContext

# CONSTANTS
DECRYPT_ROUNDS = 294611  # Number of rounds of encryption most closely linked to 0.35 seconds (noted user tolerance)
SALT_SIZE = 32  # Size of random salt to be added

# Globals

pwd_context = CryptContext(schemes=["sha256_crypt", "pbkdf2_sha256"], default="pbkdf2_sha256")


def encrypt_password(password):
    return pwd_context.hash(password, salt_size=SALT_SIZE, rounds=DECRYPT_ROUNDS)


def verify_encrypted_password(password, hashed):
    return pwd_context.verify(password, hashed)
