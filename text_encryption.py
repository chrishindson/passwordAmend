#!/usr/bin/python3
#  File: text_encryption.py
#  Description: Encryption/Decryption information for package
#  Author: Christopher Hindson
#  Date: 31/10/2020

# Imports
from passlib.context import CryptContext

# CONSTANTS

# Globals

pwd_context = CryptContext(schemes=["sha256_crypt", "md5_crypt"])


def encrypt_password(password):
    return pwd_context.hash(password)


def verify_encrypted_password(password, hashed):
    return pwd_context.verify(password, hashed)
