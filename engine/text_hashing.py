#!/usr/bin/python3
#  File: text_hashing.py
#  Description: Encryption/Decryption information for package
#  Author: Christopher Hindson
#  Date: 31/10/2020

# Imports
from passlib.context import CryptContext

# CONSTANTS
HASH_ROUNDS = 294611  # Number of rounds of encryption most closely linked to 0.35 seconds (noted user tolerance)
SALT_SIZE = 128  # Size of random salt to be added

# Globals
pwd_context = CryptContext(schemes=["sha256_crypt", "pbkdf2_sha256"], default="pbkdf2_sha256")


def hash_password(password):
    """
    Hash the supplied password using the created context above
    :param password: user supplied details for replacement/new password
    :return: hashed string of password for database input
    """
    return pwd_context.hash(password, salt_size=SALT_SIZE, rounds=HASH_ROUNDS)


def verify_hashed_password(password, hashed):
    """
    Verify that the supplied password matches the previously hashed password from the database
    :param password: user supplied details for current password
    :param hashed: current password hash from database
    :return: If password and hashed match, True, else False
    """
    return pwd_context.verify(password, hashed)
