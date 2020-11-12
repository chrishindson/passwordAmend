#  File: password_check.py
#  Description: Password candidate check
#  Author: Christopher Hindson
#  Date: 31/10/2020

# Imports
from text_encryption import verify_encrypted_password
import re

# Consts

# Globals
VIABLE_PASSWORD = True
user_credential_list = []
SPECIAL_SET = 33
NUMBER_SET = 10
ALPHA_SET = 26

# Main processing
_sequences = (
    'abcdefghijklmnopqrstuvwxyz'  # Alphabet
    'qwertyuiopasdfghjklzxcvbnm'  # Keyboard
    '~!@#$%^&*()_+-='  # Keyboard special, top row
    '01234567890'  # Numbers
)
_sequences = _sequences + _sequences[::-1]


#
def sequence_check(password_input):
    """
    check for sequential characters within the password string
    :param password_input: input from user as potential password
    function checks for sequential characters within the passed string
    :return:
    """
    global VIABLE_PASSWORD

    _sequence_count = 0
    for password_char in password_input:
        _sequence_count += 1

    if _sequence_count > 2:
        VIABLE_PASSWORD = False
    return VIABLE_PASSWORD


# check that the password has not previously been used by the user, within the
# acceptable time limit, based upon strength of password at time of creation
def viable_password(password_candidate):
    # print(f'{password_candidate}')
    return VIABLE_PASSWORD


def previous_check(user_name, password_input):
    """

    :param user_name: user_name of the user attempting password change
    :param password_input: the potential password supplied by the user
    :return:
    """
    global VIABLE_PASSWORD
    global user_credential_list
    for user_credential in user_credential_list:
        user_pass = user_credential['user_credential']
        if verify_encrypted_password(password_input, user_pass) and user_name == user_credential['user_name']:
            VIABLE_PASSWORD = False
            return VIABLE_PASSWORD
    return VIABLE_PASSWORD


def criteria_check(password_input):
    """
    Check the string against criteria, to highlight to user potential areas to improve
    Only definitive from criteria is length, all others will enhance password strength
        8 characters in length
        1 upper case character
        1 lower case character
        1 number
        1 special character
    Charset size
        10 numbers only
        26 lowercase only
        33 special characters only
        36 lowercase and numbers
        52 uppercase and lowercase
        62 uppercase, lowercase and numbers
        95 uppercase, lowercase, numbers and special characters
        brute force measurements  character_set_size^character_count
    :param password_input:
    :return:
    """
    char_set_val = 0
    upper_check = bool(re.match(r'(?=.*[A-Z])', password_input))
    lower_check = bool(re.match(r'(?=.*[a-z])', password_input))
    number_check = bool(re.match(r'(?=.*[0-9])', password_input))
    special_check = bool(re.match(r'(?=.*[\W])', password_input))
    length_check = len(password_input) >= 8

    if upper_check:
        char_set_val += ALPHA_SET
    if lower_check:
        char_set_val += ALPHA_SET
    if number_check:
        char_set_val += NUMBER_SET
    if special_check:
        char_set_val += SPECIAL_SET

    return {
        'upper_check': upper_check,
        'lower_check': lower_check,
        'number_check': number_check,
        'special_check': special_check,
        'length_check': length_check,
        'char_set_val': char_set_val
    }
