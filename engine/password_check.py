#  File: password_check.py
#  Description: Password candidate check
#  Author: Christopher Hindson
#  Date: 31/10/2020

# Imports
import re
from math import log2
from .db_access import *
from .text_encryption import verify_encrypted_password, encrypt_password

# Consts

# Globals
common_password_list = []
user_details = []
VIABLE_PASSWORD = True
user_credential_list = []
SPECIAL_SET = 33  # special characters
NUMBER_SET = 10  # numbers only
ALPHA_SET = 26  # alpha characters, used for both upper and lower case instances

# password strength list and characteristics
strength_list = ({'id': 0, 'strength_desc': '', 'strength_color': '', 'expiry_days': 0},
                 {'id': 1, 'strength_desc': 'VERY WEAK', 'strength_color': '#FF0000', 'expiry_days': 30},
                 {'id': 2, 'strength_desc': 'WEAK', 'strength_color': '#E5E500', 'expiry_days': 60},
                 {'id': 3, 'strength_desc': 'OK', 'strength_color': '#FFA500', 'expiry_days': 90},
                 {'id': 4, 'strength_desc': 'STRONG', 'strength_color': '#008000', 'expiry_days': 180},
                 {'id': 5, 'strength_desc': 'VERY STRONG', 'strength_color': '#00FF00', 'expiry_days': 365})
# Sequential character lists
sequences = (
    'abcdefghijklmnopqrstuvwxyz'  # Alphabet
    'qwertyuiopasdfghjklzxcvbnm'  # Keyboard
    '~!@#$%^&*()_+-='  # Keyboard special, top row
    '01234567890'  # Numbers
    'pyfgcrlaoeuidhtnsqjkxbmwvz'  # dvorak keyboard
)
sequences = sequences + sequences[::-1]


# Main processing
def check_common_passwords(password_input):
    """
    Check the password supplied by the user against a list of the 1000 most commonly used passwords
    :param password_input: password candidate
    :return: If password is found in common list, if exact or contains commonly used phrased,
    Position within list where 1 = Most common - 1000 Least common (within list only)
    """
    for common in common_password_list:
        if password_input == common[1]:
            return True, f'Exact Match Common Placement: {common[0]}/{len(common_password_list)}', common[0]
        elif common[1] in password_input:
            return True, f'Contains Common Placement: {common[0]}/{len(common_password_list)}', common[0] / 10
    return False, 0, 0.0


def sequence_check(password_input):
    """
    check for sequential characters within the password string
    :param password_input: input from user as potential password
    function checks for sequential characters within the passed string
    :return: the length of sequential characters
    """
    sequences_length = 0

    # Iterate through the password candidate
    i = 0
    while i < len(password_input):
        # Check password from index i
        password = password_input[i:]

        # Pass through the sequence to find any similarities
        j = -1
        common_length = 1
        while True:
            # Find the first instance of the character being searched, may appear multiple times
            j = sequences.find(password[0], j + 1)
            # if not found break
            if j == -1:
                break
            # Find the longest common prefix
            common_here = ''
            for a, b in zip(password, sequences[j:]):
                if a != b:
                    break
                else:
                    common_here += a
            # Store the max common found
            common_length = max(common_length, len(common_here))

        # Does the password contain a sequence, if so, is it greater than 2?
        if common_length > 2:
            sequences_length += common_length

        # Move beyond the current existing sequence
        i += common_length

    return sequences_length


def user_details_check(username, password):
    """
    check if username, forename or surname are used within the user password candidate, search is case insensitive
    :param username: the username being used to amend password, or username of account being created
    :param password: the password candidate for the user
    :return: If username, forename or surname appears in the password, True, else False
    """
    for user_detail in user_details:
        if user_detail[0] == username:
            if re.search(user_detail[0], password, re.IGNORECASE) or \
                    re.search(user_detail[1], password, re.IGNORECASE) or \
                    re.search(user_detail[2], password, re.IGNORECASE):
                return True
    return False


def criteria_check(username, password_input):
    """
    Check the string against criteria, to highlight to user potential areas to improve
    Only definitive from criteria is length, all others will enhance password strength
    Charset size
        10 numbers only
        26 lowercase only
        33 special characters only
        36 lowercase and numbers
        52 uppercase and lowercase
        62 uppercase, lowercase and numbers
        95 uppercase, lowercase, numbers and special characters
        brute force measurements  character_set_size^character_count
    :param username: username supplied by user for credential update, or user creation
    :param password_input: potential new password to associate to the account
    :return: suggested improvement string detailing potential methods to increase password strength,
            strength :returns the details from strength_list (id, strength_desc, strength_color, expiry_days)
    """
    char_set_val = 0
    entropy = 0
    repeated_count = 0
    common_deduction = 1.0
    user_deduction = 0
    password_len = len(password_input)
    improve_str = 'Suggestions for improvement:'

    # Check password for upper case characters
    upper_check = bool(re.match(r'(?=.*[A-Z])', password_input))
    # Check password for lower case characters
    lower_check = bool(re.match(r'(?=.*[a-z])', password_input))
    # Check password for numbers
    number_check = bool(re.match(r'(?=.*[0-9])', password_input))
    # check password for special characters
    special_check = bool(re.match(r'(?=.*[\W])', password_input))
    # Find repeated characters longer than two repetitions
    repeated_char = bool(re.findall(r'((\w)\2{2,})', password_input))
    length_check = password_len < 8
    # check the password for sequential characters and the total amount
    sequence_count = sequence_check(password_input.lower())
    # check password against common password list, and return position in list of 1000
    # exact match is penalised more heavily
    common_check, common_text, common_position = check_common_passwords(password_input.lower())
    # determine if the username, forename or surname are used within the password
    user_details_used = user_details_check(username, password_input)

    # Check booleans to suggest potential improvements to the password strength
    if length_check:
        improve_str += '\n * At least 8 characters'
    elif password_len < 12:
        improve_str += '\n * Increase password to at least 12 characters'
    if common_check:
        improve_str += f'\n * Try to avoid common passwords ({common_text})'
        if password_len < 12:
            common_deduction -= (1000 - common_position) / 1000
    if user_details_used:
        improve_str += f'\n * Do not include username, forename or surname'
        user_deduction = 10
    if repeated_char:
        # determine the total count of repeated characters within the password
        for match in re.findall(r'((\w)\2{2,})', password_input):
            repeated_count += len(match[0])

    # Add potential characters within password to char_set_val, used to calculate entropy
    # OR suggest inclusion to improve password strength
    if upper_check:
        char_set_val += ALPHA_SET
    else:
        improve_str += '\n * At least one uppercase character'
    if lower_check:
        char_set_val += ALPHA_SET
    else:
        improve_str += '\n * At least one lowercase character'
    if number_check:
        char_set_val += NUMBER_SET
    else:
        improve_str += '\n * At least one number'
    if special_check:
        char_set_val += SPECIAL_SET
    else:
        improve_str += '\n * At least one special character'
    if sequence_count > 2:
        improve_str += '\n * No more than 2 sequential characters'
    if repeated_char:
        improve_str += '\n * No more than 2 repeated characters'
    if password_len != 0:
        # Possible combinations is char_set_val to power of password length
        # Adapted within this system to account for use of sequential characters, repeated characters and user info
        combinations = char_set_val ** (password_len - (sequence_count + repeated_count + user_deduction))
        overall_entropy = log2(combinations)
        entropy_per_char = log2(char_set_val)
        # Calculated entropy used to grade the strength of the password supplied
        calculated_entropy = (password_len - (sequence_count + repeated_count)) * entropy_per_char
        entropy = {'combinations': combinations,
                   'overall_entropy': overall_entropy,
                   'entropy_per_char': entropy_per_char,
                   'calculated_entropy': calculated_entropy,
                   'character_set_values': char_set_val,
                   'password_len': password_len}

    strength = determine_strength(entropy)

    return {
        'suggested_improvements': improve_str,
        'strength': strength
    }


def determine_strength(entropy):
    """
    Determine the strength of the potential password, using the entropy details and predictability of the password
    Provide a visual guide, through text and colour for the user on key release
    :param entropy:
    :return: the rating_list information of how secure/how breakable the password supplied is for display to user
    """
    rating = 0
    if entropy != 0:
        if entropy['password_len'] < 8 or entropy['calculated_entropy'] < 20:
            rating = 1
        elif entropy['calculated_entropy'] < 40:  # entropy['password_len'] < 12 and
            rating = 2
        elif entropy['calculated_entropy'] < 60:  # entropy['password_len'] < 16 and
            rating = 3
        elif entropy['calculated_entropy'] < 100:
            rating = 4
        else:
            rating = 5
    return strength_list[rating]


def credential_update(username, password, expiry_days):
    """
    Check if the password has been used previously
    :param username: username of attempted password amend
    :param password: potential new password
    :param expiry_days: the days until the password expires
    :return: If password is verified, True, else False
    """
    sql_string = credential_retrieval()
    with closing(sql_connection()) as db:
        with closing(db.cursor()) as cursor:
            user_credentials = cursor.execute(sql_string, (username,))
            expiry_date = datetime.now(tz=None) + timedelta(days=expiry_days)
            for user_cred in user_credentials:
                if verify_encrypted_password(password, user_cred[1]):
                    return False
    encrypted_password = encrypt_password(password)
    user_update = credential_update(encrypted_password, username, expiry_date)
    return user_update


def credential_verify(username, password):
    """
    Check that the current password supplied matches the database record before updating to new password
    :param username: username of attempted password amend
    :param password: current password required to authorise the change of password
    :return: if password can be verified, True, else False
    """
    sql_string = credential_find()
    with closing(sql_connection()) as db:
        with closing(db.cursor()) as cursor:
            user_credentials = cursor.execute(sql_string, (username,))
            for user_cred in user_credentials:
                if verify_encrypted_password(password, user_cred[1]):
                    return True
    return False


def get_common_password_list():
    """
    Gather common password list from database
    :return: Common password list
    """
    global common_password_list

    common_password_list = common_passwords()


def get_user_list():
    """
    Gather list of existing users to verify user information not included in password for current user only (matched)
    :return: User details list
    """
    global user_details

    user_details = user_list()
