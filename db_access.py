#  File: db_access.py
#  Description: Database access control
#  Author: Christopher Hindson
#  Date: 12/11/2020

# Imports
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta
from sqlite3 import Error

# Consts
DB_PATH = "/home/chrishindson/Documents/Uni/CET331 - python/Assignment/passwordAmend/db/pwd_db.sqlite"

# Globals
user_credential_list = []


# Main processing

def sql_connection():
    """

    :return:
    """
    try:
        connection = sqlite3.connect(DB_PATH)
        return connection
    except Error:
        print(Error)


def credential_retrieval():
    """

    :return:
    """
    sql_string = "SELECT * FROM " \
                 "(SELECT ua.user_name, uca.user_cred " \
                 "FROM user_accounts ua " \
                 "JOIN user_cred_audit uca ON ua.user_id = uca.user_id " \
                 "UNION ALL " \
                 "SELECT u.user_name, uc.user_cred " \
                 "FROM user_accounts u " \
                 "JOIN user_credentials uc ON u.user_id = uc.user_id) a " \
                 "WHERE a.user_name = ?"
    return sql_string


def credential_update(password, username, expiry_date):
    """
    Update the password of the user to the new supplied details
    :param password: updated password for user
    :param username: username for the password update to be applied to
    :param expiry_date: the expiry date of the new password
    :return:
    """
    try:
        with closing(sql_connection()) as conn:
            with closing(conn.cursor()) as cursor:
                cursor.execute(
                    "UPDATE user_credentials "
                    "SET user_cred = ?, "
                    "expiry_date = ?, "
                    "last_updated = ? "
                    "WHERE user_id = (SELECT user_id FROM user_accounts WHERE user_name = ?);",
                    (password, expiry_date, datetime.now(), username))
                conn.commit()
                return True
    except Error:
        return False


def credential_find():
    """
    SQL to retrieve current password for user. Used for verification prior to update
    :return: SQL string for retrieving existing password for user.
    """
    sql_string = "SELECT ua.user_name, uc.user_cred " \
                 "FROM user_accounts ua " \
                 "LEFT JOIN user_credentials uc on ua.user_id = uc.user_id " \
                 "WHERE user_name = ? ;"
    return sql_string


def create_new_user(username, forename, surname, password, expiry_days):
    """

    :param username: username of new user, uniqueness checked prior to creation
    :param forename: forename of new user
    :param surname: surname of new user
    :param password: validity checked password of new user
    :param expiry_days: days before expiration of password, determined by password strength
    :return: Details of
    """
    creation_date = datetime.now(tz=None)
    expiry_date = datetime.now(tz=None) + timedelta(days=expiry_days)
    try:
        with closing(sql_connection()) as conn:
            with closing(conn.cursor()) as cursor:
                cursor.execute(
                    "INSERT INTO user_accounts (user_name, forename, surname, created_date) VALUES (?, ?, ?, ?)",
                    (username, forename, surname, creation_date))
                user_id = cursor.lastrowid
                cursor.execute(
                    "INSERT INTO user_credentials (user_id, user_cred, expiry_date, last_updated) VALUES (?, ?, ?, ?);",
                    (user_id, password, expiry_date, creation_date))
                conn.commit()
                return True, f"User account successfully created. Your password will expire in {expiry_days} days"
    except Error:
        return False, "There was a problem creating user account"


def check_username(username):
    """
    Check if the selected username is available when creating a new user
    :param username: potential new username to be created
    :return: True if available, False if already in use
    """
    sql_string = "SELECT * FROM user_accounts WHERE user_name = ?; "
    try:
        with closing(sql_connection()) as db:
            with closing(db.cursor()) as cursor:
                user_credentials = cursor.execute(sql_string, (username,)).fetchall()
                if len(user_credentials) == 0:
                    return True, "Username is available"
        return False, "Username is unavailable"

    except Error:
        return False, "There was a problem creating user account"


def common_passwords():
    """
    Gather the 1000 most common password phrases/sequences from the database into a list,
    to be checked as the user enters a potential new password to provide feedback on possible improvements
    :return: list of common passwords from the database
    """
    sql_string = "SELECT id, password_text FROM common_passwords ORDER BY id;"
    try:
        with closing(sql_connection()) as db:
            with closing(db.cursor()) as cursor:
                password_list = cursor.execute(sql_string).fetchall()
                return password_list
    except Error:
        return None


def user_list():
    """
    Gather a list of user credentials to check if username, forename, or surname is used within the password
    Used to provide feedback for possible improvements, will only match where username supplied on initial login/amend
    form matches that within the list
    :return: user list, without credentials for comparison only, password validity and username availability is checked
    directly in different function
    """
    sql_string = "SELECT user_name, forename, surname FROM user_accounts ORDER BY user_name;"
    try:
        with closing(sql_connection()) as db:
            with closing(db.cursor()) as cursor:
                user_details = cursor.execute(sql_string).fetchall()
                return user_details
    except Error:
        return None
