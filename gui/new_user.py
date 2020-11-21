#!/usr/bin/python3
#  File: main.py
#  Description: Password candidate Main program launch/display
#  Author: Christopher Hindson
#  Date: 31/10/2020

# Imports
from PyQt5 import QtCore
from PyQt5.Qt import QGridLayout, Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QLabel, QLineEdit, QMessageBox
from engine.db_access import create_new_user, check_username
from engine.password_check import criteria_check, get_user_list
from engine.text_hashing import hash_password

# CONSTANTS
WIN_LEFT = 200
WIN_TOP = 200
WIN_WIDTH = 550
WIN_HEIGHT = 400

# Globals
USERNAME_AVAILABLE = False


# Main processing

class NewUser(QWidget):
    def __init__(self):
        super().__init__()
        self.raise_()
        self._expiry_days = 90
        self.setWindowModality(QtCore.Qt.ApplicationModal)
        self.setFocusPolicy(QtCore.Qt.StrongFocus)

        # Labels
        self.user_label = QLabel('Username (*)')
        self.user_feedback_label = QLabel(None)
        self.forename_label = QLabel('Forename (*)')
        self.surname_label = QLabel('Surname ')
        self.password_label = QLabel('Password (*)')
        self.password_verify_label = QLabel('Verify Password (*)')
        self.password_match_label = QLabel(None)
        self.feedback_label = QLabel(None)
        self.strength_label = QLabel('Password strength: ')
        self.strength_feedback_label = QLabel(None)
        self.strength_feedback_label.setAutoFillBackground(True)
        self.strength_feedback_label.setAlignment(Qt.AlignCenter)

        # Buttons
        self.create_button = QPushButton('Create User')
        self.cancel_button = QPushButton('Cancel')

        # Input boxes
        self.user_box = QLineEdit()
        self.forename_box = QLineEdit()
        self.surname_box = QLineEdit()
        self.password_box = QLineEdit()
        self.password_box.setEchoMode(QLineEdit.Password)
        self.verify_password_box = QLineEdit()
        self.verify_password_box.setEchoMode(QLineEdit.Password)

        # Button controls
        self.create_button.released.connect(self.create_attempt)
        self.cancel_button.released.connect(self.clicked_cancel_button)

        # Key press procedures
        self.user_box.keyReleaseEvent = self.user_released
        self.forename_box.keyReleaseEvent = self.key_release
        self.surname_box.keyReleaseEvent = self.key_release
        self.password_box.keyReleaseEvent = self.key_release
        self.verify_password_box.keyReleaseEvent = self.key_release

        self.create_button.keyReleaseEvent = self.key_release

        user_form = QVBoxLayout()

        creation_area = QGridLayout()
        creation_area.addWidget(self.user_label, 0, 0, 1, 3)
        creation_area.addWidget(self.user_box, 1, 0, 1, 3)
        creation_area.addWidget(self.user_feedback_label, 2, 0, 1, 3)
        creation_area.addWidget(self.forename_label, 3, 0, 1, 3)
        creation_area.addWidget(self.forename_box, 4, 0, 1, 3)
        creation_area.addWidget(self.surname_label, 5, 0, 1, 3)
        creation_area.addWidget(self.surname_box, 6, 0, 1, 3)
        creation_area.addWidget(self.password_label, 7, 0, 1, 3)
        creation_area.addWidget(self.password_box, 8, 0, 1, 3)
        creation_area.addWidget(self.password_verify_label, 9, 0, 1, 3)
        creation_area.addWidget(self.verify_password_box, 10, 0, 1, 3)
        creation_area.addWidget(self.password_match_label, 11, 0, 1, 3)
        creation_area.addWidget(self.strength_label, 12, 0, 1, 3)
        creation_area.addWidget(self.strength_feedback_label, 12, 2, 1, 1)
        creation_area.addWidget(self.feedback_label, 13, 0, 1, 3)

        button_grid = QGridLayout()
        button_grid.addWidget(self.create_button, 0, 0, 1, 2)
        button_grid.addWidget(self.cancel_button, 0, 2, 1, 1)

        user_form.addLayout(creation_area)
        user_form.addLayout(button_grid)
        user_form.addStretch(0)

        self.clear_down(True)
        self.criteria_list()
        self.setLayout(user_form)
        self.setWindowTitle('Create New User')
        self.setGeometry(WIN_LEFT, WIN_TOP, WIN_WIDTH, WIN_HEIGHT)
        self.user_box.setFocus()

    def user_released(self, key_pressed):
        """
        On keystroke evaluate details supplied
        Determine if username is available before checking other user input
        :param key_pressed: key released by user
        :return: Noe, update form
        """
        global USERNAME_AVAILABLE
        # username_avail = False
        username = self.get_username()
        feedback = 'Username must be at least 5 characters'
        if len(username) >= 5:
            USERNAME_AVAILABLE, feedback = check_username(username)
        self.user_feedback_label.setText(feedback)
        # USERNAME_AVAILABLE = username_avail
        self.criteria_list()

    def forename_released(self, key_pressed):
        """
        On keystroke evaluate details supplied
        :param key_pressed: key released by user
        :return: Noe, update form
        """
        self.criteria_list()

    def surname_released(self, key_pressed):
        """
        On keystroke evaluate details supplied
        :param key_pressed: key released by user
        :return: Noe, update form
        """
        self.criteria_list()

    def key_release(self, key_pressed):
        """
        On keystroke evaluate details supplied
        :param key_pressed: key released by user
        :return: Noe, update form
        """
        self.criteria_list()
        if key_pressed.key() == Qt.Key_Return or key_pressed.key() == Qt.Key_Enter:
            if self.create_button.isEnabled():
                self.create_attempt()

    def criteria_list(self):
        """
        Verify details of form for validity and provide password feedback to user
        :return:
        """
        username = self.get_username()
        password_input = self.get_password()
        criteria_match = criteria_check(username, password_input)

        self.feedback_label.setText(criteria_match['suggested_improvements'])
        self.strength_feedback_label.setText(criteria_match['strength']['strength_desc'])
        self.strength_feedback_label.setStyleSheet(f"background-color : {criteria_match['strength']['strength_color']}")
        self._expiry_days = criteria_match['strength']['expiry_days']

        self.set_create_enabled()

    def clear_down(self, success):
        """
        Clear down form on close, reset password box only if success is False
        :param success:
        :return:
        """
        self.password_box.setText(None)
        self.verify_password_box.setText(None)
        self.password_box.setFocus()
        if success:
            self.user_box.setText(None)
            self.forename_box.setText(None)
            self.surname_box.setText(None)
        self.criteria_list()

    def get_username(self):
        return self.user_box.text()

    def get_password(self):
        return self.password_box.text()

    def get_verify_password(self):
        return self.verify_password_box.text()

    def get_forename(self):
        return self.forename_box.text()

    def get_surname(self):
        return self.surname_box.text()

    def clicked_cancel_button(self):
        self.close()
        self.clear_down(True)
        self.user_box.setFocus()

    def create_attempt(self):
        """
        Create user within the database
        :return: None, display message box if success, then close the form
        if false, clear password fields
        """
        forename = self.get_forename()
        surname = self.get_surname()
        username = self.get_username()
        password = self.get_password()
        verify_password = self.get_verify_password()
        expiry_days = self._expiry_days

        if password != verify_password:
            create_success = False
            response_str = "Passwords do not match"
        else:
            create_success, response_str = create_new_user(username=username, forename=forename, surname=surname,
                                                           password=hash_password(password), expiry_days=expiry_days)
        if create_success:
            QMessageBox.information(self, "User created", response_str, QMessageBox.Ok, QMessageBox.Ok)
            get_user_list()
            self.close()
        else:
            QMessageBox.warning(self, "Trouble creating user", response_str, QMessageBox.Ok, QMessageBox.Ok)

    def set_create_enabled(self):
        """
        Set the amend password button to enabled/disabled dependant on if both inputs are greater in length than 0
        :return: None, Update Create button enabled state
        """
        if len(self.get_username()) == 0 or len(self.get_forename()) == 0 or len(self.get_surname()) == 0 or len(
                self.get_password()) == 0 or len(self.get_verify_password()) == 0:
            self.create_button.setEnabled(False)
        # Set enabled to False if passwords do not match
        elif self.get_password() != self.get_verify_password():
            self.create_button.setEnabled(False)
            self.password_match_label.setText('Passwords do not match')
        # Set enabled to False is username already exists
        elif not USERNAME_AVAILABLE:
            self.create_button.setEnabled(False)
        # If password is WEAK or VERY WEAK do not allow update attempt
        elif self.strength_feedback_label.text() == 'VERY WEAK' or self.strength_feedback_label.text() == 'WEAK':
            self.create_button.setEnabled(False)
        else:
            self.create_button.setEnabled(True)
