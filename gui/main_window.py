#!/usr/bin/python3
#  File: main.py
#  Description: Password candidate Main program launch/display
#  Author: Christopher Hindson
#  Date: 31/10/2020

# Imports
from PyQt5.Qt import QGridLayout, QMessageBox, Qt
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QLabel, QLineEdit
from gui.new_user import NewUser
from engine.password_check import criteria_check, database_verify, credential_verify

# CONSTANTS
WIN_LEFT = 200
WIN_TOP = 200
WIN_WIDTH = 550
WIN_HEIGHT = 400


# Globals

# Main processing


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        # Label string multi-line
        instructions = '\nSuggested criteria to create a strong password:'

        # Create Labels
        self.user_label = QLabel('Username')
        self.current_password_label = QLabel('Current Password')
        self.new_password_label = QLabel('New Password')
        self.strength_label = QLabel('Password strength: ')
        self.strength_feedback_label = QLabel(None)
        self.strength_feedback_label.setAutoFillBackground(True)
        self.strength_feedback_label.setAlignment(Qt.AlignCenter)
        self.signup_label = QLabel('Create new user? ')
        self.instructions_label = QLabel(instructions)
        self.suggestions_label = QLabel()

        # Create Buttons
        self.amend_button = QPushButton('Amend Password')
        self.cancel_button = QPushButton('Cancel')
        self.signup_button = QPushButton('Create')

        # Create Input boxes
        self.user_box = QLineEdit()
        self.current_password_box = QLineEdit()
        self.new_password_box = QLineEdit()
        # Set Line Edit to Password, so that obfuscation occurs
        self.current_password_box.setEchoMode(QLineEdit.Password)
        self.new_password_box.setEchoMode(QLineEdit.Password)

        # Button controls
        self.amend_button.released.connect(self.amend_attempt)  # Update method
        self.cancel_button.released.connect(self.clicked_cancel_button)  # Close down system
        self.signup_button.released.connect(self.clicked_signup_button)  # Launch create new user window

        # Key press procedures
        self.new_password_box.keyReleaseEvent = self.new_password_released
        self.user_box.keyReleaseEvent = self.user_released

        # Set button disabled/enabled
        # self.set_amend_button_state()

        # set default expiry days for password, will be updated on keystroke on new password
        self._expiry_days = 30

        # Overall Form Layout
        user_form = QVBoxLayout()

        # Login area creation (Widget, Row, Column, Column Start, Column Span)
        login_area = QGridLayout()
        # User input section
        login_area.addWidget(self.user_label, 0, 0, 1, 3)
        login_area.addWidget(self.user_box, 1, 0, 1, 3)
        login_area.addWidget(self.current_password_label, 2, 0, 1, 3)
        login_area.addWidget(self.current_password_box, 3, 0, 1, 3)
        login_area.addWidget(self.new_password_label, 4, 0, 1, 3)
        login_area.addWidget(self.new_password_box, 5, 0, 1, 3)
        # Password strength feedback
        login_area.addWidget(self.strength_label, 6, 0, 1, 3)
        login_area.addWidget(self.strength_feedback_label, 6, 2, 1, 1)
        login_area.addWidget(self.suggestions_label, 7, 0, 1, 3)
        # Button area
        button_grid = QGridLayout()
        button_grid.addWidget(self.amend_button, 0, 0, 1, 2)
        button_grid.addWidget(self.cancel_button, 0, 2, 1, 1)
        # Signup area
        signup_grid = QVBoxLayout()
        signup_grid.addWidget(self.signup_label)
        signup_grid.addWidget(self.signup_button)

        # Add above layouts into the main form
        user_form.addLayout(login_area)
        user_form.addLayout(button_grid)
        user_form.addLayout(signup_grid)
        user_form.addStretch(0)

        self.criteria_list()

        # Set main window information
        self.setLayout(user_form)
        self.setWindowTitle('Password Change')
        self.setGeometry(WIN_LEFT, WIN_TOP, WIN_WIDTH, WIN_HEIGHT)
        self.setWindowIcon(QIcon('ico/success.svg'))
        # Launch form
        self.show()

    def get_new_password_value(self):
        # Return new password input value
        return self.new_password_box.text()

    def get_current_password_value(self):
        # Return current password input
        return self.current_password_box.text()

    def get_username_value(self):
        # return username input
        return self.user_box.text()

    def amend_attempt(self):
        """
        Validate the existing password, if correct, then update the user_credentials table with new
        password, after encryption, supplied by user.
        A database trigger will append the current password to the user_cred_audit table
        :return:
        """
        pass_update = False
        current_pass = self.get_current_password_value()
        pass_string = self.get_new_password_value()
        username = self.get_username_value()
        expiry_days = self._expiry_days
        # Validate existing credentials function
        user_correct = credential_verify(username=username, password=current_pass)

        if not user_correct:  # User password does not match supplier user, or user was not found
            response_str = 'No matching username or password found'
        else:
            pass_update = database_verify(username=username, password=pass_string, expiry_days=expiry_days)
            if pass_update:
                response_str = f'Password successfully updated. Your password will expire in {expiry_days} days'
            else:
                response_str = 'Password was previously used'

        if pass_update:
            QMessageBox.information(self, "Password Successfully Changed", response_str, QMessageBox.Ok, QMessageBox.Ok)
        else:
            QMessageBox.warning(self, "Password Not Updated", response_str, QMessageBox.Ok, QMessageBox.Ok)

        # reset the MainDisplay form and clear as appropriate
        self.clear_down(pass_update)

    def user_released(self, key_pressed):
        """
        Function to judge password input length, prior to passing to password strength calculation function
        Once strength is returned, update the strength_label to provide feedback to the user
        Enable/Disable the amend password button if length is below 8 characters
        :return:
        """
        self.set_amend_button_state()

    def new_password_released(self, key_pressed):
        """
        Function to judge password input length, prior to passing to password strength calculation function
        Once strength is returned, update the strength_label to provide feedback to the user
        Enable/Disable the amend password button if length is below 8 characters
        :return: None
        """
        self.criteria_list()
        if key_pressed.key() == Qt.Key_Return or key_pressed.key() == Qt.Key_Enter:
            self.amend_attempt()

    def criteria_list(self):
        """
        Determine the strength of potential password and check against criteria to display details to user
        :return: None, Updated form information regarding password, potentially enabling amend button
        """
        username = self.get_username_value()
        password_input = self.get_new_password_value()
        criteria_match = criteria_check(username, password_input)

        self.suggestions_label.setText(criteria_match['suggested_improvements'])
        self.strength_feedback_label.setText(criteria_match['strength']['strength_desc'])
        self.strength_feedback_label.setStyleSheet(f"background-color : {criteria_match['strength']['strength_color']}")
        self._expiry_days = criteria_match['strength']['expiry_days']
        self.set_amend_button_state()

    def clicked_cancel_button(self):
        # Close the user form
        self.close()

    def clicked_signup_button(self):
        """
        Launch the new user window, so that the user can create setup a new user within the database
        :return: None, launches Create New User window
        """
        self.dialog = NewUser()
        self.dialog.show()
        self.user_box.setFocus()

    def set_amend_button_state(self):
        """
        Set the amend password button to enabled/disabled dependant on if both inputs are greater in length than 0
        :return: None
        """
        if len(self.get_new_password_value()) == 0 or len(self.get_username_value()) == 0 or \
                len(self.get_current_password_value()) == 0:
            self.amend_button.setEnabled(False)
        # If password is WEAK or VERY WEAK do not allow update attempt
        elif self.strength_feedback_label.text() == 'VERY WEAK' or self.strength_feedback_label.text() == 'WEAK':
            self.amend_button.setEnabled(False)
        else:
            self.amend_button.setEnabled(True)

    def clear_down(self, success):
        self.new_password_box.setText(None)
        self.new_password_box.setFocus()
        # If successful, clear whole form, else just the new password box
        if success:
            self.current_password_box.setText(None)
            self.user_box.setText(None)
            self.user_box.setFocus()
        self.criteria_list()