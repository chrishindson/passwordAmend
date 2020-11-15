#!/usr/bin/python3
#  File: main.py
#  Description: Password candidate Main program launch/display
#  Author: Christopher Hindson
#  Date: 31/10/2020

# Imports
import sys
from PyQt5.Qt import QGridLayout, QMessageBox, Qt
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QLabel, QLineEdit, QApplication
from new_user import NewUser
from password_check import criteria_check, database_verify, credential_verify, \
    gather_common_password_list, gather_user_list

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

        # Labels
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

        # Buttons
        self.amend_button = QPushButton('Amend Password')
        self.cancel_button = QPushButton('Cancel')
        self.signup_button = QPushButton('Create')

        # Input boxes
        self.user_box = QLineEdit()
        self.current_password_box = QLineEdit()
        self.current_password_box.setEchoMode(QLineEdit.Password)
        self.new_password_box = QLineEdit()
        self.new_password_box.setEchoMode(QLineEdit.Password)

        # Button controls
        self.amend_button.released.connect(self.amend_attempt)
        self.cancel_button.released.connect(self.clicked_cancel_button)
        self.signup_button.released.connect(self.clicked_signup_button)

        # Key press procedures
        self.new_password_box.keyReleaseEvent = self.new_password_released
        self.user_box.keyReleaseEvent = self.user_released

        # Set button disabled/enabled
        self.set_amend_button_state()

        self._expiry_days = 90
        self.dialog = NewUser()

        user_form = QVBoxLayout()

        login_area = QGridLayout()
        login_area.addWidget(self.user_label, 0, 0, 1, 3)
        login_area.addWidget(self.user_box, 1, 0, 1, 3)
        login_area.addWidget(self.current_password_label, 2, 0, 1, 3)
        login_area.addWidget(self.current_password_box, 3, 0, 1, 3)
        login_area.addWidget(self.new_password_label, 4, 0, 1, 3)
        login_area.addWidget(self.new_password_box, 5, 0, 1, 3)

        login_area.addWidget(self.strength_label, 6, 0, 1, 3)
        login_area.addWidget(self.strength_feedback_label, 6, 2, 1, 1)
        login_area.addWidget(self.suggestions_label, 7, 0, 1, 3)

        button_grid = QGridLayout()
        button_grid.addWidget(self.amend_button, 0, 0, 1, 2)
        button_grid.addWidget(self.cancel_button, 0, 2, 1, 1)

        signup_grid = QVBoxLayout()
        signup_grid.addWidget(self.signup_label)
        signup_grid.addWidget(self.signup_button)

        user_form.addLayout(login_area)
        user_form.addLayout(button_grid)
        user_form.addLayout(signup_grid)
        user_form.addStretch(0)

        self.criteria_list()

        self.setLayout(user_form)
        self.setWindowTitle('Password Change')
        self.setGeometry(WIN_LEFT, WIN_TOP, WIN_WIDTH, WIN_HEIGHT)
        self.setWindowIcon(QIcon('ico/success.svg'))
        self.show()

    def get_new_password_value(self):
        return self.new_password_box.text()

    def get_current_password_value(self):
        return self.current_password_box.text()

    def get_username_value(self):
        return self.user_box.text()

    def amend_attempt(self):
        """

        :return:
        """
        pass_update = False
        response_str = ''
        current_pass = self.get_current_password_value()
        pass_string = self.get_new_password_value()
        username = self.get_username_value()
        expiry_days = 90
        user_correct = credential_verify(username=username, password=current_pass)
        if not user_correct:
            response_str = 'No matching username or password found'
        else:
            pass_update = database_verify(username=username, password=pass_string, expiry_days=expiry_days)
            if pass_update:
                response_str = 'Password successfully updated. Your password will expire in 90 days'
            else:
                response_str = 'Password was previously used'

        if pass_update:
            QMessageBox.information(self, "Password Successfully Changed", response_str, QMessageBox.Ok, QMessageBox.Ok)
        else:
            QMessageBox.warning(self, "Password Not Updated", response_str, QMessageBox.Ok, QMessageBox.Ok)
        self.clear_down(pass_update)

    def user_released(self, key_pressed):
        """
        Function to judge password input length, prior to passing to password strength calculation function
        Once strength is returned, update the strength_label to provide feedback to the user 
        Enable/Disable the amend password button if length is below 8 characters
        :return:
        """
        self.amend_button.setEnabled(True)
        self.set_amend_button_state()

    def new_password_released(self, key_pressed):
        """
        Function to judge password input length, prior to passing to password strength calculation function
        Once strength is returned, update the strength_label to provide feedback to the user
        Enable/Disable the amend password button if length is below 8 characters
        :return:
        """
        # run the 
        if key_pressed.key() == Qt.Key_Return or key_pressed.key() == Qt.Key_Enter:
            self.amend_attempt()
            return
        self.amend_button.setEnabled(True)
        self.set_amend_button_state()

        self.criteria_list()

    def criteria_list(self):
        """

        :return:
        """
        username = self.get_username_value()
        password_input = self.get_new_password_value()
        criteria_match = criteria_check(username, password_input)

        self.suggestions_label.setText(criteria_match['suggested_improvements'])
        self.strength_feedback_label.setText(criteria_match['strength']['strength_desc'])
        self.strength_feedback_label.setStyleSheet(f"background-color : {criteria_match['strength']['strength_color']}")
        self._expiry_days = criteria_match['strength']['expiry_days']

    def clicked_cancel_button(self):
        self.close()

    def clicked_signup_button(self):
        self.dialog.show()
        self.user_box.setFocus()

    def set_amend_button_state(self):
        """
        Set the amend password button to enabled/disabled dependant on if both inputs are greater in length than 0
        :return:
        """
        if len(self.get_new_password_value()) == 0 or len(self.get_username_value()) == 0 or len(
                self.get_current_password_value()) == 0:
            self.amend_button.setEnabled(False)

    def clear_down(self, success):
        self.new_password_box.setText(None)
        self.new_password_box.setFocus()
        if success:
            self.current_password_box.setText(None)
            self.user_box.setText(None)
            self.user_box.setFocus()
        self.criteria_list()


if __name__ == '__main__':
    gather_common_password_list()
    gather_user_list()
    app = QApplication([])
    window = MainWindow()
    sys.exit(app.exec_())
