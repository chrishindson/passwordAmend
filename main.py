#!/usr/bin/python3
#  File: main.py
#  Description: Password candidate Main program launch/display
#  Author: Christopher Hindson
#  Date: 31/10/2020

# Imports
import sys

from PyQt5 import QtGui
from PyQt5.Qt import *
from PyQt5.QtWidgets import (QWidget, QApplication, QVBoxLayout, QPushButton, QLabel, QLineEdit, QDialog)
from text_encryption import verify_encrypted_password, encrypt_password
from password_check import viable_password, criteria_check

# CONSTANTS
WIN_LEFT = 200
WIN_TOP = 200
WIN_WIDTH = 500
WIN_HEIGHT = 250


# Globals


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        # Label string multi-line
        instructions = '\nSuggested criteria to create a strong password:'

        # Labels
        self.user_label = QLabel('Username')
        self.password_label = QLabel('New Password')
        self.strength_label = QLabel('Password strength: ')
        self.signup_label = QLabel('Create new user? ')
        self.instructions_label = QLabel(instructions)
        self.minimum_label = QLabel('   * Minimum 8 characters')
        self.upper_label = QLabel('   * One uppercase character')
        self.lower_label = QLabel('   * One lowercase character')
        self.number_label = QLabel('   * One number character')
        self.special_label = QLabel('   * One special character')

        # Buttons
        self.amend_button = QPushButton('Amend Password')
        self.cancel_button = QPushButton('Cancel')
        self.signup_button = QPushButton('Create')

        # Input boxes
        self.user_box = QLineEdit()
        self.password_box = QLineEdit()
        self.password_box.setEchoMode(QLineEdit.Password)

        # Button controls
        self.amend_button.released.connect(self.clicked_amend_button)
        self.cancel_button.released.connect(self.clicked_cancel_button)

        # Key press procedures
        self.password_box.keyReleaseEvent = self.password_released
        self.user_box.keyReleaseEvent = self.user_released

        # Set button disabled/enabled
        self.set_amend_button_state()

        user_form = QVBoxLayout()

        login_area = QVBoxLayout()
        login_area.addWidget(self.user_label)
        login_area.addWidget(self.user_box)
        login_area.addWidget(self.password_label)
        login_area.addWidget(self.password_box)
        login_area.addWidget(self.strength_label)
        login_area.addWidget(self.instructions_label)
        login_area.addWidget(self.minimum_label)
        login_area.addWidget(self.upper_label)
        login_area.addWidget(self.lower_label)
        login_area.addWidget(self.number_label)
        login_area.addWidget(self.special_label)

        button_grid = QGridLayout()
        login_area.addStretch(1)
        button_grid.addWidget(self.amend_button, 0, 0, 1, 2)
        button_grid.addWidget(self.cancel_button, 0, 2, 1, 1)

        signup_grid = QVBoxLayout()
        signup_grid.addWidget(self.signup_label)
        signup_grid.addWidget(self.signup_button)

        user_form.addLayout(login_area)
        user_form.addLayout(button_grid)
        user_form.addLayout(signup_grid)

        self.setLayout(user_form)
        self.setWindowTitle('Password Change')
        self.setGeometry(WIN_LEFT, WIN_TOP, WIN_WIDTH, WIN_HEIGHT)
        self.show()

    def get_password_value(self):
        return self.password_box.text()

    def get_username_value(self):
        return self.user_box.text()

    def clicked_amend_button(self):
        pass_string = self.get_password_value()
        if viable_password(pass_string):
            db_pass = encrypt_password(pass_string)
            print(db_pass)
        else:
            self.strength_label.setText(None)
        # outcome_dialog = QDialog()

        # message_label = QLabel('Password successfully updated. Your password will expire in 180 days')
        # h_layout = QHBoxLayout()
        # h_layout.addWidget(message_label)
        # outcome_dialog.setLayout(h_layout)
        # outcome_dialog.show()

    def user_released(self, key_pressed):
        """
        Function to judge password input length, prior to passing to password strength calculation function
        Once strength is returned, update the strength_label to provide feedback to the user 
        Enable/Disable the amend password button if length is below 8 characters
        :return:
        """
        self.amend_button.setEnabled(True)
        self.set_amend_button_state()

    def password_released(self, key_pressed):
        """
        Function to judge password input length, prior to passing to password strength calculation function
        Once strength is returned, update the strength_label to provide feedback to the user
        Enable/Disable the amend password button if length is below 8 characters
        :return:
        """
        self.amend_button.setEnabled(True)
        self.set_amend_button_state()

        password_input = self.get_password_value()

        criteria_match = criteria_check(password_input)

        self.amend_button.setEnabled(criteria_match['length_check'])
        self.set_upper_bolden(criteria_match['upper_check'])
        self.set_lower_bolden(criteria_match['lower_check'])
        self.set_number_bolden(criteria_match['number_check'])
        self.set_special_bolden(criteria_match['special_check'])
        self.set_minimum_bolden(criteria_match['length_check'])

    def set_upper_bolden(self, re_check):
        text_change = QtGui.QFont()
        text_change.setBold(re_check)
        self.upper_label.setFont(text_change)

    def set_lower_bolden(self, re_check):
        text_change = QtGui.QFont()
        text_change.setBold(re_check)
        self.lower_label.setFont(text_change)

    def set_number_bolden(self, re_check):
        text_change = QtGui.QFont()
        text_change.setBold(re_check)
        self.number_label.setFont(text_change)

    def set_special_bolden(self, re_check):
        text_change = QtGui.QFont()
        text_change.setBold(re_check)
        self.special_label.setFont(text_change)

    def set_minimum_bolden(self, re_check):
        text_change = QtGui.QFont()
        text_change.setBold(re_check)
        self.minimum_label.setFont(text_change)

    def clicked_cancel_button(self):
        self.close()

    def set_amend_button_state(self):
        """
        Set the amend password button to enabled/disabled dependant on if both inputs are greater in length than 0
        :return:
        """
        if len(self.get_password_value()) == 0 or len(self.get_username_value()) == 0:
            self.amend_button.setEnabled(False)


if __name__ == '__main__':
    app = QApplication([])

    window = MainWindow()
    sys.exit(app.exec_())
