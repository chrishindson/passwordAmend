#!/usr/bin/python3
#  File: main.py
#  Description: Password candidate Main program launch/display
#  Author: Christopher Hindson
#  Date: 31/10/2020

# Imports
import sys
from PyQt5.QtWidgets import QApplication
from gui.main_window import MainWindow
from engine.password_check import get_common_password_list, get_user_list

# CONSTANTS


# Globals

# Main processing
def main():
    """
    Create the GUI for the Main Password change program
    :return:
    """
    # Get common passwords, used to judge password candidate
    get_common_password_list()
    # Get user list details, used to judge password against the user details of the supplied username only
    get_user_list()
    app = QApplication([])
    window = MainWindow()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
