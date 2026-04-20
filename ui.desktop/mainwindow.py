#!/usr/bin/python3
"""Qt MainWindow bindings for the Secure Messenger desktop UI."""

import sys
from PyQt6.QtWidgets import QApplication, QMainWindow, QListWidgetItem
from PyQt6.uic import loadUi


class MainWindow(QMainWindow):
    def __init__(self, username: str):
        super().__init__()
        loadUi('messenger.ui', self)
        self.username = username
        self.sendButton.clicked.connect(self.on_send)

    def on_send(self):
        text = self.messageInput.text().strip()
        if not text:
            return
        # TODO: wire up to main.send_message with actual recipient
        self.messageList.addItem(QListWidgetItem(f"[You]: {text}"))
        self.messageInput.clear()


def run(username: str):
    app = QApplication(sys.argv)
    window = MainWindow(username)
    window.show()
    sys.exit(app.exec())
