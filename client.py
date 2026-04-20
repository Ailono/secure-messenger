#!/usr/bin/python3
"""Secure Messenger client with PyQt6 GUI."""

import sys, socket, threading, json, time, logging
import crypto_utils, database
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QListWidget, QListWidgetItem, QTextEdit, QLineEdit, QPushButton,
    QLabel, QDialog, QFormLayout, QDialogButtonBox, QSplitter,
    QFrame, QScrollArea
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QDateTime
from PyQt6.QtGui import QFont, QColor, QPalette

logging.basicConfig(level=logging.INFO)

# ── Network thread ────────────────────────────────────────────────────────────

class NetworkThread(QThread):
    message_received = pyqtSignal(dict)
    connection_lost  = pyqtSignal()

    def __init__(self, sock):
        super().__init__()
        self.sock = sock

    def run(self):
        try:
            while True:
                raw = self.sock.recv(8192)
                if not raw:
                    break
                packet = json.loads(raw.decode('utf-8'))
                self.message_received.emit(packet)
        except Exception:
            pass
        self.connection_lost.emit()


# ── Login dialog ──────────────────────────────────────────────────────────────

class LoginDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Secure Messenger — Вход')
        self.setFixedSize(360, 200)
        self.setStyleSheet(STYLE)

        layout = QFormLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(24, 24, 24, 24)

        self.host_input = QLineEdit('127.0.0.1')
        self.port_input = QLineEdit('9999')
        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText('Ваш никнейм')

        layout.addRow('Сервер:', self.host_input)
        layout.addRow('Порт:', self.port_input)
        layout.addRow('Имя пользователя:', self.user_input)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok |
                                QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addRow(btns)

    def values(self):
        return self.host_input.text(), int(self.port_input.text()), self.user_input.text().strip()


# ── Message bubble ────────────────────────────────────────────────────────────

class MessageBubble(QFrame):
    def __init__(self, sender: str, text: str, ts: float, is_mine: bool):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)
        layout.setSpacing(2)

        time_str = QDateTime.fromSecsSinceEpoch(int(ts)).toString('hh:mm')
        header = QLabel(f"{'Вы' if is_mine else sender}  {time_str}")
        header.setStyleSheet('color: #888; font-size: 11px;')

        body = QLabel(text)
        body.setWordWrap(True)
        body.setFont(QFont('Segoe UI', 11))
        body.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        layout.addWidget(header)
        layout.addWidget(body)

        if is_mine:
            self.setStyleSheet('background:#2b5278; border-radius:12px; margin-left:60px;')
            header.setAlignment(Qt.AlignmentFlag.AlignRight)
            body.setAlignment(Qt.AlignmentFlag.AlignRight)
        else:
            self.setStyleSheet('background:#1e2d3d; border-radius:12px; margin-right:60px;')


# ── Main window ───────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    def __init__(self, sock: socket.socket, username: str, recipient: str):
        super().__init__()
        self.sock = sock
        self.username = username
        self.recipient = recipient
        self.session_key = None  # set after key exchange

        # Generate our ephemeral key pair
        self.private_key, self.public_key = crypto_utils.generate_keypair()

        self.setWindowTitle(f'Secure Messenger — {username}')
        self.resize(800, 600)
        self.setStyleSheet(STYLE)

        self._build_ui()
        self._start_network()
        self._initiate_key_exchange()
        self._load_history()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Sidebar ──
        sidebar = QFrame()
        sidebar.setFixedWidth(220)
        sidebar.setStyleSheet('background:#1a2535; border-right:1px solid #2a3a50;')
        sb_layout = QVBoxLayout(sidebar)
        sb_layout.setContentsMargins(0, 0, 0, 0)

        title = QLabel('💬 Secure Messenger')
        title.setStyleSheet('color:#5b9bd5; font-size:14px; font-weight:bold; padding:16px;')
        sb_layout.addWidget(title)

        self.contact_list = QListWidget()
        self.contact_list.setStyleSheet('''
            QListWidget { background:#1a2535; border:none; color:#ccc; }
            QListWidget::item:selected { background:#2b5278; border-radius:6px; }
            QListWidget::item { padding:10px 16px; }
        ''')
        item = QListWidgetItem(f'👤 {self.recipient}')
        item.setForeground(QColor('#e0e0e0'))
        self.contact_list.addItem(item)
        self.contact_list.setCurrentRow(0)
        sb_layout.addWidget(self.contact_list)
        sb_layout.addStretch()

        me_label = QLabel(f'🔒 {self.username}')
        me_label.setStyleSheet('color:#5b9bd5; padding:12px; font-size:12px;')
        sb_layout.addWidget(me_label)

        # ── Chat area ──
        chat_frame = QFrame()
        chat_layout = QVBoxLayout(chat_frame)
        chat_layout.setContentsMargins(0, 0, 0, 0)
        chat_layout.setSpacing(0)

        # Header
        header = QFrame()
        header.setFixedHeight(52)
        header.setStyleSheet('background:#1e2d3d; border-bottom:1px solid #2a3a50;')
        h_layout = QHBoxLayout(header)
        h_layout.setContentsMargins(16, 0, 16, 0)
        self.chat_title = QLabel(f'👤 {self.recipient}')
        self.chat_title.setStyleSheet('color:#e0e0e0; font-size:14px; font-weight:bold;')
        self.status_label = QLabel('🔑 Обмен ключами...')
        self.status_label.setStyleSheet('color:#f0a500; font-size:11px;')
        h_layout.addWidget(self.chat_title)
        h_layout.addStretch()
        h_layout.addWidget(self.status_label)

        # Messages scroll area
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setStyleSheet('QScrollArea { border:none; background:#16212e; }')
        self.msg_container = QWidget()
        self.msg_container.setStyleSheet('background:#16212e;')
        self.msg_layout = QVBoxLayout(self.msg_container)
        self.msg_layout.setContentsMargins(12, 12, 12, 12)
        self.msg_layout.setSpacing(6)
        self.msg_layout.addStretch()
        self.scroll.setWidget(self.msg_container)

        # Input area
        input_frame = QFrame()
        input_frame.setFixedHeight(64)
        input_frame.setStyleSheet('background:#1e2d3d; border-top:1px solid #2a3a50;')
        i_layout = QHBoxLayout(input_frame)
        i_layout.setContentsMargins(12, 10, 12, 10)

        self.input = QLineEdit()
        self.input.setPlaceholderText('Введите сообщение...')
        self.input.setStyleSheet('''
            QLineEdit {
                background:#16212e; color:#e0e0e0; border:1px solid #2a3a50;
                border-radius:20px; padding:8px 16px; font-size:13px;
            }
            QLineEdit:focus { border:1px solid #5b9bd5; }
        ''')
        self.input.returnPressed.connect(self.send_message)

        send_btn = QPushButton('➤')
        send_btn.setFixedSize(42, 42)
        send_btn.setStyleSheet('''
            QPushButton {
                background:#2b5278; color:white; border-radius:21px;
                font-size:16px; border:none;
            }
            QPushButton:hover { background:#3a6a9a; }
            QPushButton:pressed { background:#1e3d5c; }
        ''')
        send_btn.clicked.connect(self.send_message)

        i_layout.addWidget(self.input)
        i_layout.addWidget(send_btn)

        chat_layout.addWidget(header)
        chat_layout.addWidget(self.scroll)
        chat_layout.addWidget(input_frame)

        root.addWidget(sidebar)
        root.addWidget(chat_frame)

    def _start_network(self):
        self.net = NetworkThread(self.sock)
        self.net.message_received.connect(self.on_packet)
        self.net.connection_lost.connect(self.on_disconnect)
        self.net.start()

    def _initiate_key_exchange(self):
        """Send our public key to the recipient."""
        pub_bytes = crypto_utils.public_key_to_bytes(self.public_key)
        self._send_packet({
            'type': 'key_exchange',
            'from': self.username,
            'to': self.recipient,
            'pubkey': pub_bytes.hex()
        })

    def _load_history(self):
        database.init_db()
        for msg in database.get_history(self.username, self.recipient):
            # History stores ciphertext — decrypt on load if session key available
            if self.session_key:
                try:
                    text = crypto_utils.decrypt(bytes.fromhex(msg['ciphertext']), self.session_key)
                    self._add_bubble(msg['sender'], text, msg['ts'])
                except Exception:
                    pass  # Skip undecryptable (different session key)

    def _send_packet(self, packet: dict):
        try:
            self.sock.sendall(json.dumps(packet).encode('utf-8'))
        except Exception as e:
            logging.error(f"Send error: {e}")

    def send_message(self):
        text = self.input.text().strip()
        if not text or not self.session_key:
            if not self.session_key:
                self.status_label.setText('⚠️ Ключ ещё не согласован')
            return

        encrypted = crypto_utils.encrypt(text, self.session_key)
        ciphertext_hex = encrypted.hex()
        self._send_packet({
            'type': 'message',
            'from': self.username,
            'to': self.recipient,
            'data': ciphertext_hex
        })

        ts = time.time()
        self._add_bubble(self.username, text, ts)
        # Store only the encrypted blob — plaintext never written to disk
        database.store_message(self.username, self.recipient, ciphertext_hex)
        self.input.clear()

    def on_packet(self, packet: dict):
        ptype = packet.get('type')

        if ptype == 'key_exchange':
            peer_pub = crypto_utils.public_key_from_bytes(bytes.fromhex(packet['pubkey']))
            shared = crypto_utils.compute_shared_secret(self.private_key, peer_pub)
            self.session_key = crypto_utils.derive_keys(shared)
            self.status_label.setText('🔒 Зашифровано (E2E)')
            self.status_label.setStyleSheet('color:#4caf50; font-size:11px;')
            # Send our key back if we haven't yet (responder side)
            if packet.get('from') == self.recipient:
                self._initiate_key_exchange()

        elif ptype == 'message':
            if not self.session_key:
                return
            try:
                text = crypto_utils.decrypt(bytes.fromhex(packet['data']), self.session_key)
                ts = time.time()
                self._add_bubble(packet['from'], text, ts)
                # Store only the encrypted blob
                database.store_message(packet['from'], self.username, packet['data'])
            except Exception as e:
                logging.error(f"Decrypt error: {e}")

        elif ptype == 'error':
            self.status_label.setText(f"⚠️ {packet.get('msg')}")
            self.status_label.setStyleSheet('color:#f44336; font-size:11px;')

    def on_disconnect(self):
        self.status_label.setText('❌ Соединение потеряно')
        self.status_label.setStyleSheet('color:#f44336; font-size:11px;')

    def _add_bubble(self, sender: str, text: str, ts: float):
        is_mine = sender == self.username
        bubble = MessageBubble(sender, text, ts, is_mine)
        # Insert before the trailing stretch
        self.msg_layout.insertWidget(self.msg_layout.count() - 1, bubble)
        # Scroll to bottom
        self.scroll.verticalScrollBar().setValue(
            self.scroll.verticalScrollBar().maximum()
        )


# ── Stylesheet ────────────────────────────────────────────────────────────────

STYLE = '''
    QWidget { background:#16212e; color:#e0e0e0; font-family:"Segoe UI"; }
    QDialog { background:#1a2535; }
    QLineEdit { background:#16212e; color:#e0e0e0; border:1px solid #2a3a50; border-radius:6px; padding:6px; }
    QLabel { color:#e0e0e0; }
    QDialogButtonBox QPushButton {
        background:#2b5278; color:white; border:none;
        border-radius:6px; padding:6px 16px;
    }
    QDialogButtonBox QPushButton:hover { background:#3a6a9a; }
    QScrollBar:vertical { background:#16212e; width:6px; }
    QScrollBar::handle:vertical { background:#2a3a50; border-radius:3px; }
'''


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')

    dlg = LoginDialog()
    if dlg.exec() != QDialog.DialogCode.Accepted:
        sys.exit(0)

    host, port, username = dlg.values()
    if not username:
        sys.exit(1)

    # Ask for recipient
    from PyQt6.QtWidgets import QInputDialog
    recipient, ok = QInputDialog.getText(None, 'Собеседник', 'Имя собеседника:')
    if not ok or not recipient.strip():
        sys.exit(1)
    recipient = recipient.strip()

    # Connect to server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    sock.sendall(json.dumps({'type': 'register', 'username': username}).encode('utf-8'))
    ack = json.loads(sock.recv(1024).decode('utf-8'))
    if ack.get('type') != 'ack':
        print('Ошибка регистрации на сервере')
        sys.exit(1)

    window = MainWindow(sock, username, recipient)
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
