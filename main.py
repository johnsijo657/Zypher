import sys
import os
import stat
import base64
import json
import re
import hmac
import hashlib
from PySide6.QtWidgets import QApplication, QMainWindow, QFileDialog, QMessageBox, QDialog, QVBoxLayout, QLabel, QLineEdit, QPushButton
from PySide6.QtGui import QIcon
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from design import Ui_MainWindow
from PySide6.QtCore import Qt

# Define a modern dark theme stylesheet
MODERN_DARK_THEME = """
    QMainWindow {
        background-color: #2E3440;
    }
    QLabel {
        color: #ECEFF4;
        font-size: 14px;
    }
    QPushButton {
        background-color: #4C566A;
        color: #ECEFF4;
        border: 1px solid #5E81AC;
        border-radius: 5px;
        padding: 8px;
        font-size: 14px;
    }
    QPushButton:hover {
        background-color: #5E81AC;
    }
    QPushButton:pressed {
        background-color: #81A1C1;
    }
    QLineEdit {
        background-color: #3B4252;
        color: #ECEFF4;
        border: 1px solid #5E81AC;
        border-radius: 5px;
        padding: 5px;
        font-size: 14px;
    }
    QDialog {
        background-color: #2E3440;
    }
    QMessageBox {
        background-color: #2E3440;
    }
    QMessageBox QLabel {
        color: #ECEFF4;
    }
    QMessageBox QPushButton {
        background-color: #4C566A;
        color: #ECEFF4;
        border: 1px solid #5E81AC;
        border-radius: 5px;
        padding: 8px;
        font-size: 14px;
    }
    QMessageBox QPushButton:hover {
        background-color: #5E81AC;
    }
    QMessageBox QPushButton:pressed {
        background-color: #81A1C1;
    }
"""


class PasswordDialog(QDialog):
    """ Custom dialog to ask for password input. """
    def __init__(self, title):
        super().__init__()
        self.setWindowTitle(title)
        self.setFixedSize(300, 150)

        layout = QVBoxLayout()
        self.label = QLabel("Enter Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.ok_button = QPushButton("OK")
        self.cancel_button = QPushButton("Cancel")

        layout.addWidget(self.label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.ok_button)
        layout.addWidget(self.cancel_button)

        self.setLayout(layout)

        # Connect buttons
        self.ok_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)

    def get_password(self):
        """Returns entered password when OK is clicked."""
        return self.password_input.text()


class FileEncryptorApp(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        # Set the window title
        self.setWindowTitle("Zypher")  # Change this to your desired title

        # Set the window icon
        icon_path = "lock.png"  # Path to your icon file
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))  # Set the custom icon
        else:
            print(f"Icon file not found at: {icon_path}")

        # Connect buttons to functions
        self.ui.btn_select_file.clicked.connect(self.encrypt_file)
        self.ui.btn_decrypt_file.clicked.connect(self.decrypt_file)

    def is_password_strong(self, password):
        """Check if the password is strong."""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long."
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter."
        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter."
        if not re.search(r"[0-9]", password):
            return False, "Password must contain at least one digit."
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return False, "Password must contain at least one special character."
        return True, "Password is strong."

    def derive_key(self, password, salt):
        """Derives a cryptographic key from the password and salt."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))  # Encode password to UTF-8

    def generate_salt(self):
        """Generates a secure random salt."""
        return os.urandom(16)

    def generate_hmac(self, key, data):
        """Generates an HMAC for integrity verification."""
        hmac_key = hashlib.sha256(key).digest()  # Derive HMAC key from encryption key
        return hmac.new(hmac_key, data, hashlib.sha256).digest()

    def save_metadata(self, file_path, salt, hmac_digest):
        """Saves the salt and HMAC for key derivation and integrity verification."""
        metadata = {
            "salt": base64.b64encode(salt).decode(),
            "hmac": base64.b64encode(hmac_digest).decode()
        }
        meta_file_path = file_path + ".enc.meta"  # Changed extension to avoid conflicts
        with open(meta_file_path, "w") as meta_file:
            json.dump(metadata, meta_file)

    def load_metadata(self, file_path):
        """Loads the salt and HMAC from the metadata file."""
        meta_file_path = file_path + ".enc.meta"  # Changed extension to avoid conflicts
        if not os.path.exists(meta_file_path):
            return None, None
        with open(meta_file_path, "r") as meta_file:
            metadata = json.load(meta_file)
            salt = base64.b64decode(metadata["salt"])
            hmac_digest = base64.b64decode(metadata["hmac"])
            return salt, hmac_digest

    def encrypt_file(self):
        """Encrypts the original file in-place and locks access."""
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt")
        if not file_path:
            return

        password = self.get_password_dialog("Encryption Password")
        if not password:
            return

        # Validate password strength
        is_strong, message = self.is_password_strong(password)
        if not is_strong:
            QMessageBox.warning(self, "Weak Password", message)
            return

        salt = self.generate_salt()
        key = self.derive_key(password, salt)
        fernet = Fernet(key)

        try:
            with open(file_path, "rb") as file:
                original_data = file.read()

            # Generate HMAC for integrity verification
            hmac_digest = self.generate_hmac(key, original_data)

            encrypted_data = fernet.encrypt(original_data)

            with open(file_path, "wb") as file:
                file.write(encrypted_data)

            # Save salt and HMAC for later decryption and integrity verification
            self.save_metadata(file_path, salt, hmac_digest)

            # Restrict file access (Windows & Linux)
            self.restrict_file_access(file_path)

            QMessageBox.information(self, "Success", f"File '{file_path}' has been encrypted and locked.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Encryption failed: {e}")

    def decrypt_file(self):
        """Decrypts the file in-place and restores access."""
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Encrypted File")
        if not file_path:
            return

        stored_salt, stored_hmac = self.load_metadata(file_path)
        if stored_salt is None or stored_hmac is None:
            QMessageBox.critical(self, "Error", "Missing metadata! Cannot decrypt.")
            return

        password = self.get_password_dialog("Decryption Password")
        if not password:
            return

        # Restore file access BEFORE decryption
        self.restore_file_access(file_path)

        key = self.derive_key(password, stored_salt)
        fernet = Fernet(key)

        try:
            with open(file_path, "rb") as file:
                encrypted_data = file.read()

            decrypted_data = fernet.decrypt(encrypted_data)

            # Verify HMAC for integrity
            hmac_digest = self.generate_hmac(key, decrypted_data)
            if not hmac.compare_digest(hmac_digest, stored_hmac):
                QMessageBox.critical(self, "Error", "Integrity check failed! The file may have been tampered with.")
                return

            with open(file_path, "wb") as file:
                file.write(decrypted_data)

            # Remove metadata file
            os.remove(file_path + ".enc.meta")

            QMessageBox.information(self, "Success", f"File '{file_path}' has been decrypted and unlocked.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Decryption failed: {e}")

    def get_password_dialog(self, title):
        """Opens the password dialog and returns user input."""
        dialog = PasswordDialog(title)
        result = dialog.exec()
        if result == QDialog.DialogCode.Accepted:
            return dialog.get_password()
        return None

    def restrict_file_access(self, file_path):
        """Restricts access to the file so that no other application can open it."""
        try:
            if os.name == "nt":  # Windows
                os.chmod(file_path, stat.S_IREAD)  # Read-only
            else:  # Linux/Mac
                os.chmod(file_path, 0o000)  # No permissions
        except Exception as e:
            print(f"Failed to restrict access: {e}")

    def restore_file_access(self, file_path):
        """Restores full access to the file after decryption."""
        try:
            if os.name == "nt":  # Windows
                os.chmod(file_path, stat.S_IWRITE | stat.S_IREAD)  # Read & Write
            else:  # Linux/Mac
                os.chmod(file_path, 0o644)  # User: Read/Write, Others: Read
        except Exception as e:
            print(f"Failed to restore access: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)

    # Apply the modern dark theme stylesheet
    app.setStyleSheet(MODERN_DARK_THEME)

    window = FileEncryptorApp()
    window.show()
    sys.exit(app.exec())