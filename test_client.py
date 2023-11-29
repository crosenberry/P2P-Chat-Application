import unittest
from unittest.mock import Mock, patch
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from client import Client


def generate_mock_ec_public_key_pem():
    # Generate a private key for use in creating an ECC public key
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    # Serialize public key in PEM format
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem


class TestClient(unittest.TestCase):

    def setUp(self):
        self.gui_mock = Mock()
        self.client = Client(self.gui_mock)

    def test_init(self):
        self.assertEqual(self.client.gui, self.gui_mock)
        self.assertIsNone(self.client.client_socket)
        self.assertIsNone(self.client.aes_key)
        self.assertIsNone(self.client.client_name)
        # Ensure set_send_function was called on the GUI mock
        self.gui_mock.set_send_function.assert_called_with(self.client.send_message)

    @patch('socket.socket')
    def test_send_message(self, mock_socket):
        self.client.aes_key = os.urandom(32)  # Mock AES key
        self.client.client_socket = mock_socket.return_value
        self.client.send_message("test message")

        # Test if message is sent through the socket
        self.client.client_socket.send.assert_called()

    def test_change_username(self):
        new_username = "new_username"
        self.client.send_message = Mock()
        self.client.change_username(new_username)
        self.client.send_message.assert_called_with(f"USERNAME_CHANGE:{new_username}")
        self.assertEqual(self.client.client_name, new_username)

    def test_on_closing(self):
        self.client.client_socket = Mock()
        self.client.gui = Mock()
        self.client.on_closing()
        self.client.client_socket.close.assert_called()
        self.client.gui.root.destroy.assert_called()


if __name__ == '__main__':
    unittest.main()
