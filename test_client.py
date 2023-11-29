import unittest
from unittest.mock import Mock, patch, MagicMock
import socket
import os
from cryptography.hazmat.primitives import serialization, hashes, padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from client import Client


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
    def test_start_client(self, mock_socket):
        mock_socket_instance = mock_socket.return_value
        mock_socket_instance.recv.return_value = os.urandom(1024)  # Mock server's public key

        self.client.start_client()

        mock_socket.assert_called_with(socket.AF_INET, socket.SOCK_STREAM)
        mock_socket_instance.connect.assert_called_with(('127.0.0.1', 8082))
        self.assertIsNotNone(self.client.client_socket)
        self.assertIsNotNone(self.client.aes_key)
        # Ensure public key is sent
        mock_socket_instance.send.assert_called()

    # Mock the cryptographic and socket functions for receive_and_decrypt
    @patch('cryptography.hazmat.primitives.ciphers.Cipher')
    @patch('socket.socket')
    def test_receive_and_decrypt(self, mock_socket, mock_cipher):
        # This is gonna be rough
        pass

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
