import unittest
from unittest.mock import Mock, patch, ANY
from server import ClientHandler

class TestClientHandler(unittest.TestCase):
    def setUp(self):
        self.client_handler = ClientHandler()

    def generate_mock_aes_key(self):
        # Generate a byte string that resembles an AES key for testing
        return b'\x00' * 32  # 256-bit AES key filled with zeros

    def test_add_client(self):
        mock_socket = Mock()
        mock_addr = ('127.0.0.1', 8082)
        mock_aes_key = self.generate_mock_aes_key()

        client_id = self.client_handler.add_client(mock_socket, mock_addr, mock_aes_key)
        self.assertIn(client_id, self.client_handler.clients)
        self.assertEqual(self.client_handler.clients[client_id]['socket'], mock_socket)

    def test_remove_client(self):
        mock_socket = Mock()
        mock_addr = ('127.0.0.1', 8082)
        mock_aes_key = self.generate_mock_aes_key()
        client_id = self.client_handler.add_client(mock_socket, mock_addr, mock_aes_key)

        self.client_handler.remove_client(client_id)
        self.assertNotIn(client_id, self.client_handler.clients)

    def test_handle_username_change(self):
        mock_socket = Mock()
        mock_addr = ('127.0.0.1', 8082)
        mock_aes_key = self.generate_mock_aes_key()
        old_client_id = self.client_handler.add_client(mock_socket, mock_addr, mock_aes_key)

        new_username = 'NewUser'
        with patch.object(self.client_handler, 'send_message_to_client') as mock_send:
            self.client_handler.handle_username_change(old_client_id, new_username)

            self.assertNotIn(old_client_id, self.client_handler.clients)
            self.assertIn(new_username, self.client_handler.clients)

            mock_send.assert_called_with(f"USERNAME_UPDATE:{old_client_id}:{new_username}", ANY)

if __name__ == '__main__':
    unittest.main()
