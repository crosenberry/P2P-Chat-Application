import unittest
from unittest.mock import Mock, patch
from server import ClientHandler
from unittest.mock import ANY


class TestClientHandler(unittest.TestCase):
    def setUp(self):
        self.client_handler = ClientHandler()

    def test_add_client(self):
        mock_socket = Mock()
        mock_addr = ('127.0.0.1', 8082)
        mock_aes_key = Mock()

        client_id = self.client_handler.add_client(mock_socket, mock_addr, mock_aes_key)
        self.assertTrue(client_id in self.client_handler.clients)
        self.assertEqual(self.client_handler.clients[client_id]['socket'], mock_socket)

    def test_remove_client(self):
        mock_socket = Mock()
        mock_addr = ('127.0.0.1', 8082)
        mock_aes_key = Mock()
        client_id = self.client_handler.add_client(mock_socket, mock_addr, mock_aes_key)

        self.client_handler.remove_client(client_id)
        self.assertFalse(client_id in self.client_handler.clients)

    def test_handle_username_change(self):
        # Add a client
        mock_socket = Mock()
        mock_addr = ('127.0.0.1', 8082)
        mock_aes_key = Mock()
        old_client_id = self.client_handler.add_client(mock_socket, mock_addr, mock_aes_key)

        # Change username
        new_username = 'NewUser'
        with patch.object(self.client_handler, 'send_message_to_client') as mock_send:
            self.client_handler.handle_username_change(old_client_id, new_username)

            # Check if old username is removed and new one is added
            self.assertFalse(old_client_id in self.client_handler.clients)
            self.assertTrue(new_username in self.client_handler.clients)

            # Check if broadcast message was sent
            mock_send.assert_called_with(f"USERNAME_UPDATE:{old_client_id}:{new_username}", ANY)

# Run the tests
if __name__ == '__main__':
    unittest.main()
