import os
import socket
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.asymmetric import ec
from threading import Lock


class ClientHandler:
    def __init__(self):
        self.clients = {}  # Dictionary to store client information
        self.client_count = 0  # Counter for the number of clients
        self.lock = Lock()  # Initialize the lock

    def broadcast_client_list(self):
        """Sends the list of connected clients to all clients."""
        client_list = ','.join(self.clients.keys())
        for client_id, client_info in self.clients.items():
            self.send_message_to_client(client_list, client_id, update=True)

    def handle_username_change(self, old_client_id, new_username):
        """Allows a user to change their display name."""
        with self.lock:
            if new_username in self.clients:
                # If username is taken, inform the client
                self.send_message_to_client("Username change rejected. Name already in use.", old_client_id)
            else:
                # Update the client's identifier
                client_info = self.clients.pop(old_client_id)
                self.clients[new_username] = client_info
                self.broadcast_message(f"USERNAME_UPDATE:{old_client_id}:{new_username}")

    def add_client(self, client_socket, addr, aes_key):
        """Adds a new client to the server."""
        with self.lock:
            self.client_count += 1
            client_id = f"Client_{self.client_count}"
            self.clients[client_id] = {'socket': client_socket, 'addr': addr, 'aes_key': aes_key}
            self.broadcast_client_list()
            return client_id

    def send_message_to_client(self, message, client_id, update=False):
        """Send a message to a specific client."""
        client = self.clients.get(client_id)
        if not client:
            return  # Client not found

        aes_key = client['aes_key']
        client_socket = client['socket']
        iv = os.urandom(16)
        print(f"aes_key:", aes_key)
        print(f"iv:", iv)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = PKCS7(algorithms.AES.block_size).padder()
        padded_message = padder.update(message.encode()) + padder.finalize()
        encrypted_message = iv + encryptor.update(padded_message) + encryptor.finalize()
        client_socket.send(encrypted_message)

    def remove_client(self, client_id):
        with self.lock:
            if client_id in self.clients:
                del self.clients[client_id]
                self.broadcast_client_list()

    def broadcast_message(self, message):
        """Broadcast a message to all clients."""
        for client_id, client_info in self.clients.items():
            self.send_message_to_client(message, client_id)

    def handle_client(self, client_socket, addr):
        """Handle the client connection."""
        print(f"Connection established with {addr}")

        # Generate ECDH keys for Diffie-Hellman
        server_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        server_public_key = server_private_key.public_key()

        # Send server's public key to client
        public_key_bytes = server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        client_socket.send(public_key_bytes)

        # Receive client's public key
        client_public_key_bytes = client_socket.recv(1024)
        client_public_key = serialization.load_pem_public_key(
            client_public_key_bytes,
            backend=default_backend()
        )

        # Compute shared secret and generate AES key
        shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(shared_secret)
        aes_key = digest.finalize()

        # Encrypt a welcome message and send it
        self.send_message_to_client("Welcome to the secure chat!", client_socket)

        client_id = self.add_client(client_socket, addr, aes_key)

        try:
            while True:
                iv = os.urandom(16)
                encrypted_data = client_socket.recv(1024)
                if not encrypted_data:
                    break

                iv_received = encrypted_data[:16]
                cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv_received), backend=default_backend())
                decryptor = cipher.decryptor()
                unpadder = PKCS7(algorithms.AES.block_size).unpadder()

                decrypted_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
                decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()
                decrypted_data = decrypted_data.decode()

                # Remove leading colon if present
                if decrypted_data.startswith(":"):
                    decrypted_data = decrypted_data[1:]

                print(f"Received from {addr}: {decrypted_data}")

                # If the message is a username change request
                if decrypted_data.startswith("USERNAME_CHANGE:"):
                    _, new_username = decrypted_data.split(':', 1)
                    self.handle_username_change(client_id, new_username)
                    # After a successful username change, the client_id variable should be updated
                    client_id = new_username  # Update the client_id with the new username
                elif ':' in decrypted_data:
                    target_client_id, target_msg = decrypted_data.split(':', 1)
                    # Check if the message is for a specific client or a broadcast
                    if target_client_id == "Broadcast":
                        self.broadcast_message(f"{client_id}: {target_msg}")
                    elif target_client_id in self.clients:
                        # Send the message to the specific client
                        self.send_message_to_client(f"{client_id}: {target_msg}", target_client_id)
                    else:
                        print(f"Target client {target_client_id} not found")

        except Exception as e:
            print(f"Error with connection from {addr}: {e}")
        finally:
            print(f"Connection from {addr} closed.")
            self.remove_client(client_id)
            client_socket.close()

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', 8082))
    server_socket.listen(5)
    print("Server started and waiting for connections...")

    handler = ClientHandler()

    try:
        while True:
            client_socket, addr = server_socket.accept()
            client_thread = threading.Thread(target=handler.handle_client, args=(client_socket, addr))
            client_thread.start()
    except KeyboardInterrupt:
        print("\nShutting down the server...")
    finally:
        server_socket.close()


if __name__ == "__main__":
    start_server()
