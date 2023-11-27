import os
import socket
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.asymmetric import ec


class ClientHandler:
    def __init__(self):
        self.clients = {}
        self.client_count = 0

    def add_client(self, client_socket, addr):
        self.client_count += 1
        client_id = f"Client_{self.client_count}"  # Unique identifier for each client
        self.clients[client_id] = (client_socket, addr)
        return client_id

    def remove_client(self, client_id):
        if client_id in self.clients:
            del self.clients[client_id]

    def handle_client(self, client_socket, addr):
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

        # Compute shared secret
        shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(shared_secret)
        aes_key = digest.finalize()

        # Encrypt a welcome message
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = PKCS7(algorithms.AES.block_size).padder()
        padded_message = padder.update("Welcome to the secure chat!".encode()) + padder.finalize()
        encrypted_data = iv + encryptor.update(padded_message) + encryptor.finalize()
        client_socket.send(encrypted_data)

        client_id = self.add_client(client_socket, addr)

        try:
            while True:
                iv = os.urandom(16)  # Generate new IV for every message
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

                print(f"Received from {addr}: {decrypted_data}")
                response = f"{client_id}: {decrypted_data}"

                cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                padder = PKCS7(algorithms.AES.block_size).padder()
                padded_response = padder.update(response.encode()) + padder.finalize()
                encrypted_response = iv + encryptor.update(padded_response) + encryptor.finalize()

                client_socket.send(encrypted_response)

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
