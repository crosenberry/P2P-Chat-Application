import socket
import threading
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import os
from gui import ChatGUI


class Client:
    def __init__(self, gui):
        self.gui = gui
        self.gui.set_send_function(self.send_message)
        self.client_socket = None
        self.aes_key = None
        self.client_name = None

    def start_client(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(('127.0.0.1', 8082))
        print("Connected to server.")

        # Generate ECDH keys for Diffie-Hellman
        client_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        client_public_key = client_private_key.public_key()

        # Send client's public key to server
        public_key_bytes = client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.client_socket.send(public_key_bytes)

        # Receive server's public key
        server_public_key_bytes = self.client_socket.recv(1024)
        server_public_key = serialization.load_pem_public_key(
            server_public_key_bytes,
            backend=default_backend()
        )

        # Compute shared secret
        shared_secret = client_private_key.exchange(ec.ECDH(), server_public_key)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(shared_secret)
        self.aes_key = digest.finalize()

        # Receive and decrypt welcome message
        self.receive_and_decrypt()

    def receive_messages(self):
        while True:
            message = self.receive_and_decrypt()
            if message:
                print(f"Received message: {message}")  # Debug print
                if message.startswith("USERNAME_UPDATE:"):
                    old_name, new_name = message.split(':')[1:]
                    print(f"Username updated from {old_name} to {new_name}")
                    # Update client's own username if necessary
                    if old_name == self.client_name:
                        self.client_name = new_name
                else:
                    self.gui.update_chat(message)  # Update GUI with received message

    def receive_and_decrypt(self):
        try:
            encrypted_response = self.client_socket.recv(1024)
            if encrypted_response:
                iv_response = encrypted_response[:16]
                cipher_response = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv_response), backend=default_backend())
                decryptor_response = cipher_response.decryptor()
                unpadder_response = PKCS7(algorithms.AES.block_size).unpadder()

                decrypted_response = decryptor_response.update(
                    encrypted_response[16:]) + decryptor_response.finalize()
                response = unpadder_response.update(decrypted_response) + unpadder_response.finalize()
                return response.decode()
        except OSError:
            return None

    def send_message(self, message):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = PKCS7(algorithms.AES.block_size).padder()
        padded_message = padder.update(message.encode()) + padder.finalize()
        encrypted_message = iv + encryptor.update(padded_message) + encryptor.finalize()
        self.client_socket.send(encrypted_message)

    def change_username(self, new_username):
        self.send_message(f"USERNAME_CHANGE:{new_username}")
        self.client_name = new_username  # Optimistically set the new username

    def on_closing(self):
        self.client_socket.close()
        self.gui.root.destroy()

if __name__ == "__main__":
    gui = ChatGUI()
    client = Client(gui)
    client.start_client()
    threading.Thread(target=client.receive_messages, daemon=True).start()
    gui.root.protocol("WM_DELETE_WINDOW", client.on_closing)
    gui.root.mainloop()