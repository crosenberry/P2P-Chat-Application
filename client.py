import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import os

def start_client(gui):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 8082))
    print("Connected to server.")

    # Generate ECDH keys for Diffie-Hellman
    client_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    client_public_key = client_private_key.public_key()

    # Send client's public key to server
    public_key_bytes = client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    client_socket.send(public_key_bytes)

    # Receive server's public key
    server_public_key_bytes = client_socket.recv(1024)
    server_public_key = serialization.load_pem_public_key(
        server_public_key_bytes,
        backend=default_backend()
    )

    # Compute shared secret
    shared_secret = client_private_key.exchange(ec.ECDH(), server_public_key)
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(shared_secret)
    aes_key = digest.finalize()

    # Receive and decrypt welcome message
    encrypted_response = client_socket.recv(1024)
    iv = encrypted_response[:16]
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()

    decrypted_data = decryptor.update(encrypted_response[16:]) + decryptor.finalize()
    decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()
    decrypted_message = decrypted_data.decode()
    print(f"Server says: {decrypted_message}")
    gui.update_chat(f"Server says: {decrypted_message}")

    def receive_messages():
        while True:
            try:
                encrypted_response = client_socket.recv(1024)
                if encrypted_response:
                    iv_response = encrypted_response[:16]
                    cipher_response = Cipher(algorithms.AES(aes_key), modes.CBC(iv_response), backend=default_backend())
                    decryptor_response = cipher_response.decryptor()
                    unpadder_response = PKCS7(algorithms.AES.block_size).unpadder()

                    decrypted_response = decryptor_response.update(encrypted_response[16:]) + decryptor_response.finalize()
                    response = unpadder_response.update(decrypted_response) + unpadder_response.finalize()
                    response = response.decode()
                    gui.update_chat(response)
            except OSError:  # Possibly client has left the chat.
                break

    threading.Thread(target=receive_messages).start()

    def send_message(message):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = PKCS7(algorithms.AES.block_size).padder()
        padded_message = padder.update(message.encode()) + padder.finalize()
        encrypted_message = iv + encryptor.update(padded_message) + encryptor.finalize()
        client_socket.send(encrypted_message)

    def on_closing():
        client_socket.close()
        gui.root.destroy()

    gui.set_send_function(send_message)
    gui.root.protocol("WM_DELETE_WINDOW", on_closing)

class ChatGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("P2P Chat Client")

        self.chat_log = scrolledtext.ScrolledText(self.root, state='disabled')
        self.chat_log.grid(row=0, column=0, columnspan=2)

        self.msg_entry = tk.Entry(self.root)
        self.msg_entry.grid(row=1, column=0)

        self.send_button = tk.Button(self.root, text="Send", command=self.send_msg)
        self.send_button.grid(row=1, column=1)

        self.send_function = None

        # Start a thread for listening to messages from the server
        threading.Thread(target=self.receive_messages, daemon=True).start()

    def receive_messages(self):
        while True:
            try:
                # Assuming 'client_socket' is your socket object and 'aes_key' is your AES key
                encrypted_response = client_socket.recv(1024)
                if encrypted_response:
                    iv = encrypted_response[:16]
                    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                    decrypted_response = unpad(cipher.decrypt(encrypted_response[16:]), AES.block_size).decode()

                    # Use Tkinter's thread-safe method to update the chat window
                    self.chat_log.insert(tk.END, decrypted_response + '\n')
            except Exception as e:
                print(f"Error receiving message: {e}")
                break

    def set_send_function(self, send_function):
        self.send_function = send_function

    def send_msg(self):
        message = self.msg_entry.get()
        if message and self.send_function:
            self.send_function(message)
            self.msg_entry.delete(0, tk.END)

    def update_chat(self, message):
        self.chat_log.config(state='normal')
        self.chat_log.insert(tk.END, message + '\n')
        self.chat_log.config(state='disabled')
        self.chat_log.yview(tk.END)

if __name__ == "__main__":
    gui = ChatGUI()
    start_client(gui)
    gui.root.mainloop()