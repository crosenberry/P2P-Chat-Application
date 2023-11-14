import socket
import threading
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import ElGamal
from Crypto import Random
from Crypto.Util.Padding import pad, unpad
import tkinter as tk
from tkinter import scrolledtext

def start_client(gui):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 8082))
    print("Connected to server.")

    # Generate ElGamal keys for Diffie-Hellman
    key = ElGamal.generate(256, Random.new().read)

    # Send client's public key to server
    client_socket.send(f"{key.p},{key.g},{key.y}".encode())

    # Receive server's public key
    received_data = client_socket.recv(1024).decode()
    print(f"Client received: {received_data}")
    p, g, y = map(int, received_data.split(","))
    server_public_key = ElGamal.construct((p, g, y))

    # Compute shared secret
    shared_secret = pow(server_public_key.y, int(key.x), int(key.p))
    print(f"Client Shared Secret: {shared_secret}")
    shared_secret = 123456789
    aes_key = SHA256.new(str(shared_secret).encode()).digest()
    print(f"Client AES Key: {aes_key.hex()}")

    # Receive and decrypt welcome message
    encrypted_response = client_socket.recv(1024)
    iv = encrypted_response[:16]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_response[16:])
    decrypted_message = unpad(decrypted_data, AES.block_size).decode()
    print(f"Server says: {decrypted_message}")
    gui.update_chat(f"Server says: {decrypted_message}")
    def receive_messages():
        while True:
            try:
                encrypted_response = client_socket.recv(1024)
                if encrypted_response:
                    iv_response = encrypted_response[:16]
                    cipher_response = AES.new(aes_key, AES.MODE_CBC, iv=iv_response)
                    decrypted_response = cipher_response.decrypt(encrypted_response[16:])
                    response = unpad(decrypted_response, AES.block_size).decode()
                    gui.update_chat(response)
            except OSError:  # Possibly client has left the chat.
                break

    threading.Thread(target=receive_messages).start()

    def send_message(message):
        iv = Random.new().read(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
        encrypted_message = iv + ct_bytes
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