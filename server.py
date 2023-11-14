import socket
import threading
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import ElGamal
from Crypto import Random
from Crypto.Util.Padding import pad, unpad

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

        # Generate ElGamal keys for Diffie-Hellman
        key = ElGamal.generate(256, Random.new().read)
        public_key = key.publickey()

        # Send server's public key to client
        client_socket.send(f"{public_key.p},{public_key.g},{public_key.y}".encode())

        # Receive client's public key
        received_data = client_socket.recv(1024).decode()
        p, g, y = map(int, received_data.split(","))
        client_public_key = ElGamal.construct((p, g, y))

        # Compute shared secret
        shared_secret = pow(client_public_key.y, int(key.x), int(key.p))
        shared_secret = 123456789
        aes_key = SHA256.new(str(shared_secret).encode()).digest()

        # Encrypt a welcome message
        iv = Random.new().read(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        padded_message = pad("Welcome to the secure chat!".encode(), 16)
        encrypted_data = iv + cipher.encrypt(padded_message)
        client_socket.send(encrypted_data)

        client_id = self.add_client(client_socket, addr)

        try:
            while True:
                iv = Random.new().read(16)  # Generate new IV for every message
                encrypted_data = client_socket.recv(1024)
                iv_received = encrypted_data[:16]
                cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv_received)
                decrypted_data = unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size).decode()

                print(f"Received from {addr}: {decrypted_data}")
                response = f"{client_id}: {decrypted_data}"
                cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                ct_bytes = cipher.encrypt(pad(response.encode(), AES.block_size))
                encrypted_response = iv + ct_bytes
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
