import socket
import threading
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import ElGamal
from Crypto import Random
from Crypto.Util.Padding import pad, unpad

def handle_client(client_socket, addr):
    print(f"Connection established with {addr}")

    # Generate ElGamal keys for Diffie-Hellman
    key = ElGamal.generate(256, Random.new().read)
    public_key = key.publickey()

    # Send server's public key to client
    client_socket.send(f"{public_key.p},{public_key.g},{public_key.y}".encode())

    # Receive client's public key
    received_data = client_socket.recv(1024).decode()
    print(f"Server received: {received_data}")
    p, g, y = map(int, received_data.split(","))
    client_public_key = ElGamal.construct((p, g, y))

    # Compute shared secret
    shared_secret = pow(client_public_key.y, int(key.x), int(key.p))
    print(f"Server Shared Secret: {shared_secret}")
    aes_key = SHA256.new(str(shared_secret).encode()).digest()
    print(f"Server AES Key: {aes_key.hex()}")

    # Encrypt a welcome message
    iv = Random.new().read(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    padded_message = pad("Welcome to the secure chat!".encode(), 16)
    encrypted_data = iv + cipher.encrypt(padded_message)
    print("Padded message (hex):", padded_message.hex())
    print(f"Server encrypted data length: {len(encrypted_data)}")
    print(f"Sending from server: {encrypted_data.hex()}")
    client_socket.send(encrypted_data)

    try:
        while True:
            iv = Random.new().read(16)  # Generate new IV for every message
            encrypted_data = client_socket.recv(1024)
            iv_received = encrypted_data[:16]
            cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv_received)
            decrypted_data = unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size).decode()

            print(f"Received from {addr}: {decrypted_data}")
            response = "Message received!"
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            ct_bytes = cipher.encrypt(pad(response.encode(), AES.block_size))
            encrypted_response = iv + ct_bytes
            client_socket.send(encrypted_response)

    except Exception as e:
        print(f"Error with connection from {addr}: {e}")
    finally:
        print(f"Connection from {addr} closed.")
        client_socket.close()

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', 8082))
    server_socket.listen(5)
    print("Server started and waiting for connections...")

    try:
        while True:
            client_socket, addr = server_socket.accept()
            # Start a new thread for each client connection
            client_thread = threading.Thread(target=handle_client, args=(client_socket, addr))
            client_thread.start()
            print(f"Active connections: {threading.active_count() - 1}")
    except KeyboardInterrupt:
        print("\nShutting down the server...")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server()
