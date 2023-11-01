import socket
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import ElGamal
from Crypto import Random
from Crypto.Util.Padding import pad, unpad

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 8082))
    print("Connected to server.")

    # Generate ElGamal keys for Diffie-Hellman
    key = ElGamal.generate(256, Random.new().read)

    # Receive server's public key
    received_data = client_socket.recv(1024).decode()
    print(f"Client received: {received_data}")
    p, g, y = map(int, received_data.split(","))
    server_public_key = ElGamal.construct((p, g, y))

    # Send client's public key to server
    client_socket.send(f"{key.p},{key.g},{key.y}".encode())

    # Compute shared secret
    shared_secret = pow(server_public_key.y, int(key.x), int(key.p))
    print(f"Client Shared Secret: {shared_secret}")
    aes_key = SHA256.new(str(shared_secret).encode()).digest()
    print(f"Client AES Key: {aes_key.hex()}")

    # Receive and decrypt welcome message
    encrypted_response = client_socket.recv(1024)
    print(f"Client received encrypted data length: {len(encrypted_response)}")
    print(f"Client received: {encrypted_response.hex()}")
    iv = encrypted_response[:16]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_response[16:])
    print("Decrypted data length:", len(decrypted_data))
    print("Decrypted data (hex):", decrypted_data.hex())
    decrypted_message = unpad(decrypted_data, AES.block_size).decode()
    print(f"Server says: {decrypted_message}")

    try:
        while True:
            message = input("Enter your message: ")
            iv = Random.new().read(16)  # Generate new IV for every message
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
            encrypted_message = iv + ct_bytes
            client_socket.send(encrypted_message)

            encrypted_response = client_socket.recv(1024)
            print(f"Client received encrypted data length: {len(encrypted_response)}")
            iv_response = encrypted_response[:16]
            cipher_response = AES.new(aes_key, AES.MODE_CBC, iv=iv_response)
            decrypted_response = cipher_response.decrypt(encrypted_response[16:])
            print("Decrypted data length:", len(decrypted_response))
            print("Decrypted data (hex):", decrypted_response.hex())
            response = unpad(decrypted_response, AES.block_size).decode()
            print(f"Server responded: {response}")

    except KeyboardInterrupt:
        print("\nDisconnecting from the server...")
    finally:
        client_socket.close()

if __name__ == "__main__":
    start_client()
