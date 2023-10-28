import socket
import threading

def handle_client(client_socket, addr):
    print(f"Connection established with {addr}")
    try:
        while True:
            data = client_socket.recv(1024).decode('utf-8')
            if not data:
                break
            print(f"Received from {addr}: {data}")
            response = "Message received!"
            client_socket.send(response.encode('utf-8'))
    except Exception as e:
        print(f"Error with connection from {addr}: {e}")
    finally:
        print(f"Connection from {addr} closed.")
        client_socket.close()

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 8080))
    server_socket.listen(5)
    print("Server started and waiting for connections...")

    try:
        while True:
            client_socket, addr = server_socket.accept()
            # Start a new thread for each client connection
            client_thread = threading.Thread(target=handle_client, args=(client_socket, addr))
            client_thread.start()
            print(f"Active connections: {threading.activeCount() - 1}")  # Subtracting 1 for the main thread
    except KeyboardInterrupt:
        print("\nShutting down the server...")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server()
