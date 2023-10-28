import socket

def start_client():
    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Define the host and port of the server to connect to
    host = '127.0.0.1'  # Use localhost for testing on the same machine
    port = 8080

    # Establish a connection to the server
    client_socket.connect((host, port))
    print(f"Connected to server at {host}:{port}")

    try:
        while True:
            # Get input from the user to send as a message
            message = input("Enter your message (or 'exit' to quit): ")

            # Check if user wants to exit
            if message.lower() == 'exit':
                break

            # Send the message to the server
            client_socket.send(message.encode('utf-8'))

            # Receive a response from the server (optional based on server code)
            response = client_socket.recv(1024).decode('utf-8')
            print(f"Server responded: {response}")

    except KeyboardInterrupt:
        # Handle graceful shutdown on keyboard interrupt
        print("\nDisconnecting from the server...")

    finally:
        # Close the client socket
        client_socket.close()

# Run the client
if __name__ == "__main__":
    start_client()
