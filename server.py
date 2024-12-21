import socket
import threading
from queue import Queue
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

# Define constants for server
HOST = '127.0.0.1'
PORT = 1337
MAX_CLIENTS = 2
KEY = b'12341234123412341234123412341234'  # Shared AES key (32 bytes for AES-256)
IV = os.urandom(16)  # Initialization vector (16 bytes)

# Semaphore to manage the max number of clients
client_semaphore = threading.Semaphore(MAX_CLIENTS)

# Queue to handle pipelined tasks
task_queue = Queue()

# Shared variable to count active clients
client_count = 0
client_count_lock = threading.Lock()
# List to keep track of client connections
clients = []

# Function to encrypt the message using AES
def encrypt_message(message, iv):
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    return encrypted_message

# Function to decrypt the message using AES
def decrypt_message(encrypted_message, iv):
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    unpadded_message = unpadder.update(decrypted_message) + unpadder.finalize()

    return unpadded_message.decode()

# Function to handle each client connection
def handle_client(conn, addr):
    print(f"New connection: {addr}")
    
    # Add client to the list of connected clients
    clients.append(conn)
    
    try:
        while True:
            # Receive encrypted message from the client
            encrypted_message = conn.recv(1024)
            if not encrypted_message:
                break

            # Decrypt the message
            message = decrypt_message(encrypted_message, IV)
            print(f"Message from {addr}: {message}")

            # Broadcast the message to all other clients
            for client in clients:
                if client != conn:
                    encrypted_response = encrypt_message(f"Message from {addr}: {message}", IV)
                    client.sendall(IV + encrypted_response)  # Send IV + encrypted message

    finally:
        # Remove the client from the list of connected clients
        clients.remove(conn)
        conn.close()
        print(f"Connection closed: {addr}")

# Function to accept incoming client connections
def accept_connections():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()

        print(f"Server listening on {HOST}:{PORT}")

        while True:
            client_semaphore.acquire()  # Wait if the max number of clients is reached
            conn, addr = server_socket.accept()  # Accept a new connection
            print(f"Accepted connection from {addr}")

            # Create a new thread to handle the client connection
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()

            client_semaphore.release()  # Release the semaphore for other connections

# Start the server to accept connections
if __name__ == '__main__':
    accept_connections()