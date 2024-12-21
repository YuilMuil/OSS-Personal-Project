import socket
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

# Define constants for server
HOST = '127.0.0.1'
PORT = 65432
KEY = b'12341234123412341234123412341234'  # Shared AES key (32 bytes for AES-256)
MAX_CLIENTS = 5

# Semaphore to manage client list access
client_list_semaphore = threading.Semaphore(1)  # Only one thread can modify the list at a time
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

def handle_client(conn, addr):
    global clients  # Explicitly declare clients as global
    print(f"New connection: {addr}")
    session_iv = os.urandom(16)  # Generate a unique IV for this session

    # Send IV to the client as part of the handshake
    conn.sendall(session_iv)

    # Acquire semaphore to safely modify the client list
    client_list_semaphore.acquire()
    clients.append((conn, session_iv))
    client_list_semaphore.release()

    try:
        while True:
            # Receive encrypted message from the client
            encrypted_message = conn.recv(1024)
            if not encrypted_message:
                break

            # Decrypt the message
            message = decrypt_message(encrypted_message, session_iv)
            print(f"Message from {addr}: {message}")

            # Broadcast the message to all other clients
            client_list_semaphore.acquire()  # Ensure thread-safe access to the client list
            for client, client_iv in clients:
                if client != conn:
                    encrypted_response = encrypt_message(f"Message from {addr}: {message}", client_iv)
                    client.sendall(encrypted_response)  # Send encrypted message
            client_list_semaphore.release()

    finally:
        # Remove the client from the list of connected clients
        client_list_semaphore.acquire()
        clients = [c for c in clients if c[0] != conn]
        client_list_semaphore.release()

        conn.close()
        print(f"Connection closed: {addr}")

# Function to accept incoming client connections
def accept_connections():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print(f"Server is listening on {HOST}:{PORT}")

        while True:
            conn, addr = server_socket.accept()  # Accept new connection
            print(f"Accepted connection from {addr}")

            # Start a new thread to handle the client
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()

# Start the server
if __name__ == '__main__':
    accept_connections()
