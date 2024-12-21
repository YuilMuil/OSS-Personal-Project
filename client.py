import socket
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

# Define server details
HOST = '127.0.0.1'
PORT = 1337
KEY = b'12341234123412341234123412341234'  # Shared AES key (32 bytes for AES-256)
IV = os.urandom(16)  # Initialization vector (16 bytes)

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

# Function to handle receiving messages from the server
def receive_messages(client_socket):
    while True:
        try:
            # Receive encrypted message from the server
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message:
                break

            # Decrypt the message and display it
            iv = encrypted_message[:16]  # Extract IV from the message
            encrypted_text = encrypted_message[16:]  # Extract the encrypted text
            message = decrypt_message(encrypted_text, iv)
            print(f"New message: {message}")

        except Exception as e:
            print(f"Error receiving message: {e}")
            break

# Function to send messages to the server
def send_messages(client_socket):
    while True:
        try:
            message = input("You: ")
            if message.lower() == "exit":
                break

            # Encrypt the message
            encrypted_message = encrypt_message(message, IV)

            # Send the IV + encrypted message to the server
            client_socket.sendall(IV + encrypted_message)

        except Exception as e:
            print(f"Error sending message: {e}")
            break

# Function to connect to the server and start the chat
def client_program():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        try:
            client_socket.connect((HOST, PORT))
            print(f"Connected to server at {HOST}:{PORT}")

            # Start a thread to receive messages
            receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
            receive_thread.start()

            # Start sending messages
            send_messages(client_socket)

        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            print("Closing connection.")
            client_socket.close()

# Start the client program
if __name__ == '__main__':
    client_program()