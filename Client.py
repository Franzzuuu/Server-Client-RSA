import socket
from threading import Thread
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Generate RSA keys
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Serialize public key
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Functions for client
def handle_receive(sock, server_public_key):
    while True:
        try:
            encrypted_message = sock.recv(4096)
            if not encrypted_message:
                break
            # Decrypt the message
            decrypted_message = private_key.decrypt(
                encrypted_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print(f"Server: {decrypted_message.decode()}")
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

def handle_send(sock, server_public_key):
    while True:
        try:
            message = input("You: ")
            # Encrypt message with the server's public key
            encrypted_message = server_public_key.encrypt(
                message.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            sock.sendall(encrypted_message)
        except Exception as e:
            print(f"Error sending message: {e}")
            break

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 8000))
    print("Connected to server.")

    # Receive server's public key
    server_public_key_pem = client_socket.recv(4096)
    server_public_key = serialization.load_pem_public_key(server_public_key_pem)
    print("Server public key received.")

    # Send client's public key
    client_socket.sendall(public_key_pem)
    print("Client public key sent.")

    # Start threads for receiving and sending messages
    Thread(target=handle_receive, args=(client_socket, server_public_key), daemon=True).start()
    handle_send(client_socket, server_public_key)

if __name__ == '__main__':
    start_client()
