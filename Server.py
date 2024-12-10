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

# Functions for server
def handle_receive(conn, client_public_key):
    while True:
        try:
            encrypted_message = conn.recv(4096)
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
            print(f"Client: {decrypted_message.decode()}")
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

def handle_send(conn, client_public_key):
    while True:
        try:
            message = input("You: ")
            # Encrypt message with the client's public key
            encrypted_message = client_public_key.encrypt(
                message.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            conn.sendall(encrypted_message)
        except Exception as e:
            print(f"Error sending message: {e}")
            break

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 8000))
    server_socket.listen(1)
    print("Server listening on 127.0.0.1:8000...")

    conn, addr = server_socket.accept()
    print(f"Connection established with {addr}")

    # Send server's public key
    conn.sendall(public_key_pem)
    print("Server public key sent.")

    # Receive client's public key
    client_public_key_pem = conn.recv(4096)
    client_public_key = serialization.load_pem_public_key(client_public_key_pem)
    print("Client public key received.")

    # Start threads for receiving and sending messages
    Thread(target=handle_receive, args=(conn, client_public_key), daemon=True).start()
    handle_send(conn, client_public_key)

if __name__ == '__main__':
    start_server()
