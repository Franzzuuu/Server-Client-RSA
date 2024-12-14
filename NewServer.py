import socket
from threading import Thread
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import threading
import tkinter as tk
from tkinter.scrolledtext import ScrolledText

server_private_key = rsa.generate_private_key(public_exponent=3, key_size=3072)
server_public_key = server_private_key.public_key()

server_public_key_pem = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

def handle_received_message(connection, client_pub_key, log_function):
    while True:
        try:
            received_data = connection.recv(4096)
            if not received_data:
                break

            separator = b'||'
            encrypted_msg, msg_signature = received_data.split(separator)

            decrypted_msg = server_private_key.decrypt(
                encrypted_msg,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            client_pub_key.verify(
                msg_signature,
                decrypted_msg,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            log_function(f"Client: {decrypted_msg.decode()}")
        except Exception as e:
            log_function(f"Error receiving message: {e}")
            break

# GUI Code
class ServerMessenger:
    def __init__(self):
        self.root_window = tk.Tk()
        self.root_window.title("Server Messenger")
        self.root_window.geometry("400x500")  # Set a smaller window size
        self.root_window.configure(bg="#f7f7f7")  # Light background color

        self.log_area_widget = ScrolledText(self.root_window, wrap=tk.WORD, state="disabled", height=15, bg="#ffffff", fg="#333333", font=("Arial", 10))
        self.log_area_widget.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.input_frame_widget = tk.Frame(self.root_window, bg="#f7f7f7")
        self.input_frame_widget.pack(fill=tk.X, padx=5, pady=5)

        self.input_field = tk.Entry(self.input_frame_widget, font=("Arial", 10), bg="#ffffff", fg="#333333")
        self.input_field.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        self.input_field.bind("<Return>", lambda _: self.send_msg())

        self.send_button_widget = tk.Button(self.input_frame_widget, text="Send", command=self.send_msg, font=("Century Gothic", 10), bg="#56a0d3", fg="white")
        self.send_button_widget.pack(side=tk.RIGHT)

        self.server_socket = None
        self.client_connection = None
        self.client_public_key = None

        threading.Thread(target=self.start_server, daemon=True).start()

        self.root_window.mainloop()

    def log_message(self, message):
        self.log_area_widget.config(state="normal")
        self.log_area_widget.insert(tk.END, message + "\n")
        self.log_area_widget.config(state="disabled")
        self.log_area_widget.see(tk.END)

    def send_msg(self):
        if self.client_connection: 
            try:
                msg_to_send = self.input_field.get()
                if msg_to_send:
                    msg_signature = server_private_key.sign(
                        msg_to_send.encode(),
                        padding.PSS(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )

                    encrypted_msg = self.client_public_key.encrypt(
                        msg_to_send.encode("utf-8"),
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )

                    self.client_connection.sendall(encrypted_msg + b'||' + msg_signature)
                    self.log_message(f"You: {msg_to_send}")
                    self.input_field.delete(0, tk.END)
            except Exception as e:
                self.log_message(f"Error: {e}")

    def start_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        self.server_socket.bind(('127.0.0.1', 8000))
        self.server_socket.listen(1)
        self.log_message("The Server is listening")

        self.client_connection, client_address = self.server_socket.accept()
        self.client_connection = self.client_connection 
        self.log_message(f"Connection established with {client_address}")

        self.client_connection.sendall(server_public_key_pem)
        self.log_message("Server public key sent.")

        client_pub_key_pem = self.client_connection.recv(4096)
        self.client_public_key = serialization.load_pem_public_key(client_pub_key_pem)
        self.log_message("Client public key received.")

        threading.Thread(target=handle_received_message, args=(self.client_connection, self.client_public_key, self.log_message), daemon=True).start()

if __name__ == '__main__':
    ServerMessenger()
