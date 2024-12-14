import socket
from threading import Thread
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import tkinter as tk
from tkinter.scrolledtext import ScrolledText

class ClientMessenger:
    def __init__(self, server_ip="127.0.0.1", server_port=8000):
        self.server_ip = server_ip
        self.server_port = server_port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.is_connected = False

        self.client_private_key = rsa.generate_private_key(public_exponent=3, key_size=3072)
        self.client_public_key = self.client_private_key.public_key()

        self.client_public_key_pem = self.client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        self.remote_server_public_key = None

    def start_interface(self):
        self.main_window = tk.Tk()
        self.main_window.title("Client Messenger")
        self.main_window.geometry("400x500")  
        self.main_window.configure(bg="#f7f7f7")  # Light background color
        
        self.chat_area = ScrolledText(
            self.main_window, wrap=tk.WORD, state="disabled", height=15, bg="#ffffff", fg="#333333", font=("Arial", 10)
        )
        self.chat_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        self.input_frame = tk.Frame(self.main_window, bg="#f7f7f7")
        self.input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.text_input = tk.Entry(self.input_frame, font=("Arial", 10), bg="#ffffff", fg="#333333")
        self.text_input.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        self.text_input.bind("<Return>", lambda _: self.send_message(self.socket))
        
        self.send_button = tk.Button(
            self.input_frame, text="Send", command=lambda: self.send_message(self.socket), font=("Century Gothic", 10), bg="#56a0d3", fg="white"
        )
        self.send_button.pack(side=tk.RIGHT)
        
        self.main_window.after(100, self.connect_to_server)
        self.main_window.mainloop()
        
    def connect_to_server(self):
        try:
            self.socket.connect((self.server_ip, self.server_port))
            self.is_connected = True
            print("Connected to server.")

            server_public_key_pem = self.socket.recv(4096)
            self.remote_server_public_key = serialization.load_pem_public_key(server_public_key_pem)
            self.add_message_to_chat("Server public key received.")

            self.socket.sendall(self.client_public_key_pem)
            self.add_message_to_chat("Client public key sent.")

            Thread(target=self.receive_message, args=(self.socket,), daemon=True).start()

        except Exception as e:
            self.add_message_to_chat(f"Error: {e}")
            self.is_connected = False

    def receive_message(self, socket_connection):
        while self.is_connected:
            try:
                incoming_data = socket_connection.recv(4096)
                if not incoming_data:
                    break

                separator = b'||'
                encrypted_msg, msg_signature = incoming_data.split(separator)

                decrypted_message = self.client_private_key.decrypt(
                    encrypted_msg,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                self.remote_server_public_key.verify(
                    msg_signature,
                    decrypted_message,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )

                self.add_message_to_chat(f"Server: {decrypted_message.decode()}")
            except Exception as e:
                self.add_message_to_chat(f"Error receiving message: {e}")
                break

    def send_message(self, socket_connection):
        try:
            message_to_send = self.text_input.get()
            if message_to_send:
                encrypted_msg = self.remote_server_public_key.encrypt(
                    message_to_send.encode(),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                msg_signature = self.client_private_key.sign(
                    message_to_send.encode(),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )

                socket_connection.sendall(encrypted_msg + b'||' + msg_signature)
                self.add_message_to_chat(f"You: {message_to_send}")
                self.text_input.delete(0, tk.END)
        except Exception as e:
            self.add_message_to_chat(f"Error sending message: {e}")

    def add_message_to_chat(self, message):
        self.main_window.after(0, self._append_message_to_chat, message)

    def _append_message_to_chat(self, message):
        self.chat_area.config(state="normal")
        self.chat_area.insert(tk.END, message + "\n")
        self.chat_area.config(state="disabled")
        self.chat_area.see(tk.END)


if __name__ == '__main__':
    client_app = ClientMessenger()
    client_app.start_interface()
