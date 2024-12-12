import socket
from threading import Thread
import tkinter as tk
from tkinter import Tk, Text, Entry, Button, END, Scrollbar, PhotoImage
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

class ServerMessengerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Server Messenger")

        # Message display area
        self.chat_area = Text(self.root, wrap=tk.WORD, state='disabled', height=20, width=50, font=("Arial", 12))
        self.chat_area.grid(row=0, column=0, padx=10, pady=10, columnspan=2)

        self.chat_area.tag_config("you", foreground="red", font=("Arial", 12, "bold"))
        self.chat_area.tag_config("client", foreground="blue", font=("Arial", 12, "bold"))

        # Scrollbar
        self.scrollbar = Scrollbar(self.root, command=self.chat_area.yview)
        self.chat_area['yscrollcommand'] = self.scrollbar.set
        self.scrollbar.grid(row=0, column=2, sticky='ns')

        # Message entry
        self.message_entry = Entry(self.root, width=40, font=("Arial", 12))
        self.message_entry.grid(row=1, column=0, padx=10, pady=10)
        self.message_entry.bind("<Return>", self.send_message)

        # Create the send button
        self.send_icon = PhotoImage(file="send_icon.png")  
        self.send_button = Button(
            self.root,
            image=self.send_icon,
            command=self.send_message,
            borderwidth=0,  
            background="white",  
            activebackground="lightgray",  
        )
        self.send_button.grid(row=1, column=1, padx=10, pady=10)

        self.send_button.bind("<Enter>", lambda e: self.send_button.config(background="lightblue"))
        self.send_button.bind("<Leave>", lambda e: self.send_button.config(background="white"))

        self.connection = None
        self.remote_public_key = None
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.start_server()

    def append_message(self, message, tag=None):
        self.chat_area.config(state='normal')
        self.chat_area.insert(END, message + "\n", tag)
        self.chat_area.config(state='disabled')
        self.chat_area.see(END)

    def send_message(self, event=None):  
        message = self.message_entry.get()
        if message and self.remote_public_key:
            try:
                # Encrypt the message
                encrypted_message = self.remote_public_key.encrypt(
                    message.encode(),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                self.connection.sendall(encrypted_message)
                self.append_message(f"You: {message}", "you")  
                self.message_entry.delete(0, END)
            except Exception as e:
                self.append_message(f"Error sending message: {e}")

    def receive_messages(self):
        while True:
            try:
                encrypted_message = self.connection.recv(4096)
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
                self.append_message(f"Client: {decrypted_message.decode()}", "client")  
            except Exception as e:
                self.append_message(f"Error receiving message: {e}")
                break

    def start_server(self):
        self.socket.bind(('127.0.0.1', 8000))
        self.socket.listen(1)
        self.append_message("Server listening on 127.0.0.1:8000...")

        def accept_connection():
            conn, addr = self.socket.accept()
            self.connection = conn
            self.append_message(f"Connection established with {addr}")

            # Send server public key
            conn.sendall(public_key_pem)

            # Receive client public key
            client_public_key_pem = conn.recv(4096)
            self.remote_public_key = serialization.load_pem_public_key(client_public_key_pem)

            # Start receiving messages
            Thread(target=self.receive_messages, daemon=True).start()

        Thread(target=accept_connection, daemon=True).start()

if __name__ == '__main__':
    root = Tk()
    app = ServerMessengerGUI(root)
    root.mainloop()
