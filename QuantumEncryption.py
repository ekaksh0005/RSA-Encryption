from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend

# Generate RSA private and public key pairs
def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# Encrypt a message using the public key
def encrypt_message(message, public_key):
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode()

# Decrypt a message using the private key
def decrypt_message(ciphertext, private_key):
    decoded_ciphertext = base64.b64decode(ciphertext)
    plaintext = private_key.decrypt(
        decoded_ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()



    

    # Serialize public key for sharing
    # public_pem = public_key.public_bytes(
    #     encoding=serialization.Encoding.PEM,
    #     format=serialization.PublicFormat.SubjectPublicKeyInfo
    # )
    # print("\nPublic Key (share this safely):")
    # print(public_pem.decode())

    # # Serialize private key for secure storage
    # private_pem = private_key.private_bytes(
    #     encoding=serialization.Encoding.PEM,
    #     format=serialization.PrivateFormat.PKCS8,
    #     encryption_algorithm=serialization.NoEncryption()
    # )
    # print("\nPrivate Key (keep this secret):")
    # print(private_pem.decode())

    # # Encrypt the strain string
    # encrypted_message = encrypt_message(strain, public_key)
    # print("\nEncrypted message:")
    # print(encrypted_message)

    # # Decrypt the message
    # decrypted_message = decrypt_message(encrypted_message, private_key)
    # print("\nDecrypted message:")
    # print(decrypted_message)
    # conn.close()

import socket

def start_server():
    host = "0.0.0.0"   # Automatically gets local IP
    port = 8000  # Use any free port
    print(host)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)  # Listen for 1 connection at a time

    print(f"Server started on {host}:{port}")
    print("Waiting for a connection...")

    conn, addr = server_socket.accept()
    print(f"Connection established with {addr}")

    while True:
        data = conn.recv(1024).decode()
        if not data:
            break
        print(f"Client: {data}")
        message = input("Server: ")
        conn.send(message.encode())

    conn.close()

# if __name__ == "__main__":
#     start_server()

# Demonstration
if __name__ == "__main__":
    host = socket.gethostbyname("192.168.0.112")  # Automatically gets local IP
    port = 8000  # Use any free port

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)  

    print(f"Server started on {host}:{port}")
    print("Waiting for a connection...")

    conn, addr = server_socket.accept()
    print(f"Connection established with {addr}")

    # Input strain string
    # strain = input("Enter the strain string to encrypt: ")

    # Generate keys
    private_key, public_key = generate_key_pair()

    
    Vpublic_key = conn.recv(1024).decode()
    Vpublic_key = load_pem_public_key(Vpublic_key.encode(), backend=default_backend())

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,  # Use PEM format
        format=serialization.PublicFormat.SubjectPublicKeyInfo  # Standard public key format
    )

# Send the serialized public key
    
    print(f"Client: {Vpublic_key}")
    message = public_key
    conn.send(public_key_bytes)

    while True:
        data = conn.recv(1024).decode()
        if not data:
            break
        decrypted_message = decrypt_message(data, private_key)
        print(f"Client: {decrypted_message}")
        message = input("Server: ")
        encrypted_message = encrypt_message(message, Vpublic_key)
        conn.send(encrypted_message.encode())

    conn.close()