import socket
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def encrypt_message(public_key, message):
    """Encrypts a message using the provided public key."""
    return public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def main():
    server_ip = 'server_ip_address'  # Server IP address
    port = 65432  # Port number should match the server

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_ip, port))
        print("Connected to server at {}:{}".format(server_ip, port))

        # Receive public key from the server
        public_key_bytes = s.recv(2048)  # Adjust buffer size if necessary
        public_key = load_pem_public_key(public_key_bytes)

        message = "Hello, this is a test message from the client!"
        encrypted_message = encrypt_message(public_key, message)
        
        # Send encrypted message to the server
        s.sendall(encrypted_message)
        print("Encrypted message sent to the server.")

if __name__ == "__main__":
    main()