import socket
from Crypto.Cipher import AES
import SampleNetworkClient
import os

ip = "127.0.0.1"
port = 23456

## in lab 3 I made the communication between the client and the server encrypted, so these keys 
#must be loaded to the OS to communicate with the server 
shared_key = os.environ.get("NETWORK_KEY").encode("utf-8")
password = os.environ.get("SERVER_PASSWORD").encode("utf-8")

def encrypt(message):
    cipher = AES.new(shared_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode("utf-8"))
    return cipher.nonce + tag + ciphertext

def decrypt(message):
    nonce = message[:16]
    tag = message[16:32]
    ciphertext = message[32:]
    cipher = AES.new(shared_key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode("utf-8")

# Step 1: get a valid token using the current client
snc = SampleNetworkClient.SimpleNetworkClient(23456, 23457)
token = snc.authenticate(port, password).decode("utf-8")
print("Token:", token)

# Step 2: send a multi-command payload directly

message = f"{token};SET_DEGC;GET_TEMP"

client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_socket.settimeout(3)

payload = encrypt(message)
client_socket.sendto(payload, (ip, port))

try:
    response, _ = client_socket.recvfrom(1024)
    print("Server response:", decrypt(response))
except socket.timeout:
    print("No response from server")
except Exception as ex:
    print("Error:", ex)