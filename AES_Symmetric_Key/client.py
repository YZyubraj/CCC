# client.py
import time, socket, sys
import base64
import hashlib
from Cryptodome.Cipher import AES 
from Cryptodome.Random import get_random_bytes

#========================================= AES Encryption Decription ==============================================

_key_ = hashlib.sha256(b'mykey').digest()

def encrypt(raw):
    BS = AES.block_size
    pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)

    raw = base64.b64encode(pad(raw).encode('utf8'))
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key= _key_, mode= AES.MODE_CFB,iv= iv)
    return base64.b64encode(iv + cipher.encrypt(raw))

def decrypt(enc):
    unpad = lambda s: s[:-ord(s[-1:])]

    enc = base64.b64decode(enc)
    iv = enc[:AES.block_size]
    cipher = AES.new(_key_, AES.MODE_CFB, iv)
    return unpad(base64.b64decode(cipher.decrypt(enc[AES.block_size:])).decode('utf8'))

#================================================================================================

print("Initialising....\n")
time.sleep(1)

s = socket.socket()

host = str("127.0.0.1")
port = 1234
print("\nTrying to connect to ", host, "(", port, ")\n")
time.sleep(1)
s.connect((host, port))
print("Connected...\n")

while True:
    s_msg = s.recv(10240)
    s_msg = s_msg.decode()
    decryptted = decrypt(s_msg)
    print("encrypted message received from server:", s_msg)
    
    print("server:", decryptted)
    
    c_msg = input(str("client : "))
    encrypted = encrypt(c_msg).decode("utf-8") # encrypt the message
    print("encrypted message sent from client:", encrypted)
    if c_msg == "e":
        s.send(encrypted.encode())
        print("\n")
        break
    s.send(encrypted.encode())
