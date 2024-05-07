# server.py
import time, socket, sys
from Cryptodome.Cipher import AES
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
ip = socket.gethostbyname(host)
port = 1234
s.bind((host, port))
print(host, "(", ip, ")\n")
           
s.listen(1)
print("\nWaiting for incoming connections...\n")
conn, addr = s.accept()
print("Received connection from ", addr[0], "(", addr[1], ")\n")
while True:
    s_msg = input(str("server: "))
    encrypted = encrypt(s_msg).decode("utf-8") #encrypt the message
    if s_msg == "e":
        conn.send(encrypted.encode())
        print("\n")
        break
    
    print("encrypted message sent from server:", encrypted)
    conn.send(encrypted.encode())

    c_msg = conn.recv(10240)
    #c_msg = c_msg.decode()
    decrypted = decrypt(c_msg)
    print("encrypted message received from client:", c_msg)
    print("client:", decrypted)
