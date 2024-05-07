import socket, hashlib, time
import hmac

symmetric_key = 3

def encrypt_data(message):
    print("".center(80, "*"))
    print("Encrypting data...")
    t = ""
    print(message)
    # message = message.lower()
    for i in message:
        if i.isupper():
            alphabet = chr((ord(i) + symmetric_key - 65) % 26 + 65)
        elif i.islower():
            alphabet = chr((ord(i) + symmetric_key - 97) % 26 + 97)
        # elif i.isnumeric():
        # alphabet = chr((ord(i)+symmetric_key-48)%10+48)
        else:
            alphabet = chr(ord(i) + symmetric_key)
        t = t + alphabet
    # message
    return t

def generate_mac(message, key):
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()

def hash_data(messageToSent):
    print("".center(80, "*"))
    print("Computing the hash of the data...")
    hashedData = hashlib.md5(messageToSent.encode())
    hashedDataByte = hashedData.hexdigest()
    return hashedDataByte

def makeConnection():
    # creating a socket object
    senderSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Get local machine name
    host = socket.gethostname()
    port = 9999
    # bind to the port
    senderSocket.bind((host, port))
    print("Socket binded to ", port)
    # queue upto 5 connection requests
    senderSocket.listen(5)
    print("Socket is listening for client connections")
    # establishing a connection with client
    clientSocket, address = senderSocket.accept()
    print("Got a connection from client with address ", str(address))
    # normal case
    messageToSent = "This is a data to be sent to the receiver 123."
    # calling functions to secure data
    hashedData = hash_data(messageToSent)
    encryptedData_Key = encrypt_data(messageToSent)
    mac = generate_mac(messageToSent, str(symmetric_key))
    dataToSent = (
        '{"Message":"' + encryptedData_Key + '","Key":"' + str(symmetric_key) +
        '","Hash":"' + str(hashedData) + '","MAC":"' + mac + '"}'
    )
    clientSocket.send(dataToSent.encode("ascii"))
    # Sending Data Packet to Client
    print("".center(80, "*"))
    print("Data is sent successfully")
    # key modified case
    dataToSent = (
        '{"Message":"' + encryptedData_Key + '","Key":"' + "" +
        '","Hash":"' + str(hashedData) + '"}'
    )
    # Sending Data Packet to Client
    clientSocket.send(dataToSent.encode("ascii"))
    print("".center(80, "*"))
    print("Data is sent successfully")
    print("".center(80, "*"))
    # connection closed case
    dataToSent = '{"Message":"' + "" + '","Key":"' + "" + '","Hash":"' + "" + '"}'
    time.sleep(10)
    clientSocket.send(dataToSent.encode("ascii"))
    clientSocket.close()
print("Connection closed...\nThank you")
print("".center(80, "*"))
print("\t\t\t\t\tSender")
print("".center(80, "*"))

makeConnection()
