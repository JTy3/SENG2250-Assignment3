# Import necessary libs
import socket
import sys
import math
import random
from hashlib import sha256

def fastModular(b, e, n):
    if (n == 1):
        return 0
    rs = 1
    while (e > 0):
        if ((e & 1) == 1):
            rs = (rs * b) % n
        e = e >> 1
        b = (b*b) % n
    return rs

def rsaEncrypt(message, key):
    encryptedMessage = fastModular(message, key[1], key[0])
    return encryptedMessage

def rsaVerify(message, key):
    print(message)
    hash = int.from_bytes(sha256(message).digest(), byteorder='big')
    print('HASH', hash)
    hashFromSignature = fastModular(hash, key[1], key[0])
    print('HASH FROM SIGN', hashFromSignature)
    if(hash == hashFromSignature):
        return True
    else:
        return False

HOST = 'localhost'    # The remote host
PORT = 50007          # The same port as used by the server

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    try:

        print("-----------------")
        print("Setup Phase")
        print("-----------------\n")

        s.connect((HOST, PORT))
        print('Client to Server: Hello')
        s.sendall(b'Hello')

        serverN = int.from_bytes(s.recv(2048), byteorder="big")
        serverE = int.from_bytes(s.recv(2048), byteorder="little")
        publicKey = (serverN, serverE)
        print('Server to Client: PK=', publicKey[0], publicKey[1])

        print("\n-----------------")
        print("Setup Phase ENDED")
        print("-----------------\n")


        print("-----------------")
        print("Handshake Phase")
        print("-----------------\n")
        
        client_IDc = random.randrange(999999999)
        s.sendall(rsaEncrypt(client_IDc, publicKey).to_bytes(1024, byteorder='little'))
        print('Client to Server: Client IDc (Before RSA Encryption)=', client_IDc)

        server_IDc = rsaVerify(s.recv(1024), publicKey)
        print('Server to Client: Server IDc:', server_IDc)

        session_ID = rsaVerify(s.recv(1024), publicKey)
        print('Server to Client: Session ID:', session_ID)

        print("\n-----------------")
        print("Handshake ENDED")
        print("-----------------\n")

        print("\n-----------------")
        print("Data Exchange")
        print("-----------------\n")

    except error as e:
        # Catch any errors
        print(e)
        print("There was an error - see logging above for details")
    finally:
        # Finish Process
        print("Client closed socket")
        s.close()
