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

def rsaVerify(message, key, signature):
    messageInBytes = bytes(message)
    hash = int.from_bytes(sha256(messageInBytes).digest(), byteorder='big')
    hashFromSignature = pow(signature, key[1], key[0])
    if(hash == hashFromSignature):
        return True
    else:
        return False

HOST = 'localhost'    # The remote host
PORT = 50007          # The same port as used by the server

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    try:

        print("-----------------")
        print("Setup Phase STARTED")
        print("-----------------\n")

        s.connect((HOST, PORT))
        print('Client to Server: Hello')
        s.sendall(b'Hello')

        serverN = int.from_bytes(s.recv(2048), byteorder="big")
        serverE = int.from_bytes(s.recv(2048), byteorder="little")
        publicKey = (serverN, serverE)
        print('Server to Client: PK=', publicKey[0], publicKey[1])

        print("\n-----------------")
        print("Setup Phase COMPLETE")
        print("-----------------\n")


        print("-----------------")
        print("Handshake Phase STARTED")
        print("-----------------\n")
        
        # --------------------------------------
        # CLIENT SENDS ID_C TO SERVER AND ENCRYPTS IT WITH PUBLIC KEY RETRIEVED FROM THE SETUP PHASE - SERVER WILL DECRYPT WITH PUBLIC KEY 
        # --------------------------------------

        # Generate random client ID_c
        client_IDc = random.randrange(999999999)
        s.sendall(rsaEncrypt(client_IDc, publicKey).to_bytes(1024, byteorder='little'))
        print('Client to Server: Client IDc (Before RSA Encryption)=', client_IDc)


        # --------------------------------------
        # CLIENT RECEIVES SIGNED ID_C AND SESSION ID FROM SERVER AND VERIFIES SIGNATURES OF BOTH MESSAGES WITH PUBLIC KEY RETRIEVED FROM THE SETUP PHASE
        # --------------------------------------

        # Receive server IDc from the server followed by the server_IDc signature
        server_IDc = int.from_bytes(s.recv(1024), byteorder="little")
        server_IDc_sign = int.from_bytes(s.recv(1024), byteorder="little")

        # Verify the signature attached to the message from server
        if(rsaVerify(server_IDc, publicKey, server_IDc_sign) == True):
            # If verification passes accept the server IDc
            print('Server to Client: Server IDc:', server_IDc)
        else:
            # If verification fails deny server IDc and throw an error
            raise ValueError('The signature attached to "Server IDc" could not be verified\n')

        # Receive server IDc from the server followed by the server_IDc signature
        session_ID = int.from_bytes(s.recv(1024), byteorder="little")
        session_ID_sign = int.from_bytes(s.recv(1024), byteorder="little")

        # Verify the signature attached to the message from server
        if(rsaVerify(session_ID, publicKey, session_ID_sign) == True):
            # If verification passes accept the server IDc
            print('Server to Client: Session ID:', session_ID)
        else:
            # If verification fails deny server IDc and throw an error
            raise ValueError('The signature attached to "Session ID" could not be verified\n')

        print("\n-----------------")
        print("Handshake Phase COMPLETE")
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
