# Import necessary libs
import socket
import sys
import math
import random
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

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
    messageInBytes = message.to_bytes(1000, 'little')
    hash = int.from_bytes(sha256(messageInBytes).digest(), byteorder='big')
    hashFromSignature = pow(signature, key[1], key[0])
    if(hash == hashFromSignature):
        return True
    else:
        return False

def split_str(seq, chunk):
    lst = []
    if chunk <= len(seq):
        lst.extend([seq[:chunk]])
        lst.extend(split_str(seq[chunk:], chunk))
    return lst

def xor_function(str1, str2):
    temp_list = [chr(ord(a) ^ ord(b)) for a,b in zip(str1, str2)]
    return "".join(temp_list)

def cbcEncrypt(message):
    fullCt = ""
    tempCt = ""
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    iv = get_random_bytes(16)
    ptList = split_str(message, 16)
    for item in ptList:
        if(item == 0):
            tempCt = cipher.encrypt((xor_function(item, iv)), AES.block_size)
        else:
            tempCt = cipher.encrypt((xor_function(item, tempCt)), AES.block_size)
        fullCt += tempCt
        print(fullCt)

# def cbcDecrypt():


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
        s.sendall(rsaEncrypt(client_IDc, publicKey).to_bytes(
            1024, byteorder='little'))
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
            raise ValueError(
                'The signature attached to "Server IDc" could not be verified\n')

        # Receive server IDc from the server followed by the server_IDc signature
        session_ID = int.from_bytes(s.recv(1024), byteorder="little")
        session_ID_sign = int.from_bytes(s.recv(1024), byteorder="little")

        # Verify the signature attached to the message from server
        if(rsaVerify(session_ID, publicKey, session_ID_sign) == True):
            # If verification passes accept the server IDc
            print('Server to Client: Session ID:', session_ID)
        else:
            # If verification fails deny server IDc and throw an error
            raise ValueError(
                'The signature attached to "Session ID" could not be verified\n')

        # --------------------------------------
        # DIFFIE HELMAN KEY EXCHANGE
        # --------------------------------------

        print('\nINITIATED DIFFIE HELMAN KEY EXCHANGE\n')        

        p = 178011905478542266528237562450159990145232156369120674273274450314442865788737020770612695252123463079567156784778466449970650770920727857050009668388144034129745221171818506047231150039301079959358067395348717066319802262019714966524135060945913707594956514672855690606794135837542707371727429551343320695239
        g = 174068207532402095185811980123523436538604490794561350978495831040599953488455823147851597408940950725307797094915759492368300574252438761037084473467180148876118103083043754985190983472601550494691329488083395492313850000361646482644608492304078721818959999056496097769368017749273708962006689187956744210730
        clientSecret = random.randrange(99)

        # Compute A to send to the Server
        A = fastModular(g, clientSecret, p)

        # Send encrypted computation to server
        print('Client to Server: A Computation (Before RSA Encryption)=', A)
        s.sendall(rsaEncrypt(A, publicKey).to_bytes(1024, byteorder='little'))

        # Receive server IDc from the server followed by the server_IDc signature
        serverB = int.from_bytes(s.recv(1024), byteorder="little")
        serverB_sign = int.from_bytes(s.recv(1024), byteorder="little")

        # Verify the signature attached to the message from server
        if(rsaVerify(serverB, publicKey, serverB_sign) == True):
            # If verification passes accept the server IDc
            print('\nServer to Client: Server B:', serverB)
        else:
            # If verification fails deny server IDc and throw an error
            raise ValueError(
                'The signature attached to "Server B" could not be verified\n')

        clientSharedSecret = fastModular(serverB, clientSecret, p)
        print('\nClient Shared Secret:', clientSharedSecret)
        print(sys.getsizeof(clientSharedSecret))

        print("\n-----------------")
        print("Handshake Phase COMPLETE")
        print("-----------------\n")

        print("\n-----------------")
        print("Data Exchange STARTED")
        print("-----------------\n")

        messageToBeSent = 'wXs7qb_ol5zo-O23x6HfUCXi94boxaMXBM78w4QqNDeA9Z44FbHJ89zaDUStFiRju0c3TH6ZO1bynJGujE06Bg'
        print('Message To Be Sent to Server: ', messageToBeSent)  
        cbcEncrypt(messageToBeSent)

        print("\n-----------------")
        print("Data Exchange COMPLETE")
        print("-----------------\n")

    except error as e:
        # Catch any errors
        print(e)
        print("There was an error - see logging above for details")
    finally:
        # Finish Process
        print("Client closed socket")
        s.close()
