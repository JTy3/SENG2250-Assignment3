# Import necessary libs
import socket
import sys
import math
import random
from hashlib import sha256
from Crypto.Util import number


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


def generateRsaKeyPair():

    # Generate two random large primes
    p = number.getPrime(1024)
    q = number.getPrime(1024)

    # Calculate n and phiN
    n = p * q
    phiN = ((p - 1) * (q - 1))

    while True:
        e = 65537
        # The following if statement is to demonstrate how you would find an appropriate public key if it wasn't specified like it is in this assignment
        if math.gcd(e, phiN) == 1:
            break

    # The inverse of the public key and phi N = the private key
    d = number.inverse(e, (p - 1) * (q - 1))

    # Set keys
    publicKey = (n, e)
    privateKey = (n, d)

    # Return both
    return (publicKey, privateKey)


def rsaDecrypt(message, key):
    decryptedMessage = fastModular(message, key[1], key[0])
    return decryptedMessage


def rsaSignature(message, key):
    messageInBytes = message.to_bytes(1000, 'little')
    hash = int.from_bytes(sha256(messageInBytes).digest(), byteorder='big')
    signature = fastModular(hash, key[1], key[0])
    return signature


HOST = ''                 # Symbolic name meaning all available interfaces
PORT = 50007              # Arbitrary non-privileged port

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        while True:

            # Setup phase - receive client hello and generate RSA key
            # Wait to receive data from client
            data = conn.recv(1024)
            if not data:
                break

            # Set the server keys to a variable
            serverKeys = generateRsaKeyPair()
            conn.sendall(((serverKeys[0][0]).to_bytes(2048, byteorder='big')))
            conn.sendall(
                ((serverKeys[0][1]).to_bytes(2048, byteorder='little')))

            # Handshake phase - receive client id
            clientIDc = rsaDecrypt(int.from_bytes(
                conn.recv(1024), byteorder="little"), serverKeys[1])
            if not clientIDc:
                break

            # Sending server ID to the client, signing the message and sending the signature for client to verify
            server_IDc = random.randrange(999999999)
            conn.sendall(server_IDc.to_bytes(1024, byteorder='little'))
            conn.sendall(rsaSignature(server_IDc, serverKeys[1]).to_bytes(
                1024, byteorder='little'))

            # Sending session ID to the client, signing the message and sending the signature for client to verify
            session_ID = random.randrange(999999999)
            conn.sendall(session_ID.to_bytes(1024, byteorder='little'))
            conn.sendall(rsaSignature(session_ID, serverKeys[1]).to_bytes(
                1024, byteorder='little'))

            # Starting Diffie Helman Key Exchange
            # Receives Client computation and decrypts it
            clientA = rsaDecrypt(int.from_bytes(
                conn.recv(1024), byteorder="little"), serverKeys[1])
            if not clientA:
                break

            p = 178011905478542266528237562450159990145232156369120674273274450314442865788737020770612695252123463079567156784778466449970650770920727857050009668388144034129745221171818506047231150039301079959358067395348717066319802262019714966524135060945913707594956514672855690606794135837542707371727429551343320695239
            g = 174068207532402095185811980123523436538604490794561350978495831040599953488455823147851597408940950725307797094915759492368300574252438761037084473467180148876118103083043754985190983472601550494691329488083395492313850000361646482644608492304078721818959999056496097769368017749273708962006689187956744210730
            serverSecret = random.randrange(99)

            # Compute B to send to client
            B = fastModular(g, serverSecret, p)

            serverSharedSecret = fastModular(clientA, serverSecret, p)
            print('\nServer Shared Secret: ', serverSharedSecret)

            # Send computation w/ signature
            conn.sendall(B.to_bytes(1024, byteorder='little'))
            conn.sendall(rsaSignature(B, serverKeys[1]).to_bytes(
                1024, byteorder='little'))
