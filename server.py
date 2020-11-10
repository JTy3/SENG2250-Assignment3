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
    print('Message to be signed:', message)
    messageInBytes = bytes(message)
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

            # Sending server ID to the client, not encrypted with RSA as the client doesn't have the public key
            server_IDc = random.randrange(999999999)
            session_ID = random.randrange(999999999)
            conn.sendall(rsaSignature(server_IDc, serverKeys[1]).to_bytes(1024, byteorder='little'))
            conn.sendall(rsaSignature(session_ID, serverKeys[1]).to_bytes(1024, byteorder='little'))
