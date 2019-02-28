#!/usr/bin/env python3

import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
import socket
from Crypto.Cipher import AES

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 1234         # Port to listen on (non-privileged ports are > 1023)
def gen_keys(bits):
    new_key = RSA.generate(bits) 
    public_key = new_key.publickey().exportKey("PEM") 
    private_key = new_key.exportKey("PEM") 
    with open('PubKM', 'wb') as f:
        f.write(public_key)
    with open('PrivKM', 'wb') as f:
        f.write(private_key)
def start_conn():
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc.bind((HOST, PORT))
    soc.listen()
    conn, addr = soc.accept()
    print('Connected by', addr)
    return conn

conn=start_conn()
