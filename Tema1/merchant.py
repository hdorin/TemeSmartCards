#!/usr/bin/env python3

import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
import socket
import base64
import sys
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

BS = 16
def pad(s):
    return s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
def unpad(s):
    return s[0:-s[-1]] 
    
class AESCipher:
    def __init__( self, key ):
        self.key = key

    def encrypt( self, raw ):
        raw = pad(raw)
        iv = Random.new().read( AES.block_size )
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return base64.b64encode( iv + cipher.encrypt( raw ) )

    def decrypt( self, enc ):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return unpad(cipher.decrypt( enc[16:] ))


conn=start_conn()

buf_size=conn.recv(3)
public_key_encrypted_customer=conn.recv(int(buf_size))
buf_size=conn.recv(3)
aes_key_encrypted_customer=conn.recv(int(buf_size))



public_key_merchant=b""
with open('PrivKM', 'rb') as f:
    private_key=f.read()
private_key=RSA.importKey(private_key)
aes_key_customer=private_key.decrypt(aes_key_encrypted_customer)
aes_cipher = AESCipher(aes_key_customer)
public_key_customer=aes_cipher.decrypt(public_key_encrypted_customer)

print(public_key_customer)
print(aes_key_customer)

conn.close()