#!/usr/bin/env python3

import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Random import random
import socket
import json
import base64
from Crypto.Cipher import AES
import hashlib
import random
import sys

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




def start_conn():
    HOST = '127.0.0.1'  # The server's hostname or IP address
    PORT = 1234         # The port used by the server

    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc.connect((HOST, PORT))
    print('Connected to', HOST,':', PORT)
    return soc

def gen_rsa(bits):
    new_key = RSA.generate(bits) 
    public_key = new_key.publickey().exportKey("PEM") 
    private_key = new_key.exportKey("PEM") 
    return private_key, public_key


conn=start_conn()

private_key,public_key = gen_rsa(1024)
public_key_merchant=b""
with open('PubKM', 'rb') as f:
        public_key_merchant=f.read()
#print(public_key_merchant)
sha=hashlib.sha256()
sha.update(b"cheiameasecreta")
sha.update((str)(Random.random.randint(100000000000,9999999999999)).encode())#adding salt
aes_key=sha.digest()
aes_cipher = AESCipher(aes_key)
public_key_merchant=RSA.importKey(public_key_merchant)


#encrypting my pubk with hybrid encryption using merchant's pubk
aes_key_encryped=public_key_merchant.encrypt(aes_key,32)
public_key_encrypted=aes_cipher.encrypt(str(public_key))
aes_key_encryped=aes_key_encryped[0]

conn.send(str(len(public_key_encrypted)).encode())
conn.send(public_key_encrypted)
conn.send(str(len(aes_key_encryped)).encode())
conn.send(aes_key_encryped)


#encrypted = aes_cipher.encrypt('Secret Message A')
#decrypted = aes_cipher.decrypt(encrypted)
print(public_key)
print(aes_key)

conn.close()

    
