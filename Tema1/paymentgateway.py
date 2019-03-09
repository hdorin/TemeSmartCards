#!/usr/bin/env python3

import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Random import random
import socket
import base64
import sys
import json
import hashlib
from Crypto.Cipher import AES

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = int(sys.argv[1])+1         # Port to listen on (non-privileged ports are > 1023)
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
aes_key_customer_encrypted=conn.recv(int(buf_size))
buf_size=conn.recv(3)
aes_key_merchant_encrypted=conn.recv(int(buf_size))
buf_size=conn.recv(4)
PM_json_encrypted=conn.recv(int(buf_size))
buf_size=conn.recv(3)
aux_json_hash_signed_encryped=conn.recv(int(buf_size))

#FIFTH STEP

private_key=b""
with open('PrivKPG', 'rb') as f:
        private_key=f.read()
private_key=RSA.importKey(private_key)
aes_key_merchant=private_key.decrypt(aes_key_merchant_encrypted)
aes_key_customer=private_key.decrypt(aes_key_customer_encrypted)

aes_cipher_merchant = AESCipher(aes_key_merchant)
aes_cipher_customer = AESCipher(aes_key_customer)

PM_json_encrypted=aes_cipher_merchant.decrypt(PM_json_encrypted)

PM_json_encrypted=str(PM_json_encrypted)[7:-4]
PM_json_encrypted=str(PM_json_encrypted).encode()
PM_json=aes_cipher_customer.decrypt(PM_json_encrypted)

PM=json.loads(PM_json)

PI_json=PM["PI"]
PI=json.loads(PI_json)

public_key_customer=PI["PubKC"]
public_key_customer=str(public_key_customer)[2:-1]
public_key_customer=str(public_key_customer).replace("\\n",'\n')#fixing aes decryption result
public_key_customer=str(public_key_customer).encode()


aux=dict()
aux["Sid"]=int(PI["Sid"])
aux["PubKC"]=str(public_key_customer)
aux["amount"]=PI["Amount"]
aux_json=json.dumps(aux)
aux_json_hash=hashlib.sha256(aux_json.encode()).digest()

aux_json_hash_signed=aes_cipher_merchant.decrypt(aux_json_hash_signed_encryped)
aux_json_hash_signed=str(aux_json_hash_signed)
aux_json_hash_signed=aux_json_hash_signed[2:-1]
aux_json_hash_signed=int(aux_json_hash_signed)
l=list()
l.append(aux_json_hash_signed)
aux_json_hash_signed=l.copy()
print("JSON=",aux_json_hash_signed)

public_key_customer=RSA.importKey(public_key_customer)
PI_json_hash=hashlib.sha256(PI_json.encode()).digest()


public_key_merchant=b""
with open('PubKM', 'rb') as f:
        public_key_merchant=f.read()
public_key_merchant=RSA.importKey(public_key_merchant)

if(public_key_customer.verify(PI_json_hash,PM["SigC"])==False):
    Resp="Invalid customer signature!"
elif(public_key_merchant.verify(aux_json_hash,aux_json_hash_signed)==False):
    Resp="Invalid merchant signature!"
else:
    Resp="Valid signatures!"

print(Resp)
conn.close()