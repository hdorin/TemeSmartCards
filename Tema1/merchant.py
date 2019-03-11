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
PORT = int(sys.argv[1])         # Port to listen on (non-privileged ports are > 1023)
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
def start_conn_paymentgateway():
    HOST = '127.0.0.1'  # The server's hostname or IP address
    PORT = int(sys.argv[1])+1         # The port used by the server

    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc.connect((HOST, PORT))
    print('Connected to', HOST,':', PORT)
    return soc


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

with open('PrivKM', 'rb') as f:
    private_key=f.read()
private_key=RSA.importKey(private_key)
aes_key_customer=private_key.decrypt(aes_key_encrypted_customer)
aes_cipher_customer = AESCipher(aes_key_customer)
public_key_customer=aes_cipher_customer.decrypt(public_key_encrypted_customer)

public_key_customer=str(public_key_customer)[4:-2]
public_key_customer=str(public_key_customer).replace("\\\\n",'\n')#fixing aes decryption result
public_key_customer=str(public_key_customer).encode()
public_key_customer=RSA.importKey(public_key_customer)
#print(public_key_customer)
#print(aes_key_customer)

SessionID=Random.random.randint(100000000000,9999999999999)
SessionID_signed=private_key.sign(SessionID,32)
SessionID_signed=str(SessionID_signed[0])
SessionID=str(SessionID)

#print(SessionID)
#print(SessionID_signed)

#Generating AES key
sha=hashlib.sha256()
sha.update(b"cheiameasimaisecreta")
sha.update((str)(Random.random.randint(100000000000,9999999999999)).encode())#adding salt
aes_key=sha.digest()
aes_cipher = AESCipher(aes_key)

aes_key_encryped=public_key_customer.encrypt(aes_key,32)
aes_key_encryped=aes_key_encryped[0]

SessionID_signed_encrypted=aes_cipher.encrypt(SessionID_signed)
SessionID_signed_encrypted=SessionID_signed_encrypted
#SessionID_signed_encrypted=str(SessionID_signed_encrypted).encode()

SessionID_encrypted=aes_cipher.encrypt(SessionID)

SessionID_encrypted=SessionID_encrypted
#SessionID_encrypted=str(SessionID_encrypted).encode()


conn.send(str(len(aes_key_encryped)).encode())
conn.send(aes_key_encryped)
conn.send(str(len(SessionID_encrypted)).encode())
conn.send(SessionID_encrypted)
conn.send(str(len(SessionID_signed_encrypted)).encode())
conn.send(SessionID_signed_encrypted)

#print(SessionID)
#print(SessionID_signed)

buf_size=conn.recv(3)
#print(aes_keyaes_ke"BUFF=",buf_size)
aes_key_customer_for_paymentgateway_encrypted=conn.recv(int(buf_size))
buf_size=conn.recv(4)
PM_json_encrypted=conn.recv(int(buf_size))
buf_size=conn.recv(3)
PO_json_encrypted=conn.recv(int(buf_size))

#FOURTH STEP

#Generating and AES key for Merchant - Payment Gateway communication
public_key_paymentgateway=b""
with open('PubKPG', 'rb') as f:
        public_key_paymentgateway=f.read()
public_key_paymentgateway=RSA.importKey(public_key_paymentgateway)

sha=hashlib.sha256()
sha.update(b"ultimameacheiesecreta")
sha.update((str)(Random.random.randint(100000000000,9999999999999)).encode())#adding salt
aes_key_for_paymentgateway=sha.digest()
aes_cipher_for_paymentgateway = AESCipher(aes_key_for_paymentgateway)
aes_key_for_paymentgateway_encrypted=public_key_paymentgateway.encrypt(aes_key_for_paymentgateway,32)
aes_key_for_paymentgateway_encrypted=aes_key_for_paymentgateway_encrypted[0]


PM_json_encrypted=aes_cipher.decrypt(PM_json_encrypted)
print("PM JSON ENC=",PM_json_encrypted)
PM_json_encrypted=aes_cipher_for_paymentgateway.encrypt(str(PM_json_encrypted))
PO_json=aes_cipher.decrypt(PO_json_encrypted)
PO=json.loads(PO_json)


aux=dict()
aux["Sid"]=int(SessionID)
aux["PubKC"]=str(public_key_customer.exportKey())
aux["amount"]=PO["Amount"]
aux_json=json.dumps(aux)

aux_json_hash=hashlib.sha256(aux_json.encode()).digest()
aux_json_hash_signed=private_key.sign(aux_json_hash,32)
aux_json_hash_signed=aux_json_hash_signed[0]
aux_json_hash_signed_encryped=aes_cipher_for_paymentgateway.encrypt(str(aux_json_hash_signed))
print("JSON=",aux_json_hash_signed)

print("Connecting to Payment Gateway...")
conn_paymentgateway=start_conn_paymentgateway()
conn_paymentgateway.send(str(len(aes_key_customer_for_paymentgateway_encrypted)).encode())
conn_paymentgateway.send(aes_key_customer_for_paymentgateway_encrypted)
conn_paymentgateway.send(str(len(aes_key_for_paymentgateway_encrypted)).encode())
conn_paymentgateway.send(aes_key_for_paymentgateway_encrypted)
conn_paymentgateway.send(str(len(PM_json_encrypted)).encode())
conn_paymentgateway.send(PM_json_encrypted)
conn_paymentgateway.send(str(len(aux_json_hash_signed_encryped)).encode())
conn_paymentgateway.send(aux_json_hash_signed_encryped)

#SIXTH STEP

buf_size=conn_paymentgateway.recv(3)
aes_key_paymentgateway_encrypted=conn_paymentgateway.recv(int(buf_size))
buf_size=conn_paymentgateway.recv(3)
aux_json_encrypted=conn_paymentgateway.recv(int(buf_size))

aes_key_paymentgateway=private_key.decrypt(aes_key_paymentgateway_encrypted)
aes_cipher_paymentgateway = AESCipher(aes_key_paymentgateway)
aux_json=aes_cipher_paymentgateway.decrypt(aux_json_encrypted)

aux_json_encrypted=aes_cipher_customer.encrypt(str(aux_json))

conn.send(str(len(aux_json_encrypted)).encode())
conn.send(aux_json_encrypted)


conn.close()
conn_paymentgateway.close()