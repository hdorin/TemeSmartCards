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


def gen_keys(bits):
    new_key = RSA.generate(bits) 
    public_key = new_key.publickey().exportKey("PEM") 
    private_key = new_key.exportKey("PEM") 
    with open('PubKPG', 'wb') as f:
        f.write(public_key)
    with open('PrivKPG', 'wb') as f:
        f.write(private_key)

gen_keys(1024)

