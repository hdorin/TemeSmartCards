import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random

random_generator = Random.new()
print(random_generator.read)