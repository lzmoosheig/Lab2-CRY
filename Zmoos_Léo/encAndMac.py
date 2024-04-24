from base64 import b64decode
from Crypto.Cipher import AES

NONCE_LENGTH = 12
p = 340282366920938463463374607431768211507  # prime number

def bytesToInt(message):
    return int.from_bytes(message, "big")


def intToBytes(i):
    return int(i).to_bytes(16, "big")


# Compute the mac of message under key with nonce.
# It is similar to Poly1305
def mac(nonce, message, key):
    cipher = AES.new(key, mode=AES.MODE_ECB)
    v = bytesToInt(cipher.encrypt(b"\xff" * 16))
    blocks = [message[i:i + 16] for i in range(0, len(message), 16)]
    temp = 0
    for b in blocks:
        temp = (temp + bytesToInt(b) * v) % p
    temp = (temp + bytesToInt(cipher.encrypt(nonce + b"\x00" * (16 - NONCE_LENGTH)))) % p
    return intToBytes(temp)

# Encrypts the message under key with nonce.
# It is an improved CTR that exploits the power of prime numbers
def encrypt(nonce, message, key):
    ct = b""
    for i in range(len(message) // 16):
        cipher = AES.new(key, mode=AES.MODE_CTR, nonce=nonce)
        keystream = cipher.encrypt(b"\x00" * 16)  # Way to obtain keystream: we XOR with 0
        temp = (bytesToInt(message[16 * i:16 * (i + 1)]) + bytesToInt(keystream)) % p
        ct += intToBytes(temp)
    return ct


# Encrypt and MAC with the fixed algorithm
def encryptAndMac(nonce, message, key):
    ct = encrypt(nonce, message, key)
    tag = mac(nonce, message, key)
    return (ct, tag)


def computeV(tag, msg, c1):
    tagMod = bytesToInt(tag) % p
    m0 = msg[:16]
    c1 = c1[:16]
    # On peut calculer v
    sigma = (int.from_bytes(c1) - int.from_bytes(m0)) % p
    v = ((tagMod - sigma) * pow(bytesToInt(m0), -1, p)) % p  # multiplication par l'inverse modulo p *pow(m0, -1, p)

    return v

def computeM2(tag2, v, c2):
    # Calcul sum of c2 blocks
    sum = 0
    blocks = [c2[i:i + 16] for i in range(0, len(c2), 16)]
    n = len(c2) // 16

    for b in blocks:
        sum += bytesToInt(b)

    sigma = (int.from_bytes(tag2) - sum*v) * pow(1 - n * v, -1, p) % p

    # On peut retrouver m2
    message =b""
    for b in blocks:
        m = (bytesToInt(b) - sigma) % p
        message += intToBytes(m)

    return message

def main():
    m1 = b'ICRYInTheMorning'
    nonce1 = b'4jxXG6+qpWc/qmVO'
    c1 = b'M8Z6qSO9s+tDsgytAPKtYQ=='
    tag1 = b'SLqaOTO86RpUlv0/+u73gA=='
    nonce2 = b'BOQVAKOoO+YANkAs'
    c2 = b'y/g5o+7u5T0E1f+HfDQTSOv7MLCc9uPqSx8ShoN9BVU='
    tag2 = b'3rCXgXzAk/kfEDGaMrN2zA=='

    c1 = b64decode(c1)
    tag1 = b64decode(tag1)

    # On va calculer v qui est commun pour les deux messages
    v = computeV(tag1, m1, c1)
    print("v = ", v)

    m2 = computeM2(b64decode(tag2), v, b64decode(c2))
    print("m2 = ", m2)

if __name__ == "__main__":
    main()
