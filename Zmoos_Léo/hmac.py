from Crypto.Cipher import AES
from Crypto import Random
from base64 import b64encode, b64decode
from Crypto.Util.strxor import strxor
import sys


def pad(m):
    m += b"\x80"
    while len(m) % 16 != 0:
        m+= b"\x00"
    return m

def h(m, k):
    m = pad(m)
    blocks = [m[i:i + 16] for i in range(0, len(m), 16)]
    h = k
    for i in range(len(blocks)):
        h = strxor(AES.new(blocks[i], AES.MODE_ECB).encrypt(h), h)
    return h

def mac(message, key):
    return h(message, key)

def ex():
    k = Random.get_random_bytes(16)
    m = b"Sender: Alexandre Duc; Destination account 12-1234-12. Amount CHF123"
    mc =  mac(m, k)
    print("keyMac = %s" % b64encode(k), file=sys.stderr)
    print("m = %s" % m)
    print("mac = %s" % b64encode(mc))

#m has to be a bytestring
def pretty_print(m):
    print(m.decode("UTF-8", errors="ignore"))

