from base64 import b64decode

from Crypto.Util.strxor import strxor


def calculer_keystream2(tag2, p):







    keystream2 = tag2 - (tag2 % p)
    return keystream2

def test(tag2):
    m1 = b'ICRYInTheMorning'
    nonce1 = b'4jxXG6+qpWc/qmVO'
    c1 = b'M8Z6qSO9s+tDsgytAPKtYQ=='
    tag1 = b'SLqaOTO86RpUlv0/+u73gA=='
    bloc_m1 = m1[:16]
    bloc_c1 = c1[:16]

    keystream1 = bloc_c1-bloc_m1
    print("keystream1:", keystream1)

    sigma = strxor(b64decode(bloc_c1), b64decode(bloc_m1))
    print("sigma:", int.from_bytes(sigma, byteorder='big'))

    test = int.from_bytes(tag1) - (int.from_bytes(tag1) % p)
    print("test:", test)


    tag1 = b64decode(tag1)
    print("tag1:", int.from_bytes(tag1, byteorder='big'))




# Exemple d'utilisation :
tag2 = 20
p = 7
keystream2 = calculer_keystream2(tag2, p)
print("Keystream2:", keystream2)

test(tag2)


if __name__ == '__main__':
    calculer_keystream2(tag2, p)