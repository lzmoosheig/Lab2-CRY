from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode


def encrypt(message, key):
    # pad the message
    message = pad(message, 16)

    cipher = AES.new(key, mode=AES.MODE_ECB)

    IV = Random.get_random_bytes(16)

    ciphertext = [IV]
    # First block
    m1 = message[:16]
    t = cipher.encrypt(m1)
    c1 = strxor(t, IV)
    ciphertext.append(c1)
    # Remaining blocks don't have an IV
    message_blocks = [message[16 * (i + 1):16 * (i + 2)] for i in range(len(message) // 16 - 1)]
    for m in message_blocks:
        t = cipher.encrypt(t)
        c = strxor(t, m)  # c = t XOR m => on connait c et on cherche c XOR t = m
        ciphertext.append(c)

    return b"".join(ciphertext)


def decrypt(ciphertext, key):
    IV = ciphertext[:16]
    plaintext = [IV]
    cipher = AES.new(key, mode=AES.MODE_ECB)

    # Pour le premier bloc
    c1 = ciphertext[16:32]
    t = strxor(c1, IV)

    m1 = cipher.decrypt(t)
    plaintext.append(m1)

    cipher_blocks = [ciphertext[16 * (i + 2):16 * (i + 3)] for i in range(len(ciphertext) // 16 - 2)]

    for c in cipher_blocks:
        t = cipher.encrypt(t)
        m = strxor(t, c)
        plaintext.append(m)

    return unpad(b"".join(plaintext), 16)


def break_ecb(m1, c1, c2):
    # Flag
    plaintext = []

    # Récupérer les IV
    IV1 = c1[:16]
    IV2 = c2[:16]
    # Pour le premier bloc
    ciphertext1 = c1[16:32]
    t1 = strxor(ciphertext1, IV1)
    # Pour le deuxième bloc
    ciphertext2 = c2[16:32]
    t2 = strxor(ciphertext2, IV2)

    # Check if they are the same, the attack is possible only because of this
    # print("T1:", t1)
    # print("T2:", t2)

    cipher_blocks1 = [c1[16 * (i + 2):16 * (i + 3)] for i in range(len(c1) // 16 - 2)]
    cipher_blocks2 = [c2[16 * (i + 2):16 * (i + 3)] for i in range(len(c2) // 16 - 2)]

    # XOR avec les blocs de M1
    # xor la keystream avec les blocs de M1 pour retrouver les blocs de M2

    for i in range(len(cipher_blocks2)):
        keystream = strxor(cipher_blocks1[i], cipher_blocks2[i])
        m = strxor(keystream, m1[16 * (i + 1):16 * (i + 2)])
        plaintext.append(m)

    return unpad(b"".join(plaintext), 16)
def test():
    key = Random.get_random_bytes(16)
    m1 = b"This is a long enough test message to check that everything is working fine and it does. This algorithm is super secure and we will try to sell it soon to the Swiss governement."
    c1 = encrypt(m1, key)
    print(b64encode(c1))

    c2_d = decrypt(c1, key)
    print(c2_d)

    m1 = b'This is a long enough test message to check that everything is working fine and it does. This algorithm is super secure and we will try to sell it soon to the Swiss governement.'
    c1 = b'U7sl/fEaFkZq9KiuOhRsPZXTSxKg341L+4LlyDBG2bdeVVegWf3NshUNATDy8AF4LyFIp54WaUkkjLt+MROQaUPqCGB26J4luCmFXHIpKP+RRcTF7AH9Ch8WjVUReE1KCsMmqsEthokZQUklyB7u/eizSoCvjVHslbqu/tyyuR09Nf4lWDLn+Q4ib7B5pGRdUktg4wbwALcbz9o3btwHLmbhNu5S/w39FX/1Z2XbNMdwt2HEC1awGKUbhY503pJaWUMjflvUillOay3zgpWang=='
    c2 = b'w3KYrI71uVBA3ah3f5OVDAUa9kPfMCJd0avlEXXBIIZeVVegWf3UshUKQDryoxR2OmQBp9FCZQEjivAtIBiEbwahXlFs9Mo+tCSQGW96buSfUI/F8UaxGQUMjgAcFSpp'

    print("Decrypted message = ", break_ecb(m1, b64decode(c1), b64decode(c2)))


if __name__ == '__main__':
    test()
