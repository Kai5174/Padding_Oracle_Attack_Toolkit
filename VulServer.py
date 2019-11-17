from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import binascii
import socket
import base64

BLOCK_SIZE = 16  # bytes


class CBCCipher():
    """
    Usage:
    cipher = CBCCipher(key)
    ciphertext = cipher.encrypt(plaintext)
    plaintext = cipher.decrypt(ciphertext)
    """

    def __init__(self, key: str):
        self.h = SHA256.new()
        self.h.update(str.encode(key))
        self.key = str.encode(self.h.hexdigest()[:BLOCK_SIZE]) # get a random key
        self.iv = Random.get_random_bytes(BLOCK_SIZE)

    def encrypt(self, msg: bytearray):
        padded_msg = self.pad(msg)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)

        return base64.b64encode(self.iv + cipher.encrypt(padded_msg.encode('utf-8')))

    def decrypt(self, ciphertxt: str):
        ct = base64.b64decode(ciphertxt)
        iv = ct[:BLOCK_SIZE]
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return self._remove_padding(cipher.decrypt(ct[BLOCK_SIZE:]))


    @staticmethod
    def pad(msg: str):
        app_len = BLOCK_SIZE - len(msg) % BLOCK_SIZE
        for ii in range(app_len):
            msg += chr(app_len)
        return msg

    @staticmethod
    def _remove_padding(data: str):
        # Cited from https://github.com/TheCrowned/padding-oracle-attack/blob/master/oracle.py
        pad_len = data[-1]

        if pad_len < 1 or pad_len > BLOCK_SIZE:
            return None
        for i in range(1, pad_len):
            if data[-i - 1] != pad_len:
                return None
        return data[:-pad_len]


class VulServer(CBCCipher):

    def is_padding_correct(self, ciphertxt: str):
        return self.decrypt(ciphertxt) is not None

if __name__ == '__main__':
    key = 'AVerySecureKeyThatNoOneKnows'
    vulserver = VulServer(key)

    plaintext = "APlaintextToGenerateCookies"
    ciphertext = vulserver.encrypt(plaintext)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('localhost', 8080))
    s.listen(1)

    while 1:
        clientsocket, addr = s.accept()
        clientsocket.send(ciphertext)
        while 1:
            msg = clientsocket.recv(1024)
            if b'verifyme: ' in msg:
                print('='*16)
                print('Try to verify: {}'.format(msg[10:]))
                print('The final Decryption is: {}'.format(vulserver.decrypt(msg[10:])))
            elif len(msg) == 0:
                print("End of Decryption")
                break
            elif vulserver.is_padding_correct(msg):
                clientsocket.send(b'1')
                print('Decrypted message: {}'.format(vulserver.decrypt(msg)))
            else:
                clientsocket.send(b'0')