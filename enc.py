import base64
import ctypes
import hashlib
import os
import sys
import subprocess
import time
import urllib2
from Crypto import Random
from Crypto.Cipher import AES
#sys.stderr = sys.stdout
#XOR_KEY = ord('K')
#URL = 'https://github.com/david378/test1/raw/master/shell.bin'
KEY = '42566662363636653238352d6265613137342063'

class AESCipher(object):
    def __init__(self, key): 
        self.bs = 32
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:]))

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

if __name__ == '__main__':
    plain = open(sys.argv[1]).read()
    open(sys.argv[1], 'wb').write(AESCipher(KEY).encrypt(plain))
