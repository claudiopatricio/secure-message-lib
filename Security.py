# -*- coding: utf-8 -*-

# Copyright (c) 2018 Cláudio Patrício
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from Crypto.Cipher import *
import base64
import os
import hashlib
from Crypto import Random
from Crypto.Hash import HMAC

class MessageEncrypter:
	def __init__(self, passphrase="8iaRNT7Nj5w3Z57v", BS=64, KS=32, SS=32, DN=1777): # Size in bytes
		self.BS = BS # default block size
		self.KS = KS # default key size
		self.SS = SS # default salt size
		self.DN = DN # default deviation number
		self.passphrase = passphrase
	
	def pad(self, s, bs):
		return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)
	
	def unpad(self, s):
		return s[:-ord(s[len(s)-1:])]
	
	def encrypt(self, plaintext, mode=AES.MODE_CFB, base64=False):
		plaintext = self.pad(plaintext, self.BS)
		iv = os.urandom(AES.block_size) # IV size - 128 bits (16 bytes)
		salt = os.urandom(self.SS) # Random salt
		key = hashlib.sha256(self.passphrase).digest() # 256 bits (32 bytes)
		for i in range(0, self.DN): # Deviations
			key = hashlib.sha256(key+salt).digest()
		key = key[:self.KS]
		cipher = AES.new(key, mode, iv)
		ciphertext = cipher.encrypt(plaintext)
		ciphertext += iv + salt # cipher and add iv and salt to end
		if base64:
			import base64
			return base64.b64encode(ciphertext)
		else:
			return ciphertext.encode("hex")
	
	def decrypt(self, ciphertext, mode=AES.MODE_CFB, base64=False):
		if base64:
			import base64
			ciphertext = base64.b64decode(ciphertext)
		else:
			ciphertext = ciphertext.decode("hex")
		salt = ciphertext[len(ciphertext)-self.SS:]
		iv = ciphertext[len(ciphertext)-self.SS-AES.block_size:len(ciphertext)-self.SS]
		ciphertext = ciphertext[:len(ciphertext)-self.SS-AES.block_size]
		key = hashlib.sha256(self.passphrase).digest() # 256 bits (32 bytes)
		for i in range(0, self.DN): # Deviations
			key = hashlib.sha256(key+salt).digest()
		key = key[:self.KS]
		decipher = AES.new(key, mode, iv)
		deciphertext = decipher.decrypt(ciphertext)
		return self.unpad(deciphertext)


if __name__ == '__main__':
	sec = MessageEncrypter()
	encrypted = sec.encrypt("Hello World")
	print("Encrypted message: " + encrypted)
	print("Decrypted message: " + sec.decrypt(encrypted))
