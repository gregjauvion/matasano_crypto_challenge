
from Crypto.Cipher import AES

##
# Challenge 9 : padding
##

def pad(s, n):
	if len(s)>=n:
		return s
	return s + chr(4) * (n-len(s))

print pad("YELLOW SUBMARINE", 20)


##
# Challenge 10 : CBC mode
##

def xor(s1,s2):
	return "".join([chr(ord(i) ^ ord(j)) for i,j in zip(s1,s2)])

iv = chr(0) * 16
aes = AES.new("YELLOW SUBMARINE", AES.MODE_ECB, iv)

def encrypt_cbc(s, iv):
	s = pad(s, 16*int((len(s)-1)/16+1))
	cipher = ""
	temp = iv # temps is xored with plaintext block before encryption
	for i in range(len(s)/16):
		plain = s[i*16:(i+1)*16]
		enc = aes.encrypt(xor(plain, temp))
		cipher += enc
		temp = enc
	return cipher

def decrypt_cbc(s, iv):
	plain = ""
	temp = iv
	for i in range(len(s)/16):
		cipher = s[i*16:(i+1)*16]
		plain += xor(aes.decrypt(cipher), temp)
		temp = cipher
	return plain

test = "Un test à encrypter, qui fait pluq que 16 bytes car c'est mieux!"
cipher = encrypt_cbc(test, iv)
plain = decrypt_cbc(cipher, iv)
print cipher
print plain

# Decrypt the example
with open("inputs/10.txt", "r") as f:
	cipher = f.read().replace('\n','')

print decrypt_cbc(base64.b64decode(cipher), iv)


##
# Challenge 11 : not so interesting
##


##
# Challenge 12 : ecb decryption
##

import numpy as np

def random_key():
	return "".join([chr(np.random.randint(2**8)) for i in range(16)])

KEY = random_key()
S = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

def enc(s):
	s = s + base64.b64decode(S)
	s = pad(s, 16*int((len(s)-1)/16+1))
	iv = chr(0) * 16
	aes = AES.new(KEY, AES.MODE_ECB, iv)
	return aes.encrypt(s)

block_size = 16
enc("a"*16)[-5:-1]
enc("")[-5:-1]

# Decrypt the first bytes of the message (we coul decrypt the whole message this way...)
dec = ""
for c in range(1,10):
	solution = enc("a"*(16-c))[:16]
	all_bytes = {i:enc("a"*(16-c)+dec+chr(i))[:16] for i in range(2**8)}
	sol_byte = [i for i in all_bytes if all_bytes[i]==solution]
	if len(sol_byte)==1:
		print "Decrypted!"
		dec += chr(sol_byte[0])
	else:
		"Problem!"


##
# Challenge 13 : cut-paste
##

def parse(kv):
	return {i.split('=')[0]:i.split('=')[1] for i in kv.split('&')}

to_parse = "foo=bar&baz=qux&zap=zazzle"



