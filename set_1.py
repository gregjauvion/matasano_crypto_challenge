
#####
# A correction for Set 1 of matasano crypto challenges
#####

##
# Challenge 1 : hexadecimal to base64
##

import base64

def hex_to_base64(s):
	dec = 
	return base64.b64encode(s.decode('hex'))

s = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
print hex_to_base64(s)


##
# Challenge 2 : XOR hexadecimal values
##

def hex_xor(x1, x2):
	return hex(int(x1,16) ^ int(x2,16))

x1 = "1c0111001f010100061a024b53535009181c"
x2 = "686974207468652062756c6c277320657965"

print hex_xor(x1, x2)


##
# Challenge 3 : decrypt XOR-encrypted text
##

# We could use letters frequency from an english plaintext, but this simpler method works also
def nb_letters(s):
	return float(sum([1 if ('a'<=i<='z' or 'A'<=i<='Z' or i==' ') else 0 for i in s])) / len(s)

def hex_xor_decrypt(h, i):
	return "".join([chr(ord(c) ^ i) for c in h.decode('hex')])

h = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
key_score = {}
for i in range(256):
	key_score[i] = nb_letters(decode(h, i))

i = max(key_score, key=key_score.get)
print decode(h, i)


##
# Challenge 4 : decrypt XOR-encrypted text
##

data = []
with open('inputs/4.txt', 'r') as f:
	for line in f:
		data.append(line.replace('\n',''))

key_score = {}
for d in data:
	for i in range(256):
		key_score[(d,i)] = nb_letters(decode(d, i))

top = max(key_score, key=key_score.get)
decode(top[0], top[1])


##
# Challenge 5 : fixed-size key XOR encryption
##

from itertools import cycle

h = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"

def xor_encrypt(h, key):
	return "".join([chr(ord(i) ^ ord(k)) for i,k in zip(h, cycle(key))]).encode('hex')

encrypt(h, "ICE")


##
# Challenge 6 : fixed-size key XOR decryption
##

def hamming(x,y):
	xx = "".join([bin(ord(i))[2:].ljust(8, "0") for i in x])
	yy = "".join([bin(ord(i))[2:].ljust(8, "0") for i in y])
	return sum([1 if i!=j else 0 for i,j in zip(xx,yy)])

# Weird : I find that hamming distance is 39, it should be 37 according to the doc...
x = "this is a test"
y = "wokka wokka!!!"
hamming(x, y)

with open("inputs/6.txt", "r") as f:
	data = base64.b64decode(f.read().replace('\n',''))

# Get size of the key
size_score = {}
for size in range(1,40):
	chunks = [data[i:i+size] for i in range(0,len(data),size)][:-1]
	hamm = float(sum([hamming(chunks[i],chunks[i+1]) for i in range(len(chunks)-1)])) / (len(chunks)-1)
	size_score[size] = hamm / size

key_size = min(size_score, key=size_score.get)

# Split the text in fixed-size chunks
chunks = [data[i:i+key_size] for i in range(0,len(data),key_size)]

# Estimate the key
key = ['a'] * key_size
for ind in range(key_size):
	n = 0
	for i in range(256):
		nb = nb_letters("".join([chr(ord(c[ind]) ^ i) for c in chunks if len(c)>ind]))
		if nb>n:
			n = nb
			key[ind] = chr(i)

# Decrypt the message
"".join([chr(ord(i) ^ ord(k)) for i,k in zip(data, cycle(key))])


##
# Challenge 7 : AES-ECB
##

from Crypto.Cipher import AES

aes = AES.new("YELLOW SUBMARINE", AES.MODE_ECB, "YELLOW SUBMARINE")

with open("inputs/7.txt", "r") as f:
	data = base64.b64decode(f.read().replace('\n',''))

dec = aes.decrypt(data)


##
# Challenge 8 : AES - not finished
##

from collections import defaultdict

with open("inputs/8.txt", "r") as f:
	data = map(lambda x:x.decode('hex'), f.read().split('\n')[:-1])

# For each cipher, get the most frequent bytes appearance
stats = {e:defaultdict(lambda :0) for e in range(len(data))}
for e,d in enumerate(data):
	for c in range(len(d)/16):
		stats[e][d[c:c+16]] += 1

ord_stats = sorted(stats, key=lambda x:max(stats[x].values()))

# This simple statistical analysis of the most frequent bytes does not work...


