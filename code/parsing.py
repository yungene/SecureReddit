import praw
import re
import traceback
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad
from base64 import b64encode, b64decode
from Crypto.Util.Padding import unpad
from Crypto.Util import number
from Crypto.Hash import SHA256

# This file deals with parsing/formatting the messages
# as well as with encrypting and decrypting, and
# private key generation.

# TODO: implement certs in profile pinned post
public_key_pattern = "\<SSM-PUB\>(.*)\<\/SSM-PUB\>"
public_key_format = "<SSM-PUB>%s</SSM-PUB>"
message_pattern = "\<SSM-SYM\>\<USR\>\/u\/(.*)\<\/USR\>\<IV\>(.*)\<\/IV\>(.*)\<\/SSM-SYM\>"
message_format = "<SSM-SYM><USR>/u/%s</USR><IV>%s</IV>%s</SSM-SYM>"
symm_key_pattern = "\<SSM-MSG\>\<USR\>\/u\/(.*)\<\/USR\>(.*)<\/SSM-MSG\>"
symm_key_format = "<SSM-MSG><USR>/u/%s</USR>%s</SSM-MSG>"

# Retrieve private key from a file, else generate a new key
def get_priv_key(client):
    key = None
    f = None
    try:
        with open("mykey" + client.username + ".pem",'r') as f:
            key = RSA.import_key(f.read())
    except IOError:
        key = generate_key(client)
    return key

def generate_key(client):
   key = RSA.generate(2048)
   f = open("mykey" + client.username + ".pem", 'wb')
   f.write(key.export_key('PEM'))
   f.close()
   return key

# Encrypt a message using AES in CBC mode woth 128 bits random key.
# Returs the session key and the formatted encrypted message
def encrypt_message(client,message):
    session_key = get_random_bytes(16)
    cipher_aes = AES.new(session_key, AES.MODE_CBC)
    ct_bytes = cipher_aes.encrypt(pad(message.encode(), AES.block_size))
    iv = b64encode(cipher_aes.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    cipher_msg = message_format % (client.username, iv,ct)
    return session_key, cipher_msg

# Parsed message is expected
def decrypt_message(session_key,iv,c_message):
    try:
        cipher = AES.new(session_key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(c_message), AES.block_size)
        return pt
    except:
        traceback.print_exc()
    return "Incorrect decryption."

# Encrypt the symmetric key using user's public key.
# Uses PKCS1 OAEP with SHA256.
def ecnrypt_symm_key(user, user_pub_key, symm_key):
    print(user_pub_key);
    key = RSA.import_key(user_pub_key)

    # encrypt symm key wirh public RSA key
    cipher = PKCS1_OAEP.new(key,SHA256)

    # Adapted from github kadaliao/rsa_util.py
    # to calculate the max message size the cipher can handle
    # it can be of variable length, but not longer than the RSA modulus (in bytes)
    # minus 2, minus twice the hash output size.
    modBits = number.size(cipher._key.n)
    k = number.ceil_div(modBits, 8)
    hLen = cipher._hashObj.digest_size
    length = k - 2*hLen - 3

    res = []
    for i in range(0, len(symm_key), length):
        res.append(cipher.encrypt(symm_key[i:i+length]))
    ciph_symm_key =  b''.join(res)

    symm_b64 = b64encode(ciph_symm_key).decode('utf-8')
    return symm_key_format % (user, symm_b64)

# Decrypt using private key provided.
# priv_key as a key object, not a string.
def decrypt_symm_key(priv_key, c_symm_key):

    cipher = PKCS1_OAEP.new(priv_key,SHA256)
    length = priv_key.size_in_bytes()
    res = []
    for i in range(0, len(c_symm_key), length):
        decrypted_block = cipher.decrypt(c_symm_key[i:i + length])
        res.append(decrypted_block)
    return b''.join(res)

def parse_public_key(key_str):
    m = re.search(public_key_pattern,key_str)
    if m is None:
        return None
    return b64decode(m.group(1).encode("utf-8"))

def parse_message(msg_str):
    m = re.search(message_pattern,msg_str)
    if m is None:
        return None
    user = m.group(1)
    iv = b64decode(m.group(2).encode("utf-8"))
    msg = b64decode(m.group(3).encode("utf-8"))
    return user,iv, msg

def parse_symm_key(key_str):
    m = re.search(symm_key_pattern,key_str)
    if m is None:
        return None
    user = m.group(1)
    key_c = b64decode(m.group(2).encode("utf-8"))
    return user, key_c