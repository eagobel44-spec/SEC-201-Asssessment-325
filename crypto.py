# crypto.py
# All of the cryptography that the system uses is in this one file, so the server and
# client just call these functions (they dont do any crypto on their own).
# Each part matches one lecture: signatures, diffie-hellman, aes-gcm and hmac.

import base64
import hashlib
import hmac
import os
import secrets

from Crypto.Cipher import AES
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


# ---------- turning bytes into text and back ----------
# Keys and encrypted data are bytes, but messages are sent as JSON (which is text).
# So these two turn bytes into text and text back into bytes.

def to_text(data):
    return base64.b64encode(data).decode("ascii")


def to_bytes(text):
    return base64.b64decode(text)


# ---------- RSA signatures (lecture 7) ----------
# First: server and client (owner or team member) generate RSA keys (public and private).
# RSA is only used for signatures in this system, it never encrypts anything.
# The private key creates the signature, and the public key checks it.

# Generates the RSA keys. This gives back the private key (the public key comes from it).
def rsa_generate():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


# Creates a signature over a message with the private key.
# Signature = Sign(Message, PrivateKey), same as the lecture.
def rsa_sign(private_key, message):
    signature = private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return to_text(signature)


# Verifies the signature with the public key, and gives back True or False.
# If the message was changed, or it was signed by a different private key, this is False
# (so the receiver knows the message really came from the owner of that private key).
def rsa_verify(public_key, message, signature):
    try:
        public_key.verify(
            to_bytes(signature),
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, ValueError):
        return False


# These four turn a key into text and back, so that it can be saved in a file or sent over.
def public_key_to_text(public_key):
    pem = public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode("ascii")


def public_key_from_text(text):
    return serialization.load_pem_public_key(text.encode("ascii"))


def private_key_to_text(private_key):
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return pem.decode("ascii")


def private_key_from_text(text):
    return serialization.load_pem_private_key(text.encode("ascii"), password=None)


# The fingerprint is just a SHA-256 hash of the public key (lecture 6), cut short.
# This is so that two people can compare it by eye and know they have the same key.
def fingerprint(public_key):
    return hashlib.sha256(public_key_to_text(public_key).encode("ascii")).hexdigest()[:16]


# ---------- diffie-hellman exchange (lecture 5) ----------
# p and g are public numbers that everyone uses (this p is the big one from RFC 3526).
# Each side has a private key (a secret number) and a public key (computed from it).
# Both sides send their public keys to each other and compute a shared key.

P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
G = 2


# The private key is a random secret number. This is never sent to anyone.
def dh_private_key():
    return secrets.randbelow(P - 3) + 2


# The public key is computed from the private key (g^private mod p), and this is the one
# that gets sent over. It can't be turned back into the private key.
def dh_public_key(private_key):
    return pow(G, private_key, P)


# Computes the shared key with the other side's public key and my own private key.
# Both sides get the same value, without the value ever being sent.
# Then it is hashed with SHA-256 (lecture 6) so it becomes 32 bytes, which is what aes needs.
# (It also refuses public keys like 0 or 1, since those would make the shared key easy to guess.)
def dh_shared_key(their_public_key, my_private_key):
    if not 2 <= their_public_key <= P - 2:
        raise ValueError("Diffie-Hellman public key is out of range")
    shared_number = pow(their_public_key, my_private_key, P)
    return hashlib.sha256(shared_number.to_bytes(256, "big")).digest()


# ---------- aes-gcm encryption (lecture 4) ----------
# This is used to encrypt the messages and the confidential columns, so the data is
# encrypted and can't be read by anyone without the key. It also detects any tampering
# (that is what the tag is for).

# Creates a new random key (32 bytes). The two team keys are made with this.
def new_key():
    return os.urandom(32)


# Encrypts with aes-gcm. A new nonce is made every time, so the same data never comes
# out the same twice. The nonce, ciphertext and tag are put together and sent as one text.
def aes_encrypt(key, plaintext):
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return to_text(nonce + ciphertext + tag)


# Decrypts with aes-gcm. It splits the text back into nonce, ciphertext and tag.
# If the key is wrong, or the data was changed, it fails with an error (ValueError)
# instead of giving back wrong data.
def aes_decrypt(key, text):
    raw = to_bytes(text)
    nonce, ciphertext, tag = raw[:12], raw[12:-16], raw[-16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


# ---------- hmac pseudonyms (lecture 7 and 8) ----------
# Turns a name into a pseudonym with the team hmac key. The same name with the same key
# always gives the same pseudonym (so it can still be used in data analysis), but it
# cannot be reversed, and nobody without the key can compute it (so the server can't
# just guess the package names).
def pseudonym(key, name):
    return hmac.new(key, name.encode("utf-8"), hashlib.sha256).hexdigest()
