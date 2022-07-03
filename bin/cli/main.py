#!/usr/bin/env python
from argon2 import PasswordHasher
import os, binascii
from backports.pbkdf2 import pbkdf2_hmac

def encryptAlg(password):
    salt = binascii.unhexlify('aaef2d3f4d77ac66e9c5a6c3d8f921d1')
    passwd = password.encode("utf8")
    key = pbkdf2_hmac("sha256", passwd, salt, 50000, 32)
    return binascii.hexlify(key)

def hashPsw(ph, password):
    encryptedStr = encryptAlg(password)
    return ph.hash(encryptedStr)

def check_password(ph, password, hashed):
    try:
        ph.verify(hashed, password)
        print("[COMP_HASH] true")
    except:
        print("[COMP_HASH] false")


def comp_hash(ph, psw1, psw2):
    hash1 = hashPsw(ph, psw1)
    encryptedStr = encryptAlg(psw2)
    print( "[COMP_HASH] psw1 = %s, psw2 = %s" % (psw1, psw2));
    check_password(ph, encryptedStr, hash1)

def printPsw(ph, password):
    print( "[INPUT] %s" % password);
    print( "[OUTPUT] %s" % hashPsw(ph, password));

def main():
    ph = PasswordHasher()
    psw1 = 'pass123';
    psw2 = '123pass';
    printPsw(ph, psw1)
    printPsw(ph, psw2)
    comp_hash(ph, psw1, psw1)
    comp_hash(ph, psw1, psw2)

if __name__ == '__main__':
    main()
