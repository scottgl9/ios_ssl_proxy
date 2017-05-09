#!/usr/bin/python3
import os
import paramiko
import plistlib
from Crypto.Cipher import AES
from binascii import unhexlify

ZEROIV = "\x00"*16
def removePadding(blocksize, s):
    'Remove rfc 1423 padding from string.'
    n = ord(s[-1]) # last byte contains number of padding bytes
    if n > blocksize or n > len(s):
        raise Exception('invalid padding')
    return s[:-n]


def AESdecryptCBC(data, key, iv=ZEROIV, padding=False):
    if len(data) % 16:
        print("AESdecryptCBC: data length not /16, truncating")
        data = data[0:(len(data)/16) * 16]
    data = AES.new(key, AES.MODE_CBC, iv).decrypt(data)
    if padding:
        return removePadding(16, data)
    return data

server="192.168.12.249"

ssh = paramiko.SSHClient() 
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy()) 
ssh.connect("192.168.12.249", username='root', password='alpine')
sftp = ssh.open_sftp()
#sftp.put(localpath, remotepath)
sftp.get("/var/keybags/systembag.kb", "systembag.kb")
sftp.close()
ssh.close()

binkeybag = open("systembag.kb", 'rb').read()
p = plistlib.readPlistFromBytes(binkeybag)
wipeid ="%x"%(p["_MKBWIPEID"])
decpl = AESdecryptCBC(p["_MKBPAYLOAD"].data, wipeid, p["_MKBIV"].data, padding=True)
print(p)
