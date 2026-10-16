#!/usr/bin/python3

import sys

KEY = "EiichiroOda"

def xor(data, key) :
    key_bytes = key.encode('utf-8')
    l = len(key_bytes)
    output_str = bytearray()

    for i in range(len(data)):
        current = data[i]
        current_key = key_bytes[i % l]
        output_str.append(current ^ current_key)

    return bytes(output_str)

def printCiphertext(cuphertext) :
    print('unsigned char payload[] = { 0x' + ', 0x'.join(f"{x:02x}" for x in ciphertext) + ' };')
    print('unsigned int payload_len = sizeof(payload);')



try:
    plaintext = open(sys.argv[1], "rb").read()
except:
    print("File argument needed!")
    sys.exit()


ciphertext = xor(plaintext, KEY)
printCiphertext(ciphertext)
