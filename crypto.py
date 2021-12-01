# crypto.py
# Functions for CS 1 Lab Assignment 4.
# Avi Dixit, November 2019

from random import randint

BYTE_SIZE = 8                                       # bits per byte


# Return (x**d) % n.
def modular_exponentiation(x, d, n):
    if d == 0:
        return 1
    elif d % 2 == 0:
        y = modular_exponentiation(x, d // 2, n)
        return (y * y) % n
    else:
        return (modular_exponentiation(x, d-1, n) * x) % n


# Takes a bytes or bytearray object and converts it to an int.
# Character 0 of the bytes/bytearray should be in byte 0 (the rightmost
# byte) of the int when we are done.
def bytes_to_int(bytes):
    result = 0
    shift = 0

    for byte in bytes:
        result += byte << shift
        shift += BYTE_SIZE

    return result


# Takes an int x and converts it to a bytearray.  Byte 0 (the least significant
# byte of the int) becomes byte 0 of the bytearray.  Also takes as a parameter
# the number of bytes to include in the bytearray.
def int_to_bytes(x, size):
    result = bytearray()
    mask = 0xFF     # mask for isolating least significant byte

    for i in range(size):
        result.append(x & mask)
        x >>= BYTE_SIZE

    return result


# Generate a random pad for a given number of bytes.  Return the pad,
# represented as a bytearray.
def generate_pad(block_size):
    # Local variable pad starts as an empty bytearray
    pad = bytearray()

    # While the length of the pad is not the length of the block_size, generate a random number between 0 to 255
    # and append that random number to the pad
    while len(pad) < block_size:
        random = randint(0, 255)
        pad.append(random)
    return pad


# XOR a block of bytes, byte by byte, with a key, which is a bytearray.
# The key must be at least as long as the block.
# Return the XORed block of bytes as a bytearray.
def xor_block(key, block):
    # Ensure that the length of the key is at least the length of the block before executing
    assert len(key) >= len(block)

    # Local variable cypher starts as an empty bytearray
    cypher = bytearray()

    # For i in the range of the length of the block, append each xor'ed bit to cypher bytearray
    for i in range(len(block)):
        cypher.append((key[i] ^ block[i]))
    return cypher


# Encrypt a plaintext file into a ciphertext file, using the hybrid cryptosystem.
# Parameters are the name of the plaintext file, the name of the ciphertext file,
# the exponent and modulus used for RSA encryption of the one-time pad, the
# number of bytes in the one-time pad, and the one-time pad (if None, then generate
# the one-time pad).
def encrypt_file(plaintext_file_name, ciphertext_file_name, e, n, block_size, pad=None):
    # Local variable ciphertext is the ciphertext file opened in byte writing mode
    ciphertext = open(ciphertext_file_name, "wb")
    # Local variable in_file is the plaintext file opened in byte reading mode
    in_file = open(plaintext_file_name, "rb")

    # If the pad is None, generate a random pad of size block_size. Convert that random pad from bytes to an int
    # then, do modular exponentiation and cast to a string. Then, write to ciphertext converting from a string
    # to bytes with a newline character at the end
    if pad is None:
        pad = generate_pad(block_size)
        pad_int = bytes_to_int(pad)
        encrypt_pad = str(modular_exponentiation(pad_int, e, n))
        ciphertext.write(bytes(encrypt_pad + "\n", "UTF-8"))

    # plaintext_block starts as the first 16 bytes in in_file
    plaintext_block = in_file.read(block_size)

    # While the length of the plaintext_block is greater than zero, write the xor'ed plaintext block to ciphertext,
    # then make plaintext_block be the next 16 bytes in in_file
    while len(plaintext_block) > 0:
        ciphertext.write(xor_block(pad, plaintext_block))
        plaintext_block = in_file.read(block_size)

    # Close both of the files
    in_file.close()
    ciphertext.close()


# Decrypt just a one-time pad from a file.  Assumes that the file is already open and
# that the caller will close the file.  The encrypted one-time pad is text that is
# the first line in the file.  Parameters are the file object, the exponent and modulus
# used for RSA decryption of the one-time pad, and the number of bytes in the one-time
# pad.  Returns the one-time pad as a bytearray.
def decrypt_pad(pad_file, d, n, block_size):
    # pad is the first line including the newline character in pad_file
    pad = pad_file.readline()

    # cast pad to an int from a string and do modular exponentiation
    int_decrypted_pad = modular_exponentiation(int(pad), d, n)

    # Convert the decrypted pad from an int into bytes
    decrypted_pad = int_to_bytes(int_decrypted_pad, block_size)

    return decrypted_pad


# Decrypt a ciphertext file into a decrypted plaintext file, using the hybrid cryptosystem.
# Parameters are the name of the ciphertext file, the name of the decrypted plaintext file,
# the exponent and modulus used for RSA decryption of the one-time pad, the
# number of bytes in the one-time pad, and the one-time pad (if None, then read and
# decrypt the one-time pad from the ciphertext file).
def decrypt_file(ciphertext_file_name, decrypted_file_name, d, n, block_size, pad=None):
    # Plaintext is the decrypted_file opened in byte writing mode
    plaintext = open(decrypted_file_name, "wb")

    # In_file is the ciphertext_file opened in byte reading mode
    in_file = open(ciphertext_file_name, "rb")

    # If the pad is none, then decrypt the pad from the first line in the ciphertext_file
    if pad is None:
        pad = decrypt_pad(in_file, d, n, block_size)

    # Ciphertext_block is the first 16 bytes in the ciphertext_file
    ciphertext_block = in_file.read(block_size)

    # While the length of the ciphertext_block is greater than zero, write the xor'ed ciphertext block to plaintext,
    # then make ciphertext_block be the next 16 bytes in in_file
    while len(ciphertext_block) > 0:
        plaintext.write(xor_block(pad, ciphertext_block))
        ciphertext_block = in_file.read(block_size)

    # Close both of the files
    in_file.close()
    plaintext.close()
