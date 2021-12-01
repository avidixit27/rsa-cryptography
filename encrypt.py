# encrypt.py
# Main code to encrypt a plaintext file.

from crypto import encrypt_file
BLOCK_SIZE = 16

e = 7
n = 4041855980319282374037307005604614740934586500271608279448451250019571398120026751802867053117912633

encrypt_file("decrypted2.txt", "ciphertext.txt", e, n, BLOCK_SIZE, None)
