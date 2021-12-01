# rsa-cryptography
## Avi Dixit
### Fall 2019

### Description
Python programs that allow the user to encrypt and decrypt files using RSA cryptography technology. 

### Implementation
crypto.py contains majority of the code to allow for RSA crypography. 
  * modular_exponentiation: returns (x**d) % n
  * bytes_to_int: converts bytes to their corresponding integer values
  * int_to_bytes: converts integers to their corresponding byte values
  * generate_pad: generates random pad for a given amount of bytes
  * encrypt_file: encrypts a file using the receiver's public key
  * decrypt_pad: decrypts one time pad
  * decrypt_file: decrypts supplied file using receiver's private key

encrypt.py contains your personal public key 
decrypt.py contains the receivers public and private keys
