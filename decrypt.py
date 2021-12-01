# decrypt.py
# Main code to decrypt text and video ciphertext files.

from crypto import decrypt_file, decrypt_pad

BLOCK_SIZE = 16             # characters per block

d = 2661480680239898535516428493882002975282313443403273067728353309332128988156760842463549238010655623
n = 3105060793613214958102499909529003471162699017303930073091904632545274719722514969969920230535453983

decrypt_file("ciphertext1.txt", "decrypted1.txt", d, n, BLOCK_SIZE)
print("Decrypted ciphertext1.txt")
decrypt_file("ciphertext2.txt", "decrypted2.txt", d, n, BLOCK_SIZE)
print("Decrypted ciphertext2.txt")

pad_file = open("pad.txt", "rb")
pad = decrypt_pad(pad_file, d, n, BLOCK_SIZE)
pad_file.close()
decrypt_file("encrypted-video", "decrypted-video.mp4", None, None, BLOCK_SIZE, pad)
print("Decrypted encrypted-video")
