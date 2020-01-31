# Block Affine Cipher Encryption & Decryption scripts

## How to run the programs?
This project was verified to be working with python 2.7 and above. This project does not use any external libraries.

### ENCRYPTION
The program need an input file named "plaintext.txt" that contains the content to be encrypted. 
This text file should be in the same directory as the source code encrypt.py
Open shell or command prompt and execute:
```
python encrypt.py
```
The output file "ciphertext.txt" would be created containing the encrypted content

### DECRYPTION
The program need an input file named "ciphertext.txt" that contains the content to be decrypted. 
This text file should be in the same directory as the source code decrypt.py
Open shell or command prompt and execute:
```
python decrypt.py
```
The output file "finalplaintextoutput.txt" would be created containing the decrypted content

**Note:** The encryption script would throw away any characters that is not a alphabet or not a upper case alphabet.
If the length of the words is not a multiple of the block size, 'B' or 'BB' is appended to the text to be encrypted.
So the decrypted text would show 'B' or 'BB' to make up the block size.
The spaces between words and line are preserved in the crypted and decrypted files.

Example:
Let the plaintext.txt contain the following text
THIS IS ALFINE CIPHER enCRYPTION***
ABC DEF GHI JKL MNO PQR STU VWX YZ

After the encryption, the ciphertext.txt would be
T|�O^d P�� AxbPiC Ki�J�� K�]AT�UO~
AFS PUb FKW UZf KP[ AFP PU_ FKT UYJ

The decrypted text in finalplaintextoutput.txt would be
THISBB ISB ALFINE CIPHER CRYPTIONB
ABC DEF GHI JKL MNO PQR STU VWX YZB

