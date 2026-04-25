# IN410 Project – S-DES GCM Implementation

## Description

This project implements a simplified version of the DES algorithm combined with a GCM mode (Galois/Counter Mode). It also includes a brute force attack to test the security of the system.

The goal of this project is to demonstrate how encryption systems work by combining:

- Confidentiality: protecting the content of the message
- Integrity: detecting any modification of the message
- Cryptanalysis: attempting to recover the key and plaintext without knowing the secret key

S-DES is used as the underlying block cipher, while the GCM-inspired approach introduces a counter-based encryption mechanism along with an authentication tag. The brute force attack then tests all possible S-DES keys to show the weakness of small key sizes.

The implementation is fully developed from scratch in Python without using any built-in cryptographic libraries.

## Objectives

The main objectives of this project are:

- Understand how block ciphers operate
- Implement counter mode encryption
- Introduce authentication using a tag mechanism
- Detect modified ciphertext before decryption
- Apply a brute force attack on S-DES
- Build a complete encryption, decryption, authentication, and cryptanalysis pipeline

## Features

- Full implementation of S-DES key generation, rounds, and permutations
- Counter mode encryption
- Authentication tag computation using Galois Field operations
- Detection of modified ciphertext before decryption
- Support for text input and automatic conversion to binary
- Complete encryption and decryption workflow
- Brute force attack over all 1024 possible S-DES keys
- Readability check to identify meaningful plaintext
- No use of external cryptographic libraries

## Process Steps

### 1. Text Conversion

The plaintext message is converted into binary using ASCII encoding. Each character is represented using 8 bits.

### 2. Block Processing

The binary message is divided into 8-bit blocks, which correspond to the input size of S-DES.

### 3. Counter Mode Encryption

Instead of encrypting the plaintext directly, the algorithm encrypts a counter using S-DES and uses the result as a keystream. This keystream is XORed with the plaintext block to produce the ciphertext block.

The counter is incremented after each block to ensure that each block uses a different keystream.

### 4. Authentication Tag Generation

After generating the ciphertext, an authentication tag is computed.

This tag is generated using:

- The initial counter
- The ciphertext
- The length of the ciphertext

The computation uses XOR operations and Galois Field multiplication. This ensures that the tag depends on all parts of the message.

### 5. Decryption and Verification

During decryption, the tag is recomputed from the received ciphertext and compared with the received tag.

If they match, decryption proceeds.  
If they do not match, the message is rejected.

If verification succeeds, the ciphertext is decrypted using the same counter-based process.

### 6. Brute Force Attack

After encryption and decryption are implemented, a brute force attack is applied to test the weakness of the S-DES key size.

Since S-DES uses a 10-bit key, there are only:

2^10 = 1024 possible keys

The program generates all possible 10-bit keys and tries to decrypt the ciphertext using each one. For every attempted key, the authentication tag is recomputed. If the tag does not match, the key is rejected. If the tag matches, the decrypted text is checked for readability using common English words and printable characters.

This allows the program to identify the correct key and recover the original plaintext.

## Main Functions

### S-DES Functions

- `permute()` → applies permutation tables
- `left_shift()` → performs circular shifts
- `xor_bits()` → performs XOR between two bit strings
- `generate_keys()` → generates subkeys K1 and K2
- `sbox_lookup()` → applies S-box substitution
- `sdes_round()` → performs one round of S-DES
- `switch_halves()` → swaps the left and right halves
- `sdes_encrypt_block()` → encrypts a single 8-bit block

### GCM / CTR Functions

- `gcm_encrypt()` → encrypts a full message and returns ciphertext with tag
- `gcm_decrypt()` → verifies the tag and decrypts the message
- `compute_auth_tag()` → computes the authentication tag
- `gf_multiply()` → performs multiplication in Galois Field

### Utility Functions

- `text_to_bits()` → converts text into binary
- `bits_to_text()` → converts binary back to text
- `split_into_blocks()` → divides data into 8-bit blocks
- `increment_counter()` → increments the counter value

### Brute Force Functions

- `is_readable_text()` → checks whether decrypted text appears meaningful
- `brute_force_sdes()` → tries all 1024 possible S-DES keys until the correct key is found

## Testing

### Input

```python
message = "The meeting will take place at midnight near the old bridge on the north side of the city. All participants must arrive separately and avoid drawing attention. Do not share this information with anyone outside the group, and make sure that all communication remains confidential at all times."

key = "1100010011"

counter = "00000001"

## Output

The program displays:

- Initial plaintext  
- Ciphertext  
- Authentication tag  
- Decrypted plaintext  
- Key recovered using brute force  


## How to Run

1. Open the Python file  
2. Run:

python IN410Project.py


## Note

This implementation is for educational purposes only.  
S-DES is not secure in real-world applications due to its small key size.
