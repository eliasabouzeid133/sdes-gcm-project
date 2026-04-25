
def permute(bits, table): 
    result = ""
    for position in table:
        result += bits[position - 1]   
    return result


def left_shift(bits, n):
    for i in range(n):
        first_bit = bits[0]        
        bits = bits[1:] + first_bit  
    return bits


def xor_bits(a, b):
    if len(a) != len(b):
        raise ValueError("Inputs must have the same length")

    result = ""
    for i in range(len(a)):
        if a[i] == b[i]:
            result += "0"
        else:
            result += "1"
    return result


def generate_keys(key10):
    if len(key10) != 10:
        raise ValueError("Key must be 10 bits")
    
    p10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    p8 = [6, 3, 7, 4, 8, 5, 10, 9]

    
    permuted_key = permute(key10, p10)

    
    left = permuted_key[:5]
    right = permuted_key[5:]

    
    left = left_shift(left, 1)
    right = left_shift(right, 1)

    
    combined = left + right
    k1 = permute(combined, p8)

    
    left = left_shift(left, 2)
    right = left_shift(right, 2)

    
    combined = left + right
    k2 = permute(combined, p8)

    return k1, k2


def sbox_lookup(bits4, sbox):
    row_bits = bits4[0] + bits4[3]
    col_bits = bits4[1] + bits4[2]

    row = int(row_bits, 2)
    col = int(col_bits, 2)

    value = sbox[row][col]

    return format(value, "02b")



def sdes_round(bits8, subkey):
    ep = [4, 1, 2, 3, 2, 3, 4, 1]
    p4 = [2, 4, 3, 1]
    S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2]
    ]
    S1 = [
    [0, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3]
    ]

   
    left = bits8[:4]
    right = bits8[4:]

    
    expanded_right = permute(right, ep)

    
    xored = xor_bits(expanded_right, subkey)

    
    left_part = xored[:4]
    right_part = xored[4:]

    
    s0_output = sbox_lookup(left_part, S0)
    s1_output = sbox_lookup(right_part, S1)

    
    combined_sbox = s0_output + s1_output

    
    p4_result = permute(combined_sbox, p4)

    
    new_left = xor_bits(left, p4_result)

    
    return new_left + right


def switch_halves(bits8):
    left = bits8[:4]
    right = bits8[4:]
    return right + left




def sdes_encrypt_block(block8, key10):
    ip = [2, 6, 3, 1, 4, 8, 5, 7]
    ip_inverse = [4, 1, 3, 5, 7, 2, 8, 6]

    
    k1, k2 = generate_keys(key10)

    
    permuted_block = permute(block8, ip)

    
    round1_result = sdes_round(permuted_block, k1)

    
    switched = switch_halves(round1_result)

    
    round2_result = sdes_round(switched, k2)

    
    ciphertext = permute(round2_result, ip_inverse)

    return ciphertext


def increment_counter(counter8):
    value = int(counter8, 2)      
    value += 1                    
    value = value % 256           
    return format(value, "08b")   


def split_into_blocks(bitstring, block_size):
    blocks = []              
    current_block = ""       

    for bit in bitstring:    
        current_block += bit  

        if len(current_block) == block_size:  
            blocks.append(current_block)      
            current_block = ""                

    return blocks            


def text_to_bits(text):
    bits = ""

    for c in text:
        ascii_value = ord(c)                 
        binary = format(ascii_value, "08b")  
        bits += binary                       

    return bits



def gf_multiply(x, y):
    result = 0

    for i in range(8):
        if y & 1:
            result ^= x

        carry = x & 0b10000000
        x = (x << 1) & 0xFF

        if carry:
            x ^= 0x1B

        y >>= 1

    return result




def compute_auth_tag(ciphertext_bits, key10, counter):
    H_bits = sdes_encrypt_block("00000000", key10)
    H = int(H_bits, 2)

    tag = 0

    length_block = format(len(ciphertext_bits) % 256, "08b")
    data_to_authenticate = counter + ciphertext_bits + length_block

    blocks = split_into_blocks(data_to_authenticate, 8)

    for block in blocks:
        block_value = int(block, 2)
        tag = gf_multiply(tag ^ block_value, H)

    return format(tag, "08b")

def gcm_encrypt(plaintext, key10, counter):
    if len(key10) != 10:
        raise ValueError("Key must be 10 bits")
    if len(counter) != 8:
        raise ValueError("Counter must be 8 bits")
    
    ciphertext = ""
    original_counter = counter

    plaintext_bits = text_to_bits(plaintext)
    blocks = split_into_blocks(plaintext_bits, 8)

    for block in blocks:
        keystream = sdes_encrypt_block(counter, key10)
        cipher_block = xor_bits(block, keystream)

        ciphertext += cipher_block
        counter = increment_counter(counter)

    tag = compute_auth_tag(ciphertext, key10, original_counter)

    return ciphertext, tag



def bits_to_text(bits):
    text = ""  

    blocks = split_into_blocks(bits, 8)  

    for block in blocks:
        ascii_value = int(block, 2)   
        character = chr(ascii_value)  
        text += character             

    return text


def gcm_decrypt(ciphertext_bits, key10, counter, received_tag):
    expected_tag = compute_auth_tag(ciphertext_bits, key10, counter)

    if expected_tag != received_tag:
        raise ValueError("Authentication failed: wrong key or modified ciphertext")

    plaintext_bits = ""

    blocks = split_into_blocks(ciphertext_bits, 8)

    for block in blocks:
        keystream = sdes_encrypt_block(counter, key10)
        plain_block = xor_bits(block, keystream)

        plaintext_bits += plain_block
        counter = increment_counter(counter)

    return bits_to_text(plaintext_bits)



def is_readable_text(text):
    common_words = ["the", "and", "to", "at", "in", "on", "with", "for", "is", "are", "of", "a", "an", "this", "that", "it", "by", "from", "as", "be", "was", "were", "will", "shall", "must", "should", "can", "could", "may", "might", "do", "does", "did", "have", "has", "had", "not", "but", "or", "if", "then", "else", "when", "while", "where", "who", "whom", "which", "what", "how", "why"]

    text_lower = text.lower()

    score = 0

    for word in common_words:
        if word in text_lower:
            score += 1

    readable_chars = 0
    for c in text:
        if c.isprintable():
            readable_chars += 1

    readable_ratio = readable_chars / len(text)

    if score >= 3 and readable_ratio > 0.9:
        return True

    return False


def brute_force_sdes(ciphertext_bits, counter, tag):
    print("Starting brute force attack...")
    print()

    for i in range(1024):
        key = format(i, "010b")

        try:
            decrypted_text = gcm_decrypt(ciphertext_bits, key, counter, tag)

            if is_readable_text(decrypted_text):
                print("Possible key found:", key)
                print()
                print("Decrypted plaintext:")
                print(decrypted_text)
                print()
                return key, decrypted_text

        except:
            pass

    print("No readable plaintext found.")
    return None, None


 
def main():
    message = "The meeting will take place at midnight near the old bridge on the north side of the city. All participants must arrive separately and avoid drawing attention. Do not share this information with anyone outside the group, and make sure that all communication remains confidential at all times."
    
    key = "1100010011"
    counter = "00000001"

    ciphertext, tag = gcm_encrypt(message, key, counter)
    decrypted_text = gcm_decrypt(ciphertext, key, counter, tag)

    print("Initial text:")
    print(message)
    print()

    print("Ciphertext:")
    print(ciphertext)
    print()
    
    print("Authentication tag:")
    print(tag)
    print()

    print("Decrypted text:")
    print(decrypted_text)
    print()

    brute_force_sdes(ciphertext, counter, tag)

if __name__ == "__main__":
    main()