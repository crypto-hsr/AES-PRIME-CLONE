import numpy as np
from math import gcd
import random
import secrets
from numpy.linalg import det, inv
from aesprime import aes_prime_encrypt
from aesprime import key_schedule
from aesprime import find_exponent
from aesprime import aes_prime_finalround, add_round_key, aes_prime_round, find_exponent
#from aesprime_encdec import inv_sbox, inv_mix_columns

def generate_secure_random_integers(count=1, min_val=0, max_val=127):
    """
    Generate cryptographically secure random integers.
    """
    if count <= 0:
        raise ValueError("Count must be a positive integer.")
    if min_val > max_val:
        raise ValueError("min_val cannot be greater than max_val.")
    
    return [min_val + secrets.randbelow(max_val - min_val + 1) for _ in range(count)]

# ------------------------------------------------
# Modular Inverse Helpers
# ------------------------------------------------

def modInverse(a, m):
    # Returns the modular multiplicative inverse of a modulo m
    return pow(a, -1, m)

def matrix_mod_inv(matrix, p):
    """Calculates the inverse of a square matrix modulo p."""
    #from numpy.linalg import det, inv
    
    # Calculate determinant and its modular inverse
    d = int(round(det(matrix)))
    d_inv = modInverse(d % p, p)
    
    # Calculate adjugate matrix: adj(M) = det(M) * inv(M)
    adjugate = np.round(d * inv(matrix)).astype(int)
    
    # M^-1 = d_inv * adjugate (mod p)
    return (d_inv * adjugate) % p

# ------------------------------------------------
# Inverse Components
# ------------------------------------------------

def inv_sbox(y, p, d, c):
    # Reverse f(x) = x^e + c mod p  =>  x = (y - c)^d mod p
    return pow((int(y) - c) % p, d, p)

def inv_sub_bytes(state, p, d, c):
    out = state.copy()
    for i in range(4):
        for j in range(4):
            out[i,j] = inv_sbox(state[i,j], p, d, c)
    return out

def inv_shift_rows(state):
    out = state.copy()
    for r in range(4):
        # Shift right by r instead of left
        out[r] = np.roll(state[r], r)
    return out

def inv_mix_columns(state, p, M_inv):
    result = np.zeros((4,4), dtype=int)
    for col in range(4):
        result[:,col] = np.mod(M_inv @ state[:,col], p)
    return result

def aes_prime_five_rounds_encrypt(plaintext, master_key, p, c, rounds=5):

    e = find_exponent(p)

    round_keys = key_schedule(master_key, rounds, p, e, c)

    state = plaintext.copy()

    state = add_round_key(state, round_keys[0], p)

    for r in range(1, rounds):

        state = aes_prime_round(state,round_keys[r],p,e,c)

    #print(rounds)
    state = aes_prime_finalround(state, round_keys[rounds], p, e, c)

    return state


def aes_prime_four_round_encrypt(plaintext, master_key, p, c, rounds=4):

    e = find_exponent(p)

    round_keys = key_schedule(master_key, rounds, p, e, c)

    state = plaintext.copy()

    state = add_round_key(state, round_keys[0], p)

    for r in range(1, rounds+1):

        state = aes_prime_round(state,round_keys[r],p,e,c)
        #print(r)
    #print(rounds)
    #state = aes_prime_finalround(state, round_keys[rounds], p, e, c)

    return state

def aes_prime_three_round_encrypt(plaintext, master_key, p, c, rounds=3):

    e = find_exponent(p)

    round_keys = key_schedule(master_key, rounds, p, e, c)

    state = plaintext.copy()

    state = add_round_key(state, round_keys[0], p)

    for r in range(1, rounds+1):

        state = aes_prime_round(state,round_keys[r],p,e,c)

    #print(rounds)
    #state = aes_prime_finalround(state, round_keys[rounds], p, e, c)

    return state

def aes_prime_one_rounds_decrypt(ciphertext, master_key, p, c, rounds=5):
    # 1. Setup Parameters
    e = 3
    for i in range(3, p):
        if gcd(i, p-1) == 1:
            e = i
            break
            
    # Find decryption exponent d
    d = modInverse(e, p-1)
    
    # Precompute Inverse MixColumns Matrix
    M = np.array([
        [1,1,1,1],
        [1,2,4,16],
        [1,4,16,2],
        [1,16,2,4]
    ], dtype=int)
    M_inv = matrix_mod_inv(M, p)

    # 2. Key Schedule (same as encryption)
    # Import key_schedule from your original file or ensure it's in scope
    #from aesprime import key_schedule # Assuming original code is in aesprime.py
    round_keys = key_schedule(master_key, rounds, p, e, c)

    state = ciphertext.copy()

    # 3. Undo Final Round (No MixColumns)
    state = (state - round_keys[rounds]) % p
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state, p, d, c)

    #state = (state - round_keys[rounds-1]) % p
    #state = inv_mix_columns(state, p, M_inv)
    #state = inv_shift_rows(state)
    #state = inv_sub_bytes(state, p, d, c)
    
    # 4. Undo Main Rounds
    #for r in range(rounds - 1, 0, -1):
    #    state = (state - round_keys[r]) % p
    #    state = inv_mix_columns(state, p, M_inv)
    #    state = inv_shift_rows(state)
    #    state = inv_sub_bytes(state, p, d, c)

    # 5. Undo Initial AddRoundKey
    #state = (state - round_keys[0]) % p

    return state

p=127
c=2
plaintexts = []
ciphertexts = []

# Fixed suffix of 15 integers (all set to 0, which is 0 mod 127)
fixed_suffix = [16] * 15 

# Generating 127 distinct vectors in Z_127^16
# The first element iterates through the complete set of residues modulo 127 [0, 126]
plaintexts = [[i] + fixed_suffix for i in range(127)]


for i in range (0,127):
        plaintext = plaintexts[i]
        plaintext = np.array(plaintext, dtype=int).reshape((4,4))
        
        #print("Random plaintext (in integers):", plaintext)
        
        master_key = np.array([
            [11,22,33,44],
            [55,66,77,88],
            [99,12,23,34],
            [45,56,67,78]
        ], dtype=int)

        ciphertext = aes_prime_four_round_encrypt(
            plaintext,
            master_key,
            p,
            c
        )
        #print("Ciphertext (in integers):", ciphertext)

        ciphertexts.append(ciphertext)
    
#print("\nAll random plaintext:\n", plaintexts)
#print("\nAll ciphertexts:\n", ciphertexts)

ciphertextsum = sum(ciphertexts) % p
print("\nCiphertext sum (over mod 127):", ciphertextsum)