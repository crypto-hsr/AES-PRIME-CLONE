import numpy as np
from math import gcd
from numpy.linalg import det, inv
from aesprime import key_schedule
from aesprime import aes_prime_encrypt


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

# ------------------------------------------------
# AES-Prime Decryption Rounds
# ------------------------------------------------

def aes_prime_decrypt(ciphertext, master_key, p, c, rounds=10):
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

    # 4. Undo Main Rounds
    for r in range(rounds - 1, 0, -1):
        state = (state - round_keys[r]) % p
        state = inv_mix_columns(state, p, M_inv)
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state, p, d, c)

    # 5. Undo Initial AddRoundKey
    state = (state - round_keys[0]) % p

    return state

# ------------------------------------------------
# Integration/Test
# ------------------------------------------------

if __name__ == "__main__":
    # Parameters used during encryption
    p = 127 
    c = 2

    #p = int(input("Enter the mercen prime "))
    #c = int(input("Enter the constan term for Sbox implementation "))
    plaintext = np.array([
        [1,2,3,4],
        [5,6,7,8],
        [9,10,11,12],
        [13,14,15,16]
    ], dtype=int)

    master_key = np.array([
        [11,22,33,44],
        [55,66,77,88],
        [99,12,23,34],
        [45,56,67,78]
    ], dtype=int)

    print("\nNow plaintext is:")
    print(plaintext)

    # encrypt using your provided aes_prime_encrypt if available, else assume ciphertext variable
    ciphertext = aes_prime_encrypt(plaintext, master_key, p, c)
    print("\nCiphertext is:")
    print(ciphertext)

    # For demonstration, decrypt the ciphertext produced by your encryption function
    #print("Decryption function ready")
    print("\nDecrypted ciphertext")
    decrypted = aes_prime_decrypt(ciphertext, master_key, p, c, rounds=10)
    print(decrypted)
    if np.array_equal(plaintext, decrypted):
        print("\nDecryption successful, plaintext matches decrypted text.\n")

    else:
        print("\nDecryption failed, plaintext does not match decrypted text.\n")