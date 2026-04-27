import numpy as np
from math import gcd
import random


# ------------------------------------------------
# Find exponent e such that gcd(e, p-1)=1
# ------------------------------------------------

def find_exponent(p):
    for e in range(3, p):
        if gcd(e, p-1) == 1:
            #print(e)
            return e  
    raise ValueError("No exponent found")


# ------------------------------------------------
# SBOX: f(x) = x^e + c mod p
# ------------------------------------------------

def sbox(x, p, e, c):
    return (pow(int(x), e, p) + c) % p


# ------------------------------------------------
# SubBytes
# ------------------------------------------------

def sub_bytes(state, p, e, c):

    out = state.copy()

    for i in range(4):
        for j in range(4):
            out[i,j] = sbox(state[i,j], p, e, c)

    return out


# ------------------------------------------------
# ShiftRows
# ------------------------------------------------

def shift_rows(state):

    out = state.copy()

    for r in range(4):
        out[r] = np.roll(state[r], -r)

    return out


# ------------------------------------------------
# MixColumns
# ------------------------------------------------

def mix_columns(state, p):

    M = np.array([
        [1,1,1,1],
        [1,2,4,16],
        [1,4,16,2],
        [1,16,2,4]
    ], dtype=int)

    result = np.zeros((4,4), dtype=int)

    for col in range(4):
        result[:,col] = np.mod(M @ state[:,col], p)

    return result


# ------------------------------------------------
# AddRoundKey
# ------------------------------------------------

def add_round_key(state, key, p):
    return (state + key) % p


# ------------------------------------------------
# AES-Prime round
# ------------------------------------------------

def aes_prime_round(state, key, p, e, c):

    state = sub_bytes(state, p, e, c)

    state = shift_rows(state)

    state = mix_columns(state, p)

    state = add_round_key(state, key, p)

    return state

def aes_prime_finalround(state, key, p, e, c):

    state = sub_bytes(state, p, e, c)

    state = shift_rows(state)

    #state = mix_columns(state, p)

    state = add_round_key(state, key, p)

    return state


# ------------------------------------------------
# Round constants (multiples of 3 mod p)
# ------------------------------------------------

#def generate_rcon(rounds, p):

#    rcon = [1]
#    print(rcon)
#
#    for i in range(1, rounds):
#        rcon.append(pow(3, i, p))
#        print(rcon)
#
#    return rcon

def generate_rcon(rounds, p):
    rcon=[]
    for i in range(rounds):
        rcon.append(pow(3, i, p))
        #print(rcon)

    return rcon
    


# ------------------------------------------------
# RotWord
# ------------------------------------------------

def rot_word(word):
    return np.roll(word, -1)


# ------------------------------------------------
# SubWord
# ------------------------------------------------

def sub_word(word, p, e, c):

    out = word.copy()

    for i in range(4):
        out[i] = sbox(word[i], p, e, c)

    return out


# ------------------------------------------------
# Key schedule
# ------------------------------------------------

def key_schedule(master_key, rounds, p, e, c):

    rcon = generate_rcon(rounds, p)

    words = []

    # initial words
    for col in range(4):
        words.append(master_key[:,col].copy())

    for i in range(4, 4*(rounds+1)):

        temp = words[i-1].copy()

        if i % 4 == 0:

            temp = sub_word(temp, p, e, c)

            temp = rot_word(temp)

            temp[0] = (temp[0] + rcon[(i//4)-1]) % p

        new_word = (words[i-4] + temp) % p

        words.append(new_word)

    # convert to round keys
    round_keys = []

    for r in range(rounds+1):

        rk = np.zeros((4,4), dtype=int)

        for col in range(4):
            rk[:,col] = words[4*r + col]

        round_keys.append(rk)

    return round_keys


# ------------------------------------------------
# AES-Prime Encryption
# ------------------------------------------------

def aes_prime_encrypt(plaintext, master_key, p, c, rounds=10):

    e = find_exponent(p)

    round_keys = key_schedule(master_key, rounds, p, e, c)

    state = plaintext.copy()

    state = add_round_key(state, round_keys[0], p)

    for r in range(1, rounds):

        state = aes_prime_round(state,round_keys[r],p,e,c)

    #print(rounds)
    state = aes_prime_finalround(state, round_keys[rounds], p, e, c)

    return state


# ------------------------------------------------
# Example
# ------------------------------------------------

if __name__ == "__main__":

    #p = 127   # example prime

    p = int(input("Enter the mercen prime "))
    c = int(input("Enter the constan term for Sbox implementation "))

#    print(sbox(5,p,5,2))

#    print(generate_rcon(3, p))

    #plaintext = np.array([
    #    [1,2,3,4],
    #    [5,6,7,8],
    #    [9,10,11,12],
    #    [13,14,15,16]
    #], dtype=int)


    plaintext = np.array([
        [101,  35,  88, 100],
        [ 52,  50, 111,  45],
        [116,  28,  55,  67],
        [ 50,  88,  40,  16]
    ], dtype=int)

    master_key = np.array([
        [11,22,33,44],
        [55,66,77,88],
        [99,12,23,34],
        [45,56,67,78]
    ], dtype=int)

    ciphertext = aes_prime_encrypt(
        plaintext,
        master_key,
        p,
        c
    )

    print("Plaintext")
    print(plaintext)

    print("\nCiphertext")
    print(ciphertext)