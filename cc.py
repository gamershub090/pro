# PRACTICAL 2 – CLASSICAL CIPHERS
# Run: python3 practical2_classical_ciphers/classical_ciphers.py

import string
ABC = string.ascii_uppercase

def caesar(text, key, decrypt=False):
    shift = (-key if decrypt else key) % 26
    out = ""
    for ch in text:
        if ch.isalpha() and ch.upper() in ABC:
            idx = (ord(ch.upper()) - 65 + shift) % 26
            out += chr(idx + 65) if ch.isupper() else chr(idx + 97)
        else:
            out += ch
    return out

def caesar_key_from_uid(uid):
    return sum(int(d) for d in str(uid) if d.isdigit()) % 25 + 1

def mono_encrypt(text, key_alphabet):
    key = key_alphabet.upper()
    if len(key) != 26 or set(key) != set(ABC):
        raise ValueError("Key must be a permutation of A-Z, exactly 26 letters")
    mapping = dict(zip(ABC, key))
    return "".join(mapping[ch] if ch in mapping else mapping[ch.upper()].lower()
                   if ch.isalpha() and ch.upper() in mapping else ch for ch in text)

def mono_decrypt(text, key_alphabet):
    key = key_alphabet.upper()
    if len(key) != 26 or set(key) != set(ABC):
        raise ValueError("Key must be a permutation of A-Z, exactly 26 letters")
    inverse = {v: k for k, v in zip(ABC, key)}
    return "".join(inverse[ch] if ch in inverse else inverse[ch.upper()].lower()
                   if ch.isalpha() and ch.upper() in inverse else ch for ch in text)

def vigenere(text, keyword, decrypt=False):
    keyword = "".join(c for c in keyword.upper() if c.isalpha())
    if not keyword:
        raise ValueError("Keyword must contain letters")
    out, j = "", 0
    for ch in text:
        if ch.isalpha() and ch.upper() in ABC:
            shift = ord(keyword[j % len(keyword)]) - 65
            if decrypt:
                shift = -shift
            base = 65 if ch.isupper() else 97
            out += chr((ord(ch) - base + shift) % 26 + base)
            j += 1
        else:
            out += ch
    return out

def clean_letters(text):
    return "".join(c for c in text.upper() if c in ABC).replace("J", "I")

def playfair_matrix(keyword):
    keyword = clean_letters(keyword)
    sequence, seen = "", set()
    for ch in keyword + "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if ch not in seen:
            sequence += ch
            seen.add(ch)
    return [list(sequence[i:i+5]) for i in range(0, 25, 5)]

def playfair_prepare(text):
    text = clean_letters(text)
    pairs, i = [], 0
    while i < len(text):
        a = text[i]
        if i + 1 >= len(text):
            b = "X" if a != "X" else "Q"
            i += 1
        elif text[i + 1] == a:
            b = "X" if a != "X" else "Q"
            i += 1
        else:
            b = text[i + 1]
            i += 2
        pairs.append(a + b)
    return pairs

def playfair(text, keyword, decrypt=False):
    matrix = playfair_matrix(keyword)
    pos = {matrix[r][c]: (r, c) for r in range(5) for c in range(5)}
    pairs = playfair_prepare(text)
    result = ""
    step = -1 if decrypt else 1
    for pair in pairs:
        a, b = pair
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            result += matrix[ra][(ca + step) % 5] + matrix[rb][(cb + step) % 5]
        elif ca == cb:
            result += matrix[(ra + step) % 5][ca] + matrix[(rb + step) % 5][cb]
        else:
            result += matrix[ra][cb] + matrix[rb][ca]
    return result

def hill_det_inverse(matrix, mod=26):
    a, b = matrix[0]
    c, d = matrix[1]
    det = (a*d - b*c) % mod
    for x in range(mod):
        if (det*x) % mod == 1:
            return det, x
    raise ValueError("Matrix is not invertible modulo 26; choose another key")

def hill_inverse(matrix, mod=26):
    (a, b), (c, d) = matrix
    det, invdet = hill_det_inverse(matrix, mod)
    return [[(d*invdet) % mod, (-b*invdet) % mod],
            [(-c*invdet) % mod, (a*invdet) % mod]]

def hill_process(text, matrix, decrypt=False):
    if len(matrix) != 2 or any(len(row) != 2 for row in matrix):
        raise ValueError("This implementation uses a 2x2 Hill key")
    key = hill_inverse(matrix) if decrypt else matrix
    letters = clean_letters(text)
    if len(letters) % 2:
        letters += "X"
    out = ""
    for i in range(0, len(letters), 2):
        x, y = ord(letters[i])-65, ord(letters[i+1])-65
        u = (key[0][0]*x + key[0][1]*y) % 26
        v = (key[1][0]*x + key[1][1]*y) % 26
        out += chr(u+65) + chr(v+65)
    return out

def main():
    while True:
        print("\\nPRACTICAL 2 – CLASSICAL CIPHERS")
        print("1 Caesar  2 Monoalphabetic  3 Vigenere  4 Playfair  5 Hill 2x2  0 Exit")
        choice = input("Choice: ").strip()
        try:
            if choice == "0":
                break
            mode = input("Encrypt or decrypt? (e/d): ").strip().lower()
            decrypt = mode == "d"
            text = input("Text: ")
            if choice == "1":
                key = int(input("Shift key: "))
                print(caesar(text, key, decrypt))
            elif choice == "2":
                key = input("26-letter substitution alphabet: ")
                print(mono_decrypt(text, key) if decrypt else mono_encrypt(text, key))
            elif choice == "3":
                key = input("Keyword: ")
                print(vigenere(text, key, decrypt))
            elif choice == "4":
                key = input("Playfair keyword: ")
                print("Matrix:")
                for row in playfair_matrix(key):
                    print(" ".join(row))
                print(playfair(text, key, decrypt))
                if decrypt:
                    print("Note: remove filler X/Q manually where appropriate.")
            elif choice == "5":
                print("Enter key matrix row-wise (4 integers).")
                matrix = [[int(input("a11: ")), int(input("a12: "))],
                          [int(input("a21: ")), int(input("a22: "))]]
                print("determinant and inverse determinant:", hill_det_inverse(matrix))
                print(hill_process(text, matrix, decrypt))
            else:
                print("Invalid choice")
        except ValueError as err:
            print("Input/error:", err)

if __name__ == "__main__":
    main()
