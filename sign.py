# PRACTICAL 8 / SYLLABUS – EDUCATIONAL DIGITAL SIGNATURES
# Run: python3 practical8_digital_signatures/signatures.py
#
# WARNING: Educational small-parameter code only. Not production cryptography.
# No third-party modules are used. A tiny deterministic teaching hash is used
# for DSA-family examples so that the code remains self-contained.

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
from math_utils import gcd, mod_inverse, mod_exp, is_prime_trial

def toy_hash(message, q):
    # Not a cryptographic hash. Only maps a string to an integer for demos.
    value = 0
    for i, ch in enumerate(message):
        value = (value * 257 + ord(ch) + i) % q
    return value

# 1) Textbook RSA signature (NOT RSA-PSS)
def rsa_sign(message_int, private_key):
    n, d = private_key
    return mod_exp(message_int % n, d, n)

def rsa_verify(message_int, signature, public_key):
    n, e = public_key
    return mod_exp(signature, e, n) == message_int % n

# 2) ElGamal digital signature over Z_p*
def elgamal_sign(message, p, g, x, k):
    q = p - 1
    if gcd(k, q) != 1:
        raise ValueError("k must be coprime to p-1")
    y = mod_exp(g, x, p)
    r = mod_exp(g, k, p)
    s = (mod_inverse(k, q) * (toy_hash(message, q) - x*r)) % q
    return y, (r, s)

def elgamal_verify(message, p, g, y, signature):
    r, s = signature
    if not (0 < r < p and 0 <= s < p-1):
        return False
    left = (mod_exp(y, r, p) * mod_exp(r, s, p)) % p
    right = mod_exp(g, toy_hash(message, p-1), p)
    return left == right

# 3) Schnorr signature over a subgroup of order q
def schnorr_sign(message, p, q, g, x, k):
    y = mod_exp(g, x, p)
    R = mod_exp(g, k, p)
    e = toy_hash(str(R) + "|" + message, q)
    s = (k + e*x) % q
    return y, (R, s)

def schnorr_verify(message, p, q, g, y, signature):
    R, s = signature
    e = toy_hash(str(R) + "|" + message, q)
    return mod_exp(g, s, p) == (R * mod_exp(y, e, p)) % p

# 4) DSA signature (toy hash; small classroom parameters only)
def dsa_sign(message, p, q, g, x, k):
    if (p-1) % q != 0:
        raise ValueError("q must divide p-1")
    if not 1 <= k < q:
        raise ValueError("k must be in 1..q-1")
    y = mod_exp(g, x, p)
    r = mod_exp(g, k, p) % q
    if r == 0:
        raise ValueError("Choose another k; r became zero")
    s = (mod_inverse(k, q) * (toy_hash(message, q) + x*r)) % q
    if s == 0:
        raise ValueError("Choose another k; s became zero")
    return y, (r, s)

def dsa_verify(message, p, q, g, y, signature):
    r, s = signature
    if not (0 < r < q and 0 < s < q):
        return False
    w = mod_inverse(s, q)
    u1 = (toy_hash(message, q) * w) % q
    u2 = (r*w) % q
    v = ((mod_exp(g, u1, p) * mod_exp(y, u2, p)) % p) % q
    return v == r

# 5) ECDSA over a prime-field curve.
# Uses toy_hash; nonce must be secret, unpredictable and never reused in real systems.
def ecdsa_sign(message, p, a, G, n, d, k):
    R = scalar_mult(k, G, a, p)
    if R is None:
        raise ValueError("Invalid nonce: kG is infinity")
    r = R[0] % n
    if r == 0:
        raise ValueError("Choose another k")
    z = toy_hash(message, n)
    s = (mod_inverse(k, n) * (z + r*d)) % n
    if s == 0:
        raise ValueError("Choose another k")
    Q = scalar_mult(d, G, a, p)
    return Q, (r, s)

def ecdsa_verify(message, p, a, G, n, Q, signature):
    r, s = signature
    if not (0 < r < n and 0 < s < n):
        return False
    z = toy_hash(message, n)
    w = mod_inverse(s, n)
    u1, u2 = (z*w) % n, (r*w) % n
    X = point_add(scalar_mult(u1, G, a, p), scalar_mult(u2, Q, a, p), a, p)
    return X is not None and X[0] % n == r

def point_add(P, Q, a, p):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P; x2, y2 = Q
    if x1 == x2 and (y1+y2) % p == 0: return None
    if P == Q:
        if y1 % p == 0: return None
        slope = ((3*x1*x1+a) * mod_inverse(2*y1, p)) % p
    else:
        slope = ((y2-y1) * mod_inverse((x2-x1) % p, p)) % p
    x3 = (slope*slope-x1-x2) % p
    y3 = (slope*(x1-x3)-y1) % p
    return x3, y3

def scalar_mult(k, P, a, p):
    result, addend = None, P
    while k:
        if k & 1: result = point_add(result, addend, a, p)
        addend = point_add(addend, addend, a, p)
        k >>= 1
    return result

def demo():
    print("\\nRSA signature demonstration (tiny values)")
    # RSA p=11, q=13, e=7 -> n=143, phi=120, d=103
    pub, priv = (143, 7), (143, 103)
    m = 42
    sig = rsa_sign(m, priv)
    print("message integer:", m, "signature:", sig, "valid:", rsa_verify(m, sig, pub))
    print("tampered message valid:", rsa_verify(m+1, sig, pub))

    print("\\nElGamal signature demonstration")
    p, g, x, k = 23, 5, 6, 7
    y, sig = elgamal_sign("HELLO", p, g, x, k)
    print("public y:", y, "signature:", sig)
    print("valid:", elgamal_verify("HELLO", p, g, y, sig))
    print("tampered:", elgamal_verify("HELLO!", p, g, y, sig))

    print("\\nSchnorr demonstration (p=23, q=11, g=2 has order 11)")
    p, q, g, x, k = 23, 11, 2, 3, 4
    y, sig = schnorr_sign("HELLO", p, q, g, x, k)
    print("public y:", y, "signature:", sig)
    print("valid:", schnorr_verify("HELLO", p, q, g, y, sig))
    print("tampered:", schnorr_verify("HELLO!", p, q, g, y, sig))

    print("\\nDSA demonstration")
    # p=23, q=11, g=2, g^q mod p = 1
    p, q, g, x, k = 23, 11, 2, 3, 5
    y, sig = dsa_sign("HELLO", p, q, g, x, k)
    print("public y:", y, "signature:", sig)
    print("valid:", dsa_verify("HELLO", p, q, g, y, sig))
    print("tampered:", dsa_verify("HELLO!", p, q, g, y, sig))

    print("\\nECDSA demonstration")
    # Curve y^2=x^3+2x+2 mod 17; G=(5,1), order n=19
    p, a, G, n, d, k = 17, 2, (5,1), 19, 7, 3
    Q, sig = ecdsa_sign("HELLO", p, a, G, n, d, k)
    print("public Q:", Q, "signature:", sig)
    print("valid:", ecdsa_verify("HELLO", p, a, G, n, Q, sig))
    print("tampered:", ecdsa_verify("WORLD", p, a, G, n, Q, sig))

def main():
    print("DIGITAL SIGNATURES – educational demos")
    print("1 RSA signature  2 ElGamal signature  3 Schnorr  4 DSA  5 ECDSA  6 Run all demos")
    ch = input("Choice: ").strip()
    if ch == "6":
        demo()
    elif ch == "1":
        m, n, d, e = [int(input(x)) for x in ("Message integer: ", "n: ", "private d: ", "public e: ")]
        s = rsa_sign(m, (n,d))
        print("Signature:", s, "Verification:", rsa_verify(m,s,(n,e)))
    else:
        print("For the other algorithms, run option 6 to see complete parameterised examples.")
        print("Then change the message, keys and nonce in demo() and rerun.")

if __name__ == "__main__":
    main()
