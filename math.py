# Shared number-theory helpers. This file is importable by the practical scripts.

def gcd(a, b):
    a, b = abs(a), abs(b)
    while b:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = extended_gcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def mod_inverse(a, m):
    if m <= 1:
        raise ValueError("Modulus must be greater than 1")
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError("Inverse does not exist: gcd(a,m) is not 1")
    return x % m

def mod_exp(base, exponent, modulus, trace=False):
    if exponent < 0 or modulus <= 0:
        raise ValueError("Exponent must be non-negative and modulus positive")
    result = 1
    base %= modulus
    steps = []
    e = exponent
    while e:
        if e % 2:
            result = (result * base) % modulus
        steps.append((e, base, result))
        base = (base * base) % modulus
        e //= 2
    return (result, steps) if trace else result

def is_prime_trial(n):
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    d = 3
    while d * d <= n:
        if n % d == 0:
            return False
        d += 2
    return True

def jacobi(a, n):
    if n <= 0 or n % 2 == 0:
        raise ValueError("Jacobi denominator must be positive and odd")
    a %= n
    result = 1
    while a:
        while a % 2 == 0:
            a //= 2
            if n % 8 in (3, 5):
                result = -result
        a, n = n, a
        if a % 4 == 3 and n % 4 == 3:
            result = -result
        a %= n
    return result if n == 1 else 0
