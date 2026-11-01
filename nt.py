# PRACTICAL 1 – Number Theory
# Run: python3 practical1_number_theory/number_theory.py

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
from math_utils import gcd, extended_gcd, mod_inverse, mod_exp, is_prime_trial, jacobi

def fermat_test(n, bases):
    if n < 2:
        return False
    if n in (2, 3):
        return True
    for a in bases:
        a %= n
        if a == 0:
            continue
        if gcd(a, n) != 1:
            return False
        if mod_exp(a, n - 1, n) != 1:
            return False
    return True  # probable prime, not a proof

def euler_simple_test(n, bases):
    # Matches the simple criterion described in the uploaded lab report:
    # a^((n-1)/2) mod n should be 1 or n-1 for an odd prime.
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    for a in bases:
        a %= n
        if a == 0 or gcd(a, n) != 1:
            return False
        value = mod_exp(a, (n - 1) // 2, n)
        if value not in (1, n - 1):
            return False
    return True

def euler_jacobi_test(n, bases):
    # More precise Euler-Jacobi probable-prime test.
    if n < 3 or n % 2 == 0:
        return n == 2
    for a in bases:
        a %= n
        if a == 0 or gcd(a, n) != 1:
            return False
        if mod_exp(a, (n - 1) // 2, n) != jacobi(a, n) % n:
            return False
    return True

def miller_rabin(n, bases, verbose=False):
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    if verbose:
        print("n - 1 =", 2, "^", s, "*", d)
    for a in bases:
        a %= n
        if a in (0, 1):
            continue
        if gcd(a, n) != 1:
            return False
        x = mod_exp(a, d, n)
        if verbose:
            print("Base", a, "initial x =", x)
        if x in (1, n - 1):
            continue
        passed = False
        for r in range(s - 1):
            x = (x * x) % n
            if verbose:
                print("  square", r + 1, "=>", x)
            if x == n - 1:
                passed = True
                break
        if not passed:
            return False
    return True

def chinese_remainder(congruences):
    # congruences is [(remainder, modulus), ...], pairwise coprime moduli.
    total_modulus = 1
    for _, m in congruences:
        if m <= 1:
            raise ValueError("Each modulus must be > 1")
        total_modulus *= m
    result = 0
    for a, m in congruences:
        if gcd(m, total_modulus // m) != 1:
            raise ValueError("This implementation requires pairwise-coprime moduli")
        partial = total_modulus // m
        result += a * partial * mod_inverse(partial, m)
    return result % total_modulus, total_modulus

def main():
    while True:
        print("\\nPRACTICAL 1 – NUMBER THEORY")
        print("1 GCD  2 Extended Euclid  3 Modular inverse  4 Modular exponentiation")
        print("5 Fermat  6 Euler (simple)  7 Euler-Jacobi  8 Miller-Rabin  9 CRT  0 Exit")
        choice = input("Choice: ").strip()
        try:
            if choice == "0":
                break
            elif choice == "1":
                a, b = int(input("a: ")), int(input("b: "))
                print("gcd =", gcd(a, b))
            elif choice == "2":
                a, b = int(input("a: ")), int(input("b: "))
                print("(g, x, y) =", extended_gcd(a, b))
            elif choice == "3":
                a, m = int(input("a: ")), int(input("modulus m: "))
                print("inverse =", mod_inverse(a, m))
            elif choice == "4":
                a, e, m = int(input("base a: ")), int(input("exponent: ")), int(input("modulus: "))
                ans, steps = mod_exp(a, e, m, True)
                print("answer =", ans)
                print("Trace (current exponent, base, result):", steps)
            elif choice in ("5", "6", "7", "8"):
                n = int(input("Number n: "))
                raw = input("Bases separated by spaces (e.g. 2 3 5): ").strip()
                bases = [int(x) for x in raw.split()] or [2]
                funcs = {"5": fermat_test, "6": euler_simple_test,
                         "7": euler_jacobi_test, "8": miller_rabin}
                result = funcs[choice](n, bases, True) if choice == "8" else funcs[choice](n, bases)
                print("PROBABLY PRIME" if result else "COMPOSITE")
                print("Trial-division check for small classroom inputs:", is_prime_trial(n))
            elif choice == "9":
                count = int(input("Number of congruences: "))
                pairs = []
                for i in range(count):
                    a = int(input("Remainder a%d: " % (i + 1)))
                    m = int(input("Modulus m%d: " % (i + 1)))
                    pairs.append((a, m))
                x, mod = chinese_remainder(pairs)
                print("x =", x, "(mod", mod, ")")
            else:
                print("Invalid choice")
        except (ValueError, ZeroDivisionError) as err:
            print("Input/error:", err)

if __name__ == "__main__":
    main()
