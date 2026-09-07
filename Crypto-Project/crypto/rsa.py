#RSA
import random
import sympy

m = int("Secret".encode("utf-8").hex(),16)
print(m)

# Generate large prime (128 bits) p and q
# sympy.randprime(a, b) returns a random prime in the range [a, b)
# 2^127 to 2^128 gives us 128-bit primes
p = sympy.randprime(2**127, 2**128)
q = sympy.randprime(2**127, 2**128)

# Make sure p and q are distinct
while q == p:
    q = sympy.randprime(2**127, 2**128)

print(f"p = {p}")
print(f"q = {q}")
     
# Calculate n = pq
n = p * q
print(f"n = {n}")
     

# Calculate phi(n) = (p-1)(q-1)
phi_n = (p - 1) * (q - 1)
print(f"phi(n) = {phi_n}")


# Perform encryption and generate ciphertext [c = m^e (mod n)]
# and private key [d*e ≡ 1 (mod phi(n))]
e = 11

# Verify e is coprime to phi(n): gcd(e, phi(n)) must be 1
assert sympy.gcd(e, phi_n) == 1, "e is not coprime to phi(n)! Choose a different e."
print(f"e = {e}  (coprime to phi(n): True)")

# Compute private key d using the modular inverse (recursive Extended Euclidean)
def extended_gcd(a, b):
    """Recursive Extended Euclidean Algorithm.
    Returns (gcd, x, y) such that a*x + b*y = gcd."""
    if b == 0:
        return a, 1, 0
    gcd, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return gcd, x, y

def mod_inverse(e, phi):
    """Compute d such that d*e ≡ 1 (mod phi) using the Extended Euclidean Algorithm."""
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist (e and phi are not coprime).")
    return x % phi  # Ensure d is positive

d = mod_inverse(e, phi_n)
print(f"d = {d}")

# Encrypt: c = m^e (mod n)
# pow(m, e, n) is efficient for large numbers (fast modular exponentiation)
c = pow(m, e, n)
print(f"\nOriginal message (m) : {m}")
print(f"Ciphertext      (c) : {c}")

# Perform decryption: m = c^d (mod n)
# pow(c, d, n) uses fast modular exponentiation
m_decrypted = pow(c, d, n)
print(f"Decrypted message (m): {m_decrypted}")