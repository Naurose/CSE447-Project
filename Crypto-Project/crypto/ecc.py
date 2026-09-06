#ECC
'''
Consider the elliptic curve E: 𝑦2 = 𝑥3 − 2𝑥 + 2 (mod 23) and P = (4, 9)
1. Calculate the value of 2P and 3P.
2. Suppose this E and P = (4, 9) are used in an ECC Diffie-Hellman key exchange, 
where Alice chooses the secret value a = 3 and Bob chooses the secret value b = 6. 
What is the shared key among Alice and Bob?
'''

# Elliptic curve: y^2 = x^3 - 2x + 2 (mod 23)
p = 23
a = -2
b = 2
P = (4, 9)

def inverse_mod(k, p):
    return pow(k, -1, p)

#implement ECC point addition (also handle doubling)
def point_add(P, Q, a, p):
    #return Q if P is None, return P if Q is None
    #if P and Q are vertical reflections, return None
    #calculate slope m differently for doubling vs addition
    #compute x_r, y_r using ECC formulas, return as tuple

    if P is None:
        return Q

    if Q is None:
        return P

    x1, y1 = P
    x2, y2 = Q

    if x1 == x2 and (y1 + y2) % p == 0:
        return None

    if P == Q:
        m = (3 * x1**2 + a) * inverse_mod(2 * y1, p) % p
    else:
        m = (y2 - y1) * inverse_mod(x2 - x1, p) % p

    x_r = (m**2 - x1 - x2) % p
    y_r = (m * (x1 - x_r) - y1) % p

    return (x_r, y_r)


# Double-and-add scalar multiplication
def scalar_mult(k, P, a, p):

    #start with R as None (point at infinity)
    #loop while k > 0, check k's binary bits
    #if bit is 1, add Q to R
    #always double Q each loop
    #shift k right each loop

    R = None
    Q = P

    while k > 0:
        if k & 1:
            R = point_add(R, Q, a, p)
        Q = point_add(Q, Q, a, p)
        k >>= 1

    return R


# 1) 2P and 3P
P2 = scalar_mult(2, P, a, p)
P3 = scalar_mult(3, P, a, p)
print("2P =", P2)
print("3P =", P3)


# 2) ECC Diffie-Hellman Key
a_secret = 3
b_secret = 6

A_pub = scalar_mult(a_secret, P, a, p)
B_pub = scalar_mult(b_secret, P, a, p)

shared_A = scalar_mult(a_secret, B_pub, a, p)
shared_B = scalar_mult(b_secret, A_pub, a, p)

print("Alice's public key:", A_pub)
print("Bob's public key:", B_pub)
print("Shared key (Alice):", shared_A)
print("Shared key (Bob):", shared_B)
print("Keys match:", shared_A == shared_B)