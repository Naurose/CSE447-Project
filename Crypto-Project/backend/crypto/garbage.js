'use strict';

/**
 * ============================================================================
 * RSA Module — From-scratch implementation using JavaScript BigInt
 * ============================================================================
 *
 * Ported from: crypto/rsa.py (Python reference implementation)
 * Adapted for: Node.js backend (CommonJS, BigInt arithmetic)
 *
 * This module implements RSA public-key cryptography entirely from scratch,
 * using only Node.js's built-in `crypto` module for secure random byte
 * generation. All mathematical operations (primality testing, modular
 * arithmetic, key generation) are implemented manually.
 *
 * Exports:
 *   - generateKeyPair(bits)              → { publicKey, privateKey }
 *   - encrypt(message, publicKey)        → BigInt ciphertext
 *   - decrypt(ciphertext, privateKey)    → BigInt | string | Buffer
 *   - stringToBigInt / bigIntToString   → text ↔ BigInt helpers
 *   - modPow / modInverse / extendedGcd → math primitives
 *
 * Security Note:
 *   Default key size is 2048 bits. For faster testing, 512 or 1024 may be
 *   used, but these are NOT secure for production.
 *
 * Dependency:
 *   - Node.js built-in `crypto` (for randomBytes only — all math is manual)
 */

const crypto = require('crypto');


// ─────────────────────────────────────────────────────────────────────────────
// Section 1: BigInt Utility Helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Absolute value for BigInt.
 * (Math.abs does not support BigInt natively.)
 *
 * @param {BigInt} x
 * @returns {BigInt}
 */
function bigIntAbs(x) {
    return x < 0n ? -x : x;
}

/**
 * Convert a Buffer (byte array) to a BigInt.
 * Interprets bytes as a big-endian unsigned integer.
 *
 * Example: Buffer.from([0x01, 0xFF]) → 511n
 *
 * @param {Buffer} buf
 * @returns {BigInt}
 */
function bufferToBigInt(buf) {
    if (buf.length === 0) return 0n;
    return BigInt('0x' + buf.toString('hex'));
}

/**
 * Convert a BigInt to a Buffer (byte array).
 * Output is big-endian with minimal byte length.
 *
 * Example: 511n → Buffer.from([0x01, 0xFF])
 *
 * @param {BigInt} n — must be >= 0
 * @returns {Buffer}
 */
function bigIntToBuffer(n) {
    if (n === 0n) return Buffer.from([0]);

    let hex = n.toString(16);
    // Ensure even-length hex string for valid Buffer conversion
    if (hex.length % 2 !== 0) hex = '0' + hex;
    return Buffer.from(hex, 'hex');
}

/**
 * Convert a UTF-8 string to a BigInt.
 * Mirrors the Python approach: string → bytes → hex → int
 *
 * Python equivalent:
 *   m = int("Secret".encode("utf-8").hex(), 16)
 *
 * Example: "Secret" → 0x536563726574 → 92312836595060n
 *
 * @param {string} str
 * @returns {BigInt}
 */
function stringToBigInt(str) {
    const buf = Buffer.from(str, 'utf-8');
    return bufferToBigInt(buf);
}

/**
 * Convert a BigInt back to a UTF-8 string.
 * Reverses stringToBigInt: int → hex → bytes → string
 *
 * @param {BigInt} n
 * @returns {string}
 */
function bigIntToString(n) {
    const buf = bigIntToBuffer(n);
    return buf.toString('utf-8');
}


// ─────────────────────────────────────────────────────────────────────────────
// Section 2: Secure Random BigInt Generation
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Generate a cryptographically secure random BigInt of exactly `bits` bits.
 *
 * Uses Node's crypto.randomBytes for entropy, then masks to the exact bit
 * count and sets the MSB to guarantee the result has the requested length.
 *
 * @param {number} bits — desired bit length (e.g., 1024)
 * @returns {BigInt}  — random value in [2^(bits-1), 2^bits)
 */
function randomBigInt(bits) {
    // Number of bytes needed to hold `bits` bits
    const byteCount = Math.ceil(bits / 8);
    const buf = crypto.randomBytes(byteCount);

    let n = bufferToBigInt(buf);

    // Mask off extra bits beyond `bits` (byteCount * 8 may exceed `bits`)
    const extraBits = BigInt(byteCount * 8 - bits);
    n = n >> extraBits;

    // Set the MSB to ensure exactly `bits` bit-length
    n = n | (1n << BigInt(bits - 1));

    return n;
}

/**
 * Generate a random BigInt uniformly distributed in [min, max).
 * Uses rejection sampling for uniform distribution.
 *
 * @param {BigInt} min — inclusive lower bound
 * @param {BigInt} max — exclusive upper bound
 * @returns {BigInt}
 */
function randomBigIntRange(min, max) {
    const range = max - min;
    // Determine how many bits are needed to represent `range`
    const bits = range.toString(2).length;

    // Rejection sampling: keep generating until value fits in [0, range)
    let result;
    do {
        result = randomBigInt(bits);
        // Clear MSB that randomBigInt forcefully sets, since we want [0, range)
        result = result & ((1n << BigInt(bits)) - 1n);
    } while (result >= range);

    return result + min;
}


// ─────────────────────────────────────────────────────────────────────────────
// Section 3: Modular Arithmetic
// (ported from Python's extended_gcd and mod_inverse in rsa.py)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Modular exponentiation: (base ^ exp) mod mod.
 *
 * Uses the square-and-multiply algorithm (binary exponentiation).
 * This replaces Python's built-in pow(base, exp, mod) which JavaScript
 * BigInt does not have natively.
 *
 * Time complexity: O(log(exp)) multiplications modulo `mod`.
 *
 * @param {BigInt} base
 * @param {BigInt} exp  — must be >= 0
 * @param {BigInt} mod  — must be > 0
 * @returns {BigInt}    — result in [0, mod)
 */
function modPow(base, exp, mod) {
    // Any number mod 1 is 0
    if (mod === 1n) return 0n;

    let result = 1n;
    // Normalize base into [0, mod) — handles negative bases correctly
    base = ((base % mod) + mod) % mod;

    while (exp > 0n) {
        // If the current least-significant bit of exp is 1, multiply
        if (exp & 1n) {
            result = (result * base) % mod;
        }
        // Square the base for the next bit position
        base = (base * base) % mod;
        // Shift exp right by one bit
        exp = exp >> 1n;
    }

    return result;
}

/**
 * Recursive Extended Euclidean Algorithm.
 *
 * Returns { gcd, x, y } such that: a*x + b*y = gcd(a, b).
 *
 * ──── Direct port from Python (rsa.py lines 40-48) ────
 *   def extended_gcd(a, b):
 *       if b == 0:
 *           return a, 1, 0
 *       gcd, x1, y1 = extended_gcd(b, a % b)
 *       x = y1
 *       y = x1 - (a // b) * y1
 *       return gcd, x, y
 * ───────────────────────────────────────────────────────
 *
 * @param {BigInt} a
 * @param {BigInt} b
 * @returns {{ gcd: BigInt, x: BigInt, y: BigInt }}
 */
function extendedGcd(a, b) {
    // Base case: gcd(a, 0) = a, and a*1 + 0*0 = a
    if (b === 0n) {
        return { gcd: a, x: 1n, y: 0n };
    }

    // Recurse: same structure as the Python reference
    const result = extendedGcd(b, a % b);
    const x = result.y;
    const y = result.x - (a / b) * result.y;

    return { gcd: result.gcd, x, y };
}

/**
 * Compute the modular multiplicative inverse of e modulo phi.
 *
 * Finds d such that: d * e ≡ 1 (mod phi).
 *
 * ──── Direct port from Python (rsa.py lines 50-55) ────
 *   def mod_inverse(e, phi):
 *       gcd, x, _ = extended_gcd(e, phi)
 *       if gcd != 1:
 *           raise ValueError(...)
 *       return x % phi
 * ───────────────────────────────────────────────────────
 *
 * @param {BigInt} e   — the value to invert
 * @param {BigInt} phi — the modulus
 * @returns {BigInt}   — d in [0, phi) such that d*e ≡ 1 (mod phi)
 * @throws {Error}     — if e and phi are not coprime
 */
function modInverse(e, phi) {
    const { gcd: g, x } = extendedGcd(e, phi);

    if (g !== 1n) {
        throw new Error(
            'Modular inverse does not exist (e and phi are not coprime).'
        );
    }

    // Ensure result is positive (x may be negative from the algorithm)
    return ((x % phi) + phi) % phi;
}

/**
 * Compute GCD of two BigInts using the standard Euclidean algorithm.
 *
 * Replaces Python's sympy.gcd(e, phi_n).
 *
 * @param {BigInt} a
 * @param {BigInt} b
 * @returns {BigInt}
 */
function gcd(a, b) {
    a = bigIntAbs(a);
    b = bigIntAbs(b);
    while (b > 0n) {
        [a, b] = [b, a % b];
    }
    return a;
}


// ─────────────────────────────────────────────────────────────────────────────
// Section 4: Primality Testing (Miller-Rabin)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Miller-Rabin probabilistic primality test.
 *
 * Tests whether `n` is probably prime using `k` rounds of random witnesses.
 * False-positive probability ≤ 4^(-k). With k=20, that is < 10^(-12).
 *
 * Replaces Python's sympy.randprime / sympy.isprime for our from-scratch
 * implementation.
 *
 * Algorithm outline:
 *   1. Write n-1 as 2^r · d  (factor out all powers of 2)
 *   2. For each random witness a in [2, n-2]:
 *      a) Compute x = a^d mod n
 *      b) If x ∈ {1, n-1}, this witness passes → next witness
 *      c) Square x up to (r-1) times:
 *         - if x becomes n-1, this witness passes → next witness
 *      d) If no squaring yielded n-1, n is COMPOSITE → return false
 *   3. All witnesses passed → n is PROBABLY PRIME → return true
 *
 * @param {BigInt} n — number to test (must be > 1)
 * @param {number} k — number of witness rounds (default: 20)
 * @returns {boolean} — true if probably prime, false if definitely composite
 */
function millerRabin(n, k = 20) {
    // Handle trivial cases
    if (n < 2n) return false;
    if (n === 2n || n === 3n) return true;
    if (n % 2n === 0n) return false;       // Even numbers > 2 are composite

    // Step 1: Decompose n-1 = 2^r · d, where d is odd
    let r = 0n;
    let d = n - 1n;
    while (d % 2n === 0n) {
        d = d / 2n;
        r = r + 1n;
    }
    // Invariant: n - 1 === (2n ** r) * d, and d is odd

    // Step 2: Run k rounds of witness testing
    for (let i = 0; i < k; i++) {
        // Pick a random witness a ∈ [2, n-2]
        const a = randomBigIntRange(2n, n - 1n);

        // Compute x = a^d mod n
        let x = modPow(a, d, n);

        // If x ∈ {1, n-1}, this witness is inconclusive → skip
        if (x === 1n || x === n - 1n) continue;

        // Square x up to (r-1) times looking for n-1
        let witnessPass = false;
        for (let j = 1n; j < r; j++) {
            x = modPow(x, 2n, n);
            if (x === n - 1n) {
                witnessPass = true;
                break;
            }
        }

        // If no squaring yielded n-1, n is definitely composite
        if (!witnessPass) return false;
    }

    // All k witnesses passed — n is probably prime
    return true;
}

/**
 * Generate a random prime number of exactly `bits` bit-length.
 *
 * Replaces Python's:
 *   p = sympy.randprime(2**127, 2**128)
 *
 * Strategy: generate random odd numbers and test with Miller-Rabin until
 * a prime is found. By the Prime Number Theorem, on average we test
 * ~ln(2^bits) ≈ bits × 0.693 candidates.
 *
 * @param {number} bits — desired bit length (e.g., 1024 for RSA-2048)
 * @returns {BigInt}    — a prime with exactly `bits` bits
 */
function generatePrime(bits) {
    // Small primes for quick trial-division filter (avoids slow Miller-Rabin
    // on obvious composites)
    const SMALL_PRIMES = [
        3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n,
        37n, 41n, 43n, 47n, 53n, 59n, 61n, 67n, 71n, 73n,
        79n, 83n, 89n, 97n, 101n, 103n, 107n, 109n, 113n
    ];

    while (true) {
        // Generate random odd number with exactly `bits` bits
        let candidate = randomBigInt(bits);
        candidate = candidate | 1n;            // Force odd (primes > 2 are odd)

        // Trial division against small primes (quick rejection)
        let divisible = false;
        for (const sp of SMALL_PRIMES) {
            if (candidate === sp) break;       // The candidate IS the small prime
            if (candidate % sp === 0n) {
                divisible = true;
                break;
            }
        }
        if (divisible) continue;

        // Full Miller-Rabin test (20 rounds ≈ 10^-12 false-positive rate)
        if (millerRabin(candidate, 20)) {
            return candidate;
        }
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// Section 5: RSA Key Generation
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Generate an RSA key pair.
 *
 * ──── Ported from Python (rsa.py) key generation logic ────
 *   p = sympy.randprime(2**127, 2**128)
 *   q = sympy.randprime(2**127, 2**128)
 *   while q == p: ...
 *   n = p * q
 *   phi_n = (p - 1) * (q - 1)
 *   e = 11
 *   assert sympy.gcd(e, phi_n) == 1
 *   d = mod_inverse(e, phi_n)
 * ──────────────────────────────────────────────────────────
 *
 * Differences from the Python original:
 *   - Python uses e=11 and 128-bit primes (educational).
 *   - This uses e=65537 (Fermat prime F4, industry standard) and defaults
 *     to 2048-bit keys for real security.
 *
 * @param {number} [bits=2048] — total modulus bit-length; each prime is bits/2
 * @returns {{
 *   publicKey:  { n: BigInt, e: BigInt },
 *   privateKey: { n: BigInt, d: BigInt, p: BigInt, q: BigInt }
 * }}
 */
function generateKeyPair(bits = 2048) {
    const halfBits = Math.floor(bits / 2);

    // Step 1: Generate two large distinct primes p and q
    //   Python: p = sympy.randprime(2**127, 2**128)
    const p = generatePrime(halfBits);
    let q = generatePrime(halfBits);

    // Ensure p ≠ q (mirrors Python: while q == p)
    while (q === p) {
        q = generatePrime(halfBits);
    }

    // Step 2: Compute modulus n = p × q
    //   Python: n = p * q
    const n = p * q;

    // Step 3: Compute Euler's totient φ(n) = (p-1)(q-1)
    //   Python: phi_n = (p - 1) * (q - 1)
    const phiN = (p - 1n) * (q - 1n);

    // Step 4: Choose public exponent e
    //   Python uses e=11 (educational); we use 65537 (industry standard)
    //   65537 = 2^16 + 1, a Fermat prime, balances security and speed
    const e = 65537n;

    // Verify gcd(e, φ(n)) = 1
    //   Python: assert sympy.gcd(e, phi_n) == 1
    if (gcd(e, phiN) !== 1n) {
        // Astronomically unlikely with e=65537, but handle gracefully
        return generateKeyPair(bits);
    }

    // Step 5: Compute private exponent d = e⁻¹ mod φ(n)
    //   Python: d = mod_inverse(e, phi_n)
    const d = modInverse(e, phiN);

    return {
        publicKey:  { n, e },
        privateKey: { n, d, p, q }
    };
}


// ─────────────────────────────────────────────────────────────────────────────
// Section 6: RSA Encryption & Decryption
// ─────────────────────────────────────────────────────────────────────────────

/**
 * RSA Encryption: c = m^e (mod n)
 *
 * ──── Direct port from Python (rsa.py line 62) ────
 *   c = pow(m, e, n)
 * ──────────────────────────────────────────────────
 *
 * The plaintext is converted to a BigInt (if not already one), then
 * encrypted using modular exponentiation with the public key.
 *
 * @param {Buffer|string|BigInt} message — the plaintext to encrypt
 * @param {{ n: BigInt, e: BigInt }}     publicKey — recipient's public key
 * @returns {BigInt}                     — ciphertext as a BigInt
 * @throws {Error} — if the message numeric value is ≥ n (too large for key)
 */
function encrypt(message, publicKey) {
    const { n, e } = publicKey;

    // ── Convert message to BigInt ──
    let m;
    if (typeof message === 'bigint') {
        m = message;
    } else if (typeof message === 'string') {
        // Mirrors Python: m = int("Secret".encode("utf-8").hex(), 16)
        m = stringToBigInt(message);
    } else if (Buffer.isBuffer(message)) {
        m = bufferToBigInt(message);
    } else {
        throw new Error('Message must be a string, Buffer, or BigInt.');
    }

    // ── Validate message size ──
    // RSA requires 0 ≤ m < n; otherwise decryption will fail
    if (m < 0n) {
        throw new Error('Message cannot be negative.');
    }
    if (m >= n) {
        throw new Error(
            `Message is too large for this key. ` +
            `Message has ${m.toString(16).length * 4} bits but modulus n ` +
            `has ${n.toString(16).length * 4} bits. ` +
            'Use a larger key size or chunk the message.'
        );
    }

    // ── Encrypt: c = m^e mod n ──
    // Python: c = pow(m, e, n)
    const c = modPow(m, e, n);

    return c;
}

/**
 * RSA Decryption: m = c^d (mod n)
 *
 * ──── Direct port from Python (rsa.py line 68) ────
 *   m_decrypted = pow(c, d, n)
 * ──────────────────────────────────────────────────
 *
 * @param {BigInt} ciphertext — the ciphertext BigInt (from encrypt)
 * @param {{ n: BigInt, d: BigInt }}  privateKey — recipient's private key
 * @param {string} [outputFormat='bigint'] — 'bigint' | 'string' | 'buffer'
 * @returns {BigInt|string|Buffer} — the recovered plaintext
 */
function decrypt(ciphertext, privateKey, outputFormat = 'bigint') {
    const { n, d } = privateKey;

    // Decrypt: m = c^d mod n
    // Python: m_decrypted = pow(c, d, n)
    const m = modPow(ciphertext, d, n);

    // Return in the requested format
    switch (outputFormat) {
        case 'string':
            return bigIntToString(m);
        case 'buffer':
            return bigIntToBuffer(m);
        case 'bigint':
        default:
            return m;
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// Section 7: Module Exports
// ─────────────────────────────────────────────────────────────────────────────

module.exports = {
    // ── Core RSA operations ──
    generateKeyPair,
    encrypt,
    decrypt,

    // ── Math primitives (exposed for testing and reuse by other modules) ──
    modPow,
    modInverse,
    extendedGcd,
    gcd,

    // ── Primality ──
    millerRabin,
    generatePrime,

    // ── Conversion helpers ──
    stringToBigInt,
    bigIntToString,
    bufferToBigInt,
    bigIntToBuffer,
    randomBigInt,
    randomBigIntRange
};
