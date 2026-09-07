'use strict';

/**
 * ============================================================================
 * HMAC Module — From-Scratch Implementation (RFC 2104 & FIPS 198-1)
 * ============================================================================
 *
 * Course: CSE447 — Cryptography and Network Security
 * Purpose:
 *   - Implement Hash-based Message Authentication Code (HMAC) entirely from scratch
 *   - Provide cryptographic message integrity and authenticity verification
 *   - Include a pure from-scratch SHA-256 hash function (FIPS 180-4)
 *   - Support constant-time verification against timing side-channel attacks
 *
 * Mathematical Foundation (RFC 2104):
 *   HMAC(K, m) = H( (K0 ⊕ opad) ∥ H( (K0 ⊕ ipad) ∥ m ) )
 *
 * Definitions:
 *   - H:       Cryptographic hash function (SHA-256)
 *   - B:       Block size of the hash function (64 bytes / 512 bits for SHA-256)
 *   - L:       Output size of the hash function (32 bytes / 256 bits for SHA-256)
 *   - K:       Secret authentication key
 *   - K0:      Preprocessed key of length B (hashed if len > B, zero-padded if len < B)
 *   - ipad:    Inner padding constant (0x36 repeated B times)
 *   - opad:    Outer padding constant (0x5C repeated B times)
 *   - ⊕:       Bitwise XOR operation
 *   - ∥:       Byte concatenation
 *
 * ============================================================================
 */

const crypto = require('crypto');

// =====================================================
// Section 1: Constants & Protocol Parameters
// =====================================================

// SHA-256 block size in bytes (512 bits = 64 bytes)
const BLOCK_SIZE = 64;

// SHA-256 output digest size in bytes (256 bits = 32 bytes)
const OUTPUT_SIZE = 32;

// Inner pad byte: 0x36 (00110110 in binary)
const IPAD_BYTE = 0x36;

// Outer pad byte: 0x5C (01011100 in binary)
const OPAD_BYTE = 0x5C;

// SHA-256 round constants: first 32 bits of the fractional parts
// of the cube roots of the first 64 prime numbers (2..311)
const SHA256_K = Object.freeze([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);


// =====================================================
// Section 2: Bitwise Operation Helpers
// =====================================================

/**
 * 32-bit Right Rotation (circular shift).
 * ROTR^n(x) = (x >>> n) | (x << (32 - n))
 *
 * In JavaScript, bitwise operations evaluate to 32-bit signed integers.
 * The `>>> 0` unsigned right shift forces the result to be treated
 * as an unsigned 32-bit integer.
 *
 * @param {number} n - Number of bits to rotate right
 * @param {number} x - 32-bit integer
 * @returns {number} Unsigned 32-bit rotated integer
 */
function rotr(n, x) {
    return ((x >>> n) | (x << (32 - n))) >>> 0;
}

/**
 * Normalize any input (string or Buffer) to a Buffer.
 *
 * @param {Buffer|string} input - Input data
 * @param {string} [encoding='utf8'] - String encoding if input is a string
 * @returns {Buffer}
 */
function toBuffer(input, encoding = 'utf8') {
    if (Buffer.isBuffer(input)) {
        return input;
    }
    if (typeof input === 'string') {
        return Buffer.from(input, encoding);
    }
    throw new TypeError('Input must be a Buffer or a string.');
}


// =====================================================
// Section 3: From-Scratch SHA-256 Hash Implementation
// (FIPS PUB 180-4 Specification)
// =====================================================

/**
 * Pure from-scratch SHA-256 cryptographic hash function.
 * Computes the 256-bit message digest of the input data.
 *
 * Algorithm Steps:
 *   1. Padding: Append bit '1' (0x80), then k zero bytes, then 64-bit message length.
 *   2. Chunking: Process the padded message in 512-bit (64-byte) blocks.
 *   3. Schedule: Expand 16 words into a 64-word message schedule array (W).
 *   4. Compression: 64 rounds of non-linear mixing with working variables (a..h).
 *   5. State Update: Add compressed values back to hash state accumulators (H0..H7).
 *
 * @param {Buffer|string} data - Plaintext message or byte buffer
 * @returns {Buffer} 32-byte (256-bit) digest
 */
function sha256(data) {
    const buf = toBuffer(data);
    const bitLen = buf.length * 8;

    // Step 1: Pre-processing (Padding)
    // The message must be padded such that:
    // (len + 1 + k) ≡ 56 (mod 64), leaving 8 bytes for 64-bit length
    let k = (56 - ((buf.length + 1) % 64)) % 64;
    if (k < 0) k += 64;

    const padded = Buffer.alloc(buf.length + 1 + k + 8);
    buf.copy(padded);

    // Append single '1' bit (as byte 0x80 = 10000000)
    padded[buf.length] = 0x80;

    // Append 64-bit big-endian representation of original bit length
    padded.writeBigUInt64BE(BigInt(bitLen), padded.length - 8);

    // Step 2: Initialize hash state values (H0..H7)
    // First 32 bits of the fractional parts of the square roots of the first 8 primes (2..19)
    let H0 = 0x6a09e667;
    let H1 = 0xbb67ae85;
    let H2 = 0x3c6ef372;
    let H3 = 0xa54ff53a;
    let H4 = 0x510e527f;
    let H5 = 0x9b05688c;
    let H6 = 0x1f83d9ab;
    let H7 = 0x5be0cd19;

    // Message schedule buffer for 64 32-bit words
    const W = new Uint32Array(64);

    // Step 3: Process the message in successive 512-bit (64-byte) chunks
    for (let offset = 0; offset < padded.length; offset += 64) {
        // a. Copy 16 32-bit big-endian words into W[0..15]
        for (let t = 0; t < 16; t++) {
            W[t] = padded.readUInt32BE(offset + t * 4);
        }

        // b. Extend W[16..63] using the message schedule expansion formulas
        for (let t = 16; t < 64; t++) {
            // σ0(x) = ROTR^7(x) ⊕ ROTR^18(x) ⊕ (x >>> 3)
            const s0 = rotr(7, W[t - 15]) ^ rotr(18, W[t - 15]) ^ (W[t - 15] >>> 3);

            // σ1(x) = ROTR^17(x) ⊕ ROTR^19(x) ⊕ (x >>> 10)
            const s1 = rotr(17, W[t - 2]) ^ rotr(19, W[t - 2]) ^ (W[t - 2] >>> 10);

            // W[t] = W[t-16] + σ0 + W[t-7] + σ1 (mod 2^32)
            W[t] = (((s1 + W[t - 7]) >>> 0) + ((s0 + W[t - 16]) >>> 0)) >>> 0;
        }

        // c. Initialize working variables with current hash values
        let a = H0;
        let b = H1;
        let c = H2;
        let d = H3;
        let e = H4;
        let f = H5;
        let g = H6;
        let h = H7;

        // d. Compression loop: 64 rounds of non-linear mixing
        for (let t = 0; t < 64; t++) {
            // Σ1(e) = ROTR^6(e) ⊕ ROTR^11(e) ⊕ ROTR^25(e)
            const S1 = rotr(6, e) ^ rotr(11, e) ^ rotr(25, e);

            // Ch(e, f, g) = (e AND f) ⊕ (NOT e AND g)
            const ch = (e & f) ^ ((~e) & g);

            // Temp1 = h + Σ1(e) + Ch(e, f, g) + K[t] + W[t]
            const temp1 = (h + S1 + ch + SHA256_K[t] + W[t]) >>> 0;

            // Σ0(a) = ROTR^2(a) ⊕ ROTR^13(a) ⊕ ROTR^22(a)
            const S0 = rotr(2, a) ^ rotr(13, a) ^ rotr(22, a);

            // Maj(a, b, c) = (a AND b) ⊕ (a AND c) ⊕ (b AND c)
            const maj = (a & b) ^ (a & c) ^ (b & c);

            // Temp2 = Σ0(a) + Maj(a, b, c)
            const temp2 = (S0 + maj) >>> 0;

            h = g;
            g = f;
            f = e;
            e = (d + temp1) >>> 0;
            d = c;
            c = b;
            b = a;
            a = (temp1 + temp2) >>> 0;
        }

        // e. Add working variables back into the intermediate hash values
        H0 = (H0 + a) >>> 0;
        H1 = (H1 + b) >>> 0;
        H2 = (H2 + c) >>> 0;
        H3 = (H3 + d) >>> 0;
        H4 = (H4 + e) >>> 0;
        H5 = (H5 + f) >>> 0;
        H6 = (H6 + g) >>> 0;
        H7 = (H7 + h) >>> 0;
    }

    // Step 4: Produce final 32-byte digest
    const digest = Buffer.alloc(32);
    digest.writeUInt32BE(H0, 0);
    digest.writeUInt32BE(H1, 4);
    digest.writeUInt32BE(H2, 8);
    digest.writeUInt32BE(H3, 12);
    digest.writeUInt32BE(H4, 16);
    digest.writeUInt32BE(H5, 20);
    digest.writeUInt32BE(H6, 24);
    digest.writeUInt32BE(H7, 28);

    return digest;
}


// =====================================================
// Section 4: Key Pre-Processing (RFC 2104 Section 2)
// =====================================================

/**
 * Preprocess the secret key K to produce K0 of exact length BLOCK_SIZE (64 bytes).
 *
 * Rules:
 *   1. If length(K) > BLOCK_SIZE:
 *      K is hashed: K0 = H(K) zero-padded up to BLOCK_SIZE.
 *      (e.g., 128-byte key becomes 32-byte SHA-256 digest + 32 zero bytes)
 *   2. If length(K) < BLOCK_SIZE:
 *      K is zero-padded on the right to BLOCK_SIZE bytes.
 *   3. If length(K) == BLOCK_SIZE:
 *      K is used as-is.
 *
 * @param {Buffer} keyBuf - Raw secret key
 * @returns {Buffer} Formatted key K0 of exactly BLOCK_SIZE bytes
 */
function preprocessKey(keyBuf) {
    const K0 = Buffer.alloc(BLOCK_SIZE, 0);

    if (keyBuf.length > BLOCK_SIZE) {
        // Key is longer than 64 bytes: hash it first
        const hashedKey = sha256(keyBuf);
        hashedKey.copy(K0, 0);
    } else {
        // Key is shorter than or equal to 64 bytes: copy and zero-pad
        keyBuf.copy(K0, 0);
    }

    return K0;
}


// =====================================================
// Section 5: HMAC Computation (RFC 2104)
// =====================================================

/**
 * Computes the HMAC of a message using a shared secret key.
 *
 * Core Equation:
 *   HMAC(K, m) = H( (K0 ⊕ opad) ∥ H( (K0 ⊕ ipad) ∥ m ) )
 *
 * Detailed Procedure:
 *   Step 1: Normalize key and message to Buffers.
 *   Step 2: Pre-process key K to 64 bytes (K0).
 *   Step 3: Generate inner padded key:
 *           k_ipad = K0 ⊕ 0x36
 *   Step 4: Generate outer padded key:
 *           k_opad = K0 ⊕ 0x5C
 *   Step 5: Compute inner hash:
 *           innerHash = SHA-256( k_ipad ∥ message )
 *   Step 6: Compute outer hash:
 *           outerHash = SHA-256( k_opad ∥ innerHash )
 *   Step 7: Return final authentication tag.
 *
 * @param {Buffer|string} key - Shared secret key
 * @param {Buffer|string} message - Message to authenticate
 * @param {string} [format='hex'] - Output format: 'hex', 'base64', or 'buffer'
 * @returns {string|Buffer} The computed HMAC authentication tag
 */
function computeHmac(key, message, format = 'hex') {
    const keyBuf = toBuffer(key);
    const msgBuf = toBuffer(message);

    // Step 1: Pre-process key to exactly BLOCK_SIZE bytes
    const K0 = preprocessKey(keyBuf);

    // Step 2: Create inner and outer padded keys via bitwise XOR
    const k_ipad = Buffer.alloc(BLOCK_SIZE);
    const k_opad = Buffer.alloc(BLOCK_SIZE);

    for (let i = 0; i < BLOCK_SIZE; i++) {
        k_ipad[i] = K0[i] ^ IPAD_BYTE;
        k_opad[i] = K0[i] ^ OPAD_BYTE;
    }

    // Step 3: Compute inner hash: H(k_ipad ∥ message)
    const innerData = Buffer.concat([k_ipad, msgBuf]);
    const innerHash = sha256(innerData);

    // Step 4: Compute outer hash: H(k_opad ∥ innerHash)
    const outerData = Buffer.concat([k_opad, innerHash]);
    const outerHash = sha256(outerData);

    // Step 5: Format and return output
    if (format === 'buffer') {
        return outerHash;
    }
    if (format === 'base64') {
        return outerHash.toString('base64');
    }
    // Default: 'hex'
    return outerHash.toString('hex');
}


// =====================================================
// Section 6: Constant-Time Verification
// (Defends Against Timing Attacks)
// =====================================================

/**
 * Performs a constant-time comparison between two Buffers.
 *
 * Why constant-time?
 * A standard comparison (like `===` or `memcmp`) returns false immediately
 * at the first byte mismatch. Attackers can measure response time variations
 * (nanosecond differences) to reconstruct the expected MAC byte-by-byte.
 *
 * Constant-time comparison inspects every byte regardless of whether an
 * earlier byte differed, ensuring identical execution time.
 *
 * @param {Buffer} a - First byte buffer
 * @param {Buffer} b - Second byte buffer
 * @returns {boolean} True if both buffers contain identical contents
 */
function constantTimeCompare(a, b) {
    if (a.length !== b.length) {
        return false;
    }

    let diff = 0;
    for (let i = 0; i < a.length; i++) {
        diff |= (a[i] ^ b[i]);
    }

    return diff === 0;
}

/**
 * Verifies that a received HMAC matches the computed HMAC for a message and key.
 *
 * Steps:
 *   1. Compute expected HMAC for the message and key.
 *   2. Convert both expected and received tags to raw byte Buffers.
 *   3. Perform constant-time comparison to prevent side-channel leaks.
 *
 * @param {Buffer|string} key - Shared secret key
 * @param {Buffer|string} message - Original message
 * @param {Buffer|string} receivedMac - MAC tag to verify (hex, base64, or Buffer)
 * @returns {boolean} True if authentic and untampered; false otherwise
 */
function verifyHmac(key, message, receivedMac) {
    try {
        // Compute expected HMAC as raw Buffer
        const expectedMacBuf = computeHmac(key, message, 'buffer');

        // Normalize received MAC to Buffer
        let receivedMacBuf;
        if (Buffer.isBuffer(receivedMac)) {
            receivedMacBuf = receivedMac;
        } else if (typeof receivedMac === 'string') {
            // Detect if input is hex (32 bytes = 64 hex characters) or base64
            const isHex = /^[0-9a-fA-F]{64}$/.test(receivedMac.trim());
            receivedMacBuf = isHex
                ? Buffer.from(receivedMac.trim(), 'hex')
                : Buffer.from(receivedMac.trim(), 'base64');
        } else {
            return false;
        }

        // Verify using constant-time equality check
        return constantTimeCompare(expectedMacBuf, receivedMacBuf);
    } catch (err) {
        return false;
    }
}


// =====================================================
// Section 7: Key Generation Helper
// =====================================================

/**
 * Generates a cryptographically secure random authentication key.
 *
 * @param {number} [length=32] - Desired key length in bytes (default: 32 bytes / 256 bits)
 * @returns {string} Hex-encoded random key
 */
function generateKey(length = 32) {
    return crypto.randomBytes(length).toString('hex');
}


// =====================================================
// Section 8: Module Exports
// =====================================================

module.exports = {
    // HMAC operations
    computeHmac,
    verifyHmac,

    // Key utilities
    generateKey,
};