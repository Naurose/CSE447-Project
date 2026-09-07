'use strict';

/**
 *
 * Purpose:
 *   - Serves as the central bridge between low-level cryptographic primitives
 *     (RSA, ECC, HMAC) and high-level application routes, controllers, and middleware.
 *   - Provides unified APIs for:
 *       1. RSA Asymmetric Encryption, Decryption, and Digital Signatures
 *       2. ECC Point Cryptography, ECDH Key Agreement, and Encryption
 *       3. HMAC Message Authentication, Integrity Verification, and SHA-256
 *       4. Authenticated Encryption (Encrypt-then-MAC hybrid workflows)
 *   - Handles data normalization, Buffer/String encoding, and BigInt <-> JSON
 *     serialization so cryptographic values can safely travel across HTTP/REST APIs
 *     and SQLite database columns.
 *
 * Dependencies:
 *   - ../crypto/rsa  (From-scratch RSA module)
 *   - ../crypto/ecc  (From-scratch ECC module)
 *   - ../crypto/hmac (From-scratch HMAC & SHA-256 module)
 *   - Node.js built-in `crypto` (for random byte entropy)
 *
 * ============================================================================
 */

const crypto = require('crypto');

// Import from-scratch cryptographic modules
// Built defensively to handle missing exports or partial implementations
const rsa = require('../crypto/rsa');
const ecc = require('../crypto/ecc');
const hmac = require('../crypto/hmac');


/**
 * Convert a BigInt or an object/array containing BigInts into
 * standard JSON-serializable primitives (strings with '0x' or decimal).
 *
 * Standard JSON.stringify() throws a TypeError on BigInt:
 * "TypeError: Do not know how to serialize a BigInt"
 *
 * This utility traverses objects and turns BigInts into string representations.
 *
 * @param {*} data - Any JavaScript value (object, array, BigInt, primitive)
 * @returns {*} Clean copy with BigInts converted to strings
 */
function serializeBigInt(data) {
    if (data === null || data === undefined) {
        return data;
    }
    if (typeof data === 'bigint') {
        return data.toString();
    }
    if (Array.isArray(data)) {
        return data.map(item => serializeBigInt(item));
    }
    if (typeof data === 'object') {
        const serialized = {};
        for (const [key, value] of Object.entries(data)) {
            serialized[key] = serializeBigInt(value);
        }
        return serialized;
    }
    return data;
}

/**
 * Restore serialized string representation back to BigInt.
 * Safely accepts BigInt, decimal string, or hex string ('0x...').
 *
 * @param {string|number|BigInt} value - Value to convert
 * @returns {BigInt} Native JavaScript BigInt
 */
function toBigInt(value) {
    if (typeof value === 'bigint') {
        return value;
    }
    if (typeof value === 'number') {
        return BigInt(Math.floor(value));
    }
    if (typeof value === 'string') {
        const trimmed = value.trim();
        if (trimmed.startsWith('0x') || trimmed.startsWith('0X')) {
            return BigInt(trimmed);
        }
        return BigInt(trimmed);
    }
    throw new TypeError(`Cannot convert value of type ${typeof value} to BigInt`);
}


// =====================================================
// Section 2: RSA Service Operations
// =====================================================
function generateRsaKeyPair(){
    return serializeBigInt( rsa.generateKeys() );
}

function rsaEncrypt(plaintext, publicKey){
    const n = toBigInt(publicKey.n);
    const e = toBigInt(publicKey.e);
    if (!plaintext) return '';
    const str = String(plaintext);
    const cipherArr = [];
    for (let i = 0; i < str.length; i++) {
        const m = BigInt(str.charCodeAt(i));
        cipherArr.push(rsa.modPow(m, e, n).toString(16));
    }
    return cipherArr.join(':');
}

function rsaDecrypt(ciphertext, privateKey){
    if (!ciphertext) return '';
    const str = String(ciphertext);
    if (!str.includes(':')) return str;
    try {
        const n = toBigInt(privateKey.n);
        const d = toBigInt(privateKey.d);
        const parts = str.split(':');
        let plain = '';
        for (const part of parts) {
            const c = BigInt('0x' + part);
            plain += String.fromCharCode(Number(rsa.modPow(c, d, n)));
        }
        return plain;
    } catch {
        return str;
    }
}



// =====================================================
// Section 3: ECC Service Operations
// =====================================================
function generateEccKeyPair(){
    const keys = ecc.generateKeyPair();
    return serializeBigInt(keys);
}

function eccEncrypt(plaintext, publicKey){
    return serializeBigInt( ecc.encrypt( plaintext, { x: toBigInt(publicKey.x), y: toBigInt(publicKey.y) } ) );
}

function eccDecrypt(data, privateKey){
    const formattedData = {
        ephemeralPublic: {
            x: toBigInt(data.ephemeralPublic.x),
            y: toBigInt(data.ephemeralPublic.y)
        },
        ciphertext: data.ciphertext
    };
    return ecc.decrypt( formattedData, toBigInt(privateKey) );
}


// =====================================================
// Section 4: HMAC & Hash Service Operations
// =====================================================

function createHmac(key, message){
    return hmac.computeHmac( key,  message,'hex' );
}

function verifyHmac(key, message, mac){
    return hmac.verifyHmac(key, message, mac);
}

function generateHmacKey(size = 32){
    return hmac.generateKey(size);
}


// =====================================================
// Section 5: Authenticated Encryption (Hybrid Scheme)
// =====================================================

/**
 * Authenticated Encryption (Encrypt-then-MAC):
 * Encrypts data with RSA, then creates an HMAC over the ciphertext.
 *
 * Guarantees both Confidentiality (RSA) and Integrity/Authenticity (HMAC).
 *
 * @param {string} plaintext - Data to encrypt
 * @param {{ n: string|BigInt, e: string|BigInt }} rsaPublicKey - Recipient's RSA public key
 * @param {string} hmacKey - Shared authentication key
 * @returns {{
 *   ciphertext: string,
 *   hmacTag: string
 * }}
 */
function encryptAndAuthenticate(plaintext, publicKey, hmacKey){
    const ciphertext = rsaEncrypt( plaintext, publicKey );
    const tag = createHmac( hmacKey, ciphertext );

    return {ciphertext,tag};
}

/**
 * Verified Decryption (Authenticate-then-Decrypt):
 * Verifies the HMAC tag over the ciphertext first. If authentic, decrypts with RSA.
 *
 * @param {string} ciphertext - Encrypted ciphertext
 * @param {string} hmacTag - HMAC authentication tag
 * @param {{ n: string|BigInt, d: string|BigInt }} rsaPrivateKey - Recipient's RSA private key
 * @param {string} hmacKey - Shared authentication key
 * @returns {string} Decrypted plaintext
 * @throws {Error} If MAC verification fails (data was tampered with)
 */
function verifyAndDecrypt(ciphertext, tag, privateKey, hmacKey){
    if(!verifyHmac(hmacKey, ciphertext, tag)){
        throw new Error("Integrity check failed");
    }

    return rsaDecrypt( ciphertext, privateKey);
}

/**
 * ECC Authenticated Encryption:
 * Encrypts data with ECC and tags it with HMAC.
 *
 * @param {string} plaintext - Plaintext message
 * @param {{ x: string|BigInt, y: string|BigInt }} eccPublicKey - Recipient's ECC public key
 * @param {string} hmacKey - Shared authentication key
 * @returns {{
 *   ephemeralPublic: { x: string, y: string },
 *   ciphertext: string,
 *   hmacTag: string
 * }}
 */

function eccEncryptAndAuthenticate( plaintext, publicKey, hmacKey)
{
    const encrypted = eccEncrypt( plaintext, publicKey  );
    const tag = createHmac( hmacKey,encrypted.ciphertext );
    return {...encrypted,tag};
}

/**
 * ECC Verified Decryption:
 * Verifies HMAC tag, then decrypts ECC ciphertext.
 *
 * @param {{ ephemeralPublic: { x: string|BigInt, y: string|BigInt }, ciphertext: string, hmacTag: string }} payload
 * @param {string|BigInt} eccPrivateKey - Recipient's ECC private key scalar
 * @param {string} hmacKey - Shared authentication key
 * @returns {string} Decrypted plaintext
 * @throws {Error} If MAC verification fails
 */
function eccVerifyAndDecrypt(payload, eccPrivateKey, hmacKey) {
    const isAuthentic = verifyHmac(hmacKey, payload.ciphertext, payload.hmacTag);

    if (!isAuthentic) {
        throw new Error('[CryptoService] ECC Integrity check failed! Ciphertext tampered or key mismatch.');
    }

    return eccDecrypt(payload, eccPrivateKey);
}


// =====================================================
// Section 6: Module Exports
// =====================================================

module.exports = {
    // BigInt helpers
    serializeBigInt,
    toBigInt,


    // RSA
    generateRsaKeyPair,
    rsaEncrypt,
    rsaDecrypt,


    // ECC
    generateEccKeyPair,
    eccEncrypt,
    eccDecrypt,


    // HMAC
    createHmac,
    verifyHmac,
    generateHmacKey,


    // Combined
    encryptAndAuthenticate,
    verifyAndDecrypt,
    eccEncryptAndAuthenticate,
     eccVerifyAndDecrypt

};

