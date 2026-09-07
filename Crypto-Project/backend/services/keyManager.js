'use strict';

/**
 * ============================================================================
 * KeyManager Service — Central Key Management
 * ============================================================================
 *
 * Course: CSE447 — Cryptography and Network Security
 * Project: GameVault
 *
 * Purpose:
 *   - Manages the lifecycle of active cryptographic keys (RSA, ECC, HMAC)
 *   - Stores current keys in memory
 *   - Exposes public keys to clients for encryption & verification
 *   - Keeps private keys secure on the server for decryption & signing
 *   - Provides key rotation to replace old keys with fresh ones
 *
 * ============================================================================
 */

const cryptoService = require('./cryptoService');

// In-memory key store
const keyStore = {
    rsa: null,        // { publicKey: { n, e }, privateKey: { n, d } }
    ecc: null,        // { publicKey: { x, y }, privateKey }
    hmac: null,       // secret key string
    createdAt: null   // timestamp
};

// =====================================================
// Core Functions
// =====================================================

/**
 * Generate a complete set of fresh keys (RSA, ECC, HMAC).
 */
function generateAllKeys() {
    keyStore.rsa = cryptoService.generateRsaKeyPair();
    keyStore.ecc = cryptoService.generateEccKeyPair();
    keyStore.hmac = cryptoService.generateHmacKey();
    keyStore.createdAt = new Date().toISOString();

    return keyStore;
}

/**
 * Initialize keys on system startup if not already created.
 */
function initKeys() {
    if (!keyStore.createdAt) {
        generateAllKeys();
    }
    return keyStore;
}

/**
 * Get active public keys.
 * Safe to share with clients/frontend for encryption and signature verification.
 */
function getPublicKeys() {
    initKeys();
    return {
        rsa: keyStore.rsa.publicKey,
        ecc: keyStore.ecc.publicKey,
        createdAt: keyStore.createdAt
    };
}

/**
 * Get full key store (including private keys and HMAC secret).
 * For internal server use only.
 */
function getAllKeys() {
    initKeys();
    return keyStore;
}

/**
 * Rotate keys: generates brand new keys and updates the timestamp.
 */
function rotateKeys() {
    generateAllKeys();
    return {
        message: 'Keys rotated successfully',
        createdAt: keyStore.createdAt,
        publicKeys: {
            rsa: keyStore.rsa.publicKey,
            ecc: keyStore.ecc.publicKey
        }
    };
}

/**
 * Encrypt sensitive user data (address, phone) using RSA public key.
 */
function encryptUserData(plaintext) {
    if (!plaintext) return '';
    const keys = getPublicKeys();
    return cryptoService.rsaEncrypt(plaintext, keys.rsa);
}

/**
 * Decrypt sensitive user data using RSA private key.
 */
function decryptUserData(ciphertext) {
    if (!ciphertext) return '';
    const keys = getAllKeys();
    return cryptoService.rsaDecrypt(ciphertext, keys.rsa.privateKey);
}

/**
 * Encrypt content data (reviews, articles) using ECC public key.
 */
function encryptContentData(plaintext) {
    if (!plaintext) return '';
    const keys = getPublicKeys();
    const encrypted = cryptoService.eccEncrypt(plaintext, keys.ecc);
    return JSON.stringify(encrypted);
}

/**
 * Decrypt content data using ECC private key.
 */
function decryptContentData(ciphertext) {
    if (!ciphertext) return '';
    try {
        const parsed = JSON.parse(ciphertext);
        if (parsed && parsed.ephemeralPublic && parsed.ciphertext) {
            const keys = getAllKeys();
            return cryptoService.eccDecrypt(parsed, keys.ecc.privateKey);
        }
        return ciphertext;
    } catch {
        return ciphertext;
    }
}

// Auto-initialize keys on load
initKeys();

module.exports = {
    initKeys,
    getPublicKeys,
    getAllKeys,
    rotateKeys,
    encryptUserData,
    decryptUserData,
    encryptContentData,
    decryptContentData
};

