'use strict';

const pool = require('../db');
const { encryptUserData, decryptUserData } = require('./keyManager');

/**
 * Decrypt user object fields (username, email, address, phone)
 */
function decryptUser(user) {
    if (!user) return null;
    return {
        ...user,
        username: user.username ? decryptUserData(user.username) : '',
        email: user.email ? decryptUserData(user.email) : '',
        address: user.address ? decryptUserData(user.address) : '',
        phone: user.phone ? decryptUserData(user.phone) : ''
    };
}

/**
 * Encrypt user object fields (username, email, address, phone) with RSA
 */
function encryptUserFields({ username, email, address, phone }) {
    return {
        username: username ? encryptUserData(username) : '',
        email: email ? encryptUserData(email) : '',
        address: address ? encryptUserData(address) : '',
        phone: phone ? encryptUserData(phone) : ''
    };
}

/**
 * Find user by email or username by fetching candidates and matching decrypted values
 */
async function findUserByIdentifier(identifier) {
    if (!identifier) return null;
    const target = identifier.trim().toLowerCase();

    const [rows] = await pool.query('SELECT * FROM users');
    for (const rawUser of rows) {
        const decryptedUser = decryptUser(rawUser);
        if (
            (decryptedUser.email && decryptedUser.email.toLowerCase() === target) ||
            (decryptedUser.username && decryptedUser.username.toLowerCase() === target)
        ) {
            return decryptedUser;
        }
    }
    return null;
}

/**
 * Find user specifically by decrypted email
 */
async function findUserByEmail(email) {
    if (!email) return null;
    const target = email.trim().toLowerCase();

    const [rows] = await pool.query('SELECT * FROM users');
    for (const rawUser of rows) {
        const decryptedUser = decryptUser(rawUser);
        if (decryptedUser.email && decryptedUser.email.toLowerCase() === target) {
            return decryptedUser;
        }
    }
    return null;
}

/**
 * Find user specifically by user_id
 */
async function findUserById(userId) {
    if (!userId) return null;
    const [rows] = await pool.query('SELECT * FROM users WHERE user_id = ?', [userId]);
    if (rows.length === 0) return null;
    return decryptUser(rows[0]);
}

module.exports = {
    decryptUser,
    encryptUserFields,
    findUserByIdentifier,
    findUserByEmail,
    findUserById
};
