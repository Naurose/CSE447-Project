const jwt = require('jsonwebtoken');
const pool = require('../db');
const { decryptUserData } = require('../services/keyManager');

/**
 * Centralized JWT verification middleware
 * Extracts req.user from token, including user_id, username, email, and role
 */
const verifyToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access denied. No authentication token provided.' });
    }

    try {
        const jwtSecret = process.env.JWT_SECRET || 'crypto_default_secret_key';
        const decoded = jwt.verify(token, jwtSecret);

        // Fetch user record from database to verify status & role
        const [users] = await pool.query(
            'SELECT user_id, username, email, role FROM users WHERE user_id = ?',
            [decoded.id]
        );

        if (users.length === 0) {
            return res.status(401).json({ message: 'Invalid token. User does not exist.' });
        }

        const user = users[0];
        req.user = {
            id: user.user_id,
            username: decryptUserData(user.username),
            email: decryptUserData(user.email),
            role: user.role || 'user'
        };

        next();
    } catch (err) {
        return res.status(403).json({ message: 'Invalid or expired authentication token.' });
    }
};

module.exports = {
    verifyToken
};