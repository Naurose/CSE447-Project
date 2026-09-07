const express = require('express');
const pool = require('../db');
const bcrypt = require('bcryptjs');
const { encryptUserData, decryptUserData } = require('../services/keyManager');

const router = express.Router();

// Get User Profile (Decrypted)
router.get('/:userId/profile', async (req, res) => {
    try {
        const [users] = await pool.query(
            'SELECT user_id, username, email, address, phone, two_factor_enabled FROM users WHERE user_id = ?',
            [req.params.userId]
        );
        if (users.length === 0) return res.status(404).json({ message: 'User not found' });
        const user = users[0];
        res.json({
            id: user.user_id,
            username: user.username,
            email: user.email,
            address: decryptUserData(user.address),
            phone: decryptUserData(user.phone),
            two_factor_enabled: user.two_factor_enabled
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get User Library
router.get('/:userId/library', async (req, res) => {
    try {
        const query = `
            SELECT l.library_id, l.type, l.expiry_date, g.game_id, g.title, g.cover_image, g.genre
            FROM library l
            JOIN games g ON l.game_id = g.game_id
            WHERE l.user_id = ? 
            AND (l.type = 'buy' OR l.expiry_date > datetime('now'))
        `;
        const [library] = await pool.query(query, [req.params.userId]);
        res.json(library);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

router.put('/update', async (req, res) => {
    const { userId, username, email, address, phone, password } = req.body;

    try {
        const encAddress = address ? encryptUserData(address) : '';
        const encPhone = phone ? encryptUserData(phone) : '';

        let query = 'UPDATE users SET username=?, email=?, address=?, phone=?';
        const params = [username, email, encAddress, encPhone];

        if (password) {
             const salt = await bcrypt.genSalt(10);
             const hashedPassword = await bcrypt.hash(password, salt);
             query += ', password=?';
             params.push(hashedPassword);
        }

        query += ' WHERE user_id=?';
        params.push(userId);

        await pool.query(query, params);
        res.json({ message: 'Profile updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

// Settings / 2FA Stub
router.put('/settings/2fa', async (req, res) => {
    const { userId, enable } = req.body;
    try {
        await pool.query('UPDATE users SET two_factor_enabled = ? WHERE user_id = ?', [enable, userId]);
        res.json({ message: `2FA ${enable ? 'enabled' : 'disabled'}` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

module.exports = router;
