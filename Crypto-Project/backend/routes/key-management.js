'use strict';

/**
 * ============================================================================
 * Key Management Routes
 * ============================================================================
 *
 * Exposes key management endpoints:
 *   - GET  /api/keys/public  -> Get public keys (RSA & ECC) for encryption
 *   - GET  /api/keys/status  -> Check key status and creation timestamp
 *   - POST /api/keys/rotate  -> Rotate active keys
 *
 * ============================================================================
 */

const express = require('express');
const router = express.Router();
const keyManager = require('../services/keyManager');

// Get active public keys (accessible by clients/frontend)
router.get('/public', (req, res) => {
    try {
        const publicKeys = keyManager.getPublicKeys();
        res.json({
            success: true,
            keys: publicKeys
        });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// Check key status and active timestamp
router.get('/status', (req, res) => {
    try {
        const publicKeys = keyManager.getPublicKeys();
        res.json({
            success: true,
            status: 'active',
            createdAt: publicKeys.createdAt
        });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// Rotate cryptographic keys
router.post('/rotate', (req, res) => {
    try {
        const result = keyManager.rotateKeys();
        res.json({
            success: true,
            ...result
        });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

module.exports = router;

