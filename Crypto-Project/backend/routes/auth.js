const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const pool = require('../db');
const { sendOtpEmail } = require('../services/emailService');
const { encryptUserData, decryptUserData } = require('../services/keyManager');
const { encryptUserFields, findUserByIdentifier, findUserByEmail } = require('../services/userService');

const router = express.Router();

/**
 * Generate cryptographically strong 6-digit numeric OTP code
 */
const generate6DigitOtp = () => {
    return crypto.randomInt(100000, 1000000).toString();
};

/**
 * Helper to invalidate old OTPs and send a new one
 */
const createAndSendOtp = async (email, purpose) => {
    // Generate code
    const otpCode = generate6DigitOtp();
    const salt = await bcrypt.genSalt(10);
    const otpHash = await bcrypt.hash(otpCode, salt);

    // Expiry set to 5 minutes from now (in ISO format for SQLite comparison)
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();

    // Delete existing unverified OTPs for this email & purpose
    await pool.query(
        'DELETE FROM otps WHERE email = ? AND purpose = ? AND is_verified = 0',
        [email, purpose]
    );

    // Insert new OTP record
    await pool.query(
        'INSERT INTO otps (email, otp_hash, purpose, expires_at) VALUES (?, ?, ?, ?)',
        [email, otpHash, purpose, expiresAt]
    );

    // Dispatch email
    await sendOtpEmail(email, otpCode, purpose);

    return otpCode;
};

// ==========================================
// REGISTRATION FLOW (WITH OTP)
// ==========================================

// Step 1: Request Registration OTP
router.post('/register-request', async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ message: 'Please provide all required fields' });
    }

    try {
        // Check if user exists (matching decrypted username or email)
        const existingEmail = await findUserByEmail(email);
        const existingUsername = await findUserByIdentifier(username);

        if (existingEmail || existingUsername) {
            return res.status(400).json({ message: 'Username or Email is already registered' });
        }

        // Send OTP
        await createAndSendOtp(email, 'register');

        res.status(200).json({
            success: true,
            requiresOtp: true,
            email,
            message: 'OTP verification code sent to your email.'
        });
    } catch (err) {
        console.error('Register Request Error:', err);
        res.status(500).json({ message: 'Server error during registration request' });
    }
});

// Step 2: Verify Registration OTP & Complete Account Creation
router.post('/register-verify', async (req, res) => {
    const { username, email, password, address, phone, otp } = req.body;

    if (!email || !otp || !username || !password) {
        return res.status(400).json({ message: 'Missing required parameters or OTP code' });
    }

    try {
        // Check if user was registered in the meantime
        const existingUser = await findUserByEmail(email) || await findUserByIdentifier(username);
        if (existingUser) {
            return res.status(400).json({ message: 'User already registered' });
        }

        // Find latest active OTP for this email & purpose='register'
        const [otpRecords] = await pool.query(
            "SELECT * FROM otps WHERE email = ? AND purpose = 'register' AND is_verified = 0 ORDER BY created_at DESC LIMIT 1",
            [email]
        );

        if (otpRecords.length === 0) {
            return res.status(400).json({ message: 'No active OTP found. Please request a new code.' });
        }

        const otpRecord = otpRecords[0];

        // Check if expired
        if (new Date(otpRecord.expires_at) < new Date()) {
            return res.status(400).json({ message: 'OTP has expired. Please request a new code.' });
        }

        // Check attempts limit (max 5)
        if (otpRecord.attempts >= 5) {
            return res.status(400).json({ message: 'Too many incorrect attempts. Please request a new OTP.' });
        }

        // Verify OTP
        const isMatch = await bcrypt.compare(otp, otpRecord.otp_hash);
        if (!isMatch) {
            // Increment attempts
            await pool.query('UPDATE otps SET attempts = attempts + 1 WHERE otp_id = ?', [otpRecord.otp_id]);
            return res.status(400).json({ message: 'Invalid OTP code. Please try again.' });
        }

        // Mark OTP verified
        await pool.query('UPDATE otps SET is_verified = 1 WHERE otp_id = ?', [otpRecord.otp_id]);

        // Hash password and encrypt all sensitive fields (username, email, address, phone) with RSA
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const enc = encryptUserFields({ username, email, address, phone });

        const [result] = await pool.query(
            'INSERT INTO users (username, email, password, address, phone) VALUES (?, ?, ?, ?, ?)',
            [enc.username, enc.email, hashedPassword, enc.address, enc.phone]
        );

        const userId = result.insertId;

        // Generate JWT Token for immediate login
        const jwtSecret = process.env.JWT_SECRET || 'crypto_default_secret_key';
        const userRole = 'user';
        const token = jwt.sign({ id: userId, role: userRole }, jwtSecret, { expiresIn: '24h' });

        res.status(201).json({
            message: 'Account registered and verified successfully!',
            token,
            user: {
                id: userId,
                username,
                email,
                role: userRole,
                address: address || '',
                phone: phone || '',
                two_factor_enabled: 0
            }
        });
    } catch (err) {
        console.error('Register Verify Error:', err);
        res.status(500).json({ message: 'Server error during registration verification' });
    }
});

// Original /register endpoint redirecting to appropriate flow
router.post('/register', async (req, res) => {
    if (req.body.otp) {
        return router.handle({ ...req, url: '/register-verify' }, res);
    } else {
        return router.handle({ ...req, url: '/register-request' }, res);
    }
});

// ==========================================
// LOGIN FLOW (WITH OTP 2FA)
// ==========================================

// Step 1: Request Login OTP (Validate password & send email OTP)
router.post('/login-request', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Please enter email/username and password' });
    }

    try {
        // Query user by decrypted email or username
        const user = await findUserByIdentifier(email);

        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Check password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Send OTP to user's registered email
        await createAndSendOtp(user.email, 'login');

        res.json({
            requiresOtp: true,
            email: user.email,
            message: 'Password verified. An OTP code has been sent to your email.'
        });
    } catch (err) {
        console.error('Login Request Error:', err);
        res.status(500).json({ message: 'Server error during login request' });
    }
});

// Step 2: Verify Login OTP & Issue JWT Token
router.post('/login-verify', async (req, res) => {
    const { email, otp } = req.body;

    if (!email || !otp) {
        return res.status(400).json({ message: 'Email and OTP code are required' });
    }

    try {
        // Find latest active OTP for this email & purpose='login'
        const [otpRecords] = await pool.query(
            "SELECT * FROM otps WHERE email = ? AND purpose = 'login' AND is_verified = 0 ORDER BY created_at DESC LIMIT 1",
            [email]
        );

        if (otpRecords.length === 0) {
            return res.status(400).json({ message: 'No active OTP found. Please request a new code.' });
        }

        const otpRecord = otpRecords[0];

        // Check expiry
        if (new Date(otpRecord.expires_at) < new Date()) {
            return res.status(400).json({ message: 'OTP code has expired. Please request a new code.' });
        }

        // Check max attempts
        if (otpRecord.attempts >= 5) {
            return res.status(400).json({ message: 'Too many incorrect attempts. Please request a new OTP.' });
        }

        // Verify code
        const isMatch = await bcrypt.compare(otp, otpRecord.otp_hash);
        if (!isMatch) {
            await pool.query('UPDATE otps SET attempts = attempts + 1 WHERE otp_id = ?', [otpRecord.otp_id]);
            return res.status(400).json({ message: 'Invalid OTP code. Please try again.' });
        }

        // Mark OTP as verified
        await pool.query('UPDATE otps SET is_verified = 1 WHERE otp_id = ?', [otpRecord.otp_id]);

        // Get decrypted user details
        const user = await findUserByEmail(email);
        if (!user) {
            return res.status(400).json({ message: 'User not found' });
        }

        // Issue token
        const jwtSecret = process.env.JWT_SECRET || 'crypto_default_secret_key';
        const userRole = user.role || 'user';
        const token = jwt.sign({ id: user.user_id, role: userRole }, jwtSecret, { expiresIn: '24h' });

        res.json({
            token,
            user: {
                id: user.user_id,
                username: user.username,
                email: user.email,
                role: userRole,
                address: user.address,
                phone: user.phone,
                two_factor_enabled: user.two_factor_enabled
            }
        });
    } catch (err) {
        console.error('Login Verify Error:', err);
        res.status(500).json({ message: 'Server error during OTP verification' });
    }
});

// Original /login endpoint supporting 1-step or 2-step
router.post('/login', async (req, res) => {
    if (req.body.otp) {
        // Call login-verify
        const { email, otp } = req.body;
        const [otpRecords] = await pool.query(
            "SELECT * FROM otps WHERE email = ? AND purpose = 'login' AND is_verified = 0 ORDER BY created_at DESC LIMIT 1",
            [email]
        );

        if (otpRecords.length > 0) {
            const otpRecord = otpRecords[0];
            const isMatch = await bcrypt.compare(otp, otpRecord.otp_hash);
            if (isMatch && new Date(otpRecord.expires_at) >= new Date()) {
                await pool.query('UPDATE otps SET is_verified = 1 WHERE otp_id = ?', [otpRecord.otp_id]);
                const user = await findUserByIdentifier(email);
                if (user) {
                    const jwtSecret = process.env.JWT_SECRET || 'crypto_default_secret_key';
                    const userRole = user.role || 'user';
                    const token = jwt.sign({ id: user.user_id, role: userRole }, jwtSecret, { expiresIn: '24h' });
                    return res.json({
                        token,
                        user: {
                            id: user.user_id,
                            username: user.username,
                            email: user.email,
                            role: userRole,
                            address: user.address,
                            phone: user.phone,
                            two_factor_enabled: user.two_factor_enabled
                        }
                    });
                }
            }
        }
    }

    // Step 1: Login Request
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: 'Please provide email and password' });
    }

    try {
        const user = await findUserByIdentifier(email);
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Send OTP
        await createAndSendOtp(user.email, 'login');
        return res.json({
            requiresOtp: true,
            email: user.email,
            message: 'OTP sent to email'
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

// ==========================================
// RESEND OTP ENDPOINT (WITH RATE LIMITING)
// ==========================================

router.post('/resend-otp', async (req, res) => {
    const { email, purpose = 'login' } = req.body;

    if (!email) {
        return res.status(400).json({ message: 'Email address is required' });
    }

    try {
        // Rate limit check: check if an OTP was created < 60 seconds ago
        const [recentOtps] = await pool.query(
            'SELECT * FROM otps WHERE email = ? AND purpose = ? ORDER BY created_at DESC LIMIT 1',
            [email, purpose]
        );

        if (recentOtps.length > 0) {
            const rawCreatedAt = recentOtps[0].created_at;
            const isoString = rawCreatedAt.includes('T') ? rawCreatedAt : rawCreatedAt.replace(' ', 'T') + 'Z';
            const lastCreated = new Date(isoString).getTime();
            const timeDiff = (Date.now() - lastCreated) / 1000; // seconds

            if (timeDiff < 60) {
                const waitSecs = Math.ceil(60 - timeDiff);
                return res.status(429).json({
                    message: `Please wait ${waitSecs} seconds before requesting another code.`
                });
            }
        }

        await createAndSendOtp(email, purpose);

        res.json({
            success: true,
            message: 'A new OTP code has been sent to your email.'
        });
    } catch (err) {
        console.error('Resend OTP Error:', err);
        res.status(500).json({ message: 'Server error while resending OTP' });
    }
});

module.exports = router;
