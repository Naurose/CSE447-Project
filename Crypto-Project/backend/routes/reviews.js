const express = require('express');
const pool = require('../db');
const { encryptContentData, decryptContentData, decryptUserData } = require('../services/keyManager');

const router = express.Router();

// Get Reviews for a Game
router.get('/:gameId', async (req, res) => {
    try {
        const query = `
            SELECT r.*, u.username 
            FROM reviews r
            JOIN users u ON r.user_id = u.user_id
            WHERE r.game_id = ?
            ORDER BY r.review_date DESC
        `;
        const [reviews] = await pool.query(query, [req.params.gameId]);

        // Decrypt ECC-encrypted review comments & RSA-encrypted usernames
        const decryptedReviews = reviews.map(r => ({
            ...r,
            username: decryptUserData(r.username),
            comment: decryptContentData(r.comment)
        }));

        res.json(decryptedReviews);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

// Add Review
router.post('/', async (req, res) => {
    const { userId, gameId, rating, comment } = req.body;

    try {
        // Encrypt review comment using ECC
        const encryptedComment = encryptContentData(comment);

        await pool.query(
            'INSERT INTO reviews (user_id, game_id, rating, comment) VALUES (?, ?, ?, ?)',
            [userId, gameId, rating, encryptedComment]
        );
        res.json({ message: 'Review submitted' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

const { verifyToken } = require('../middleware/auth');
const { requireAdmin } = require('../middleware/rbac');

// DELETE Review (Admin Only)
router.delete('/:reviewNum', verifyToken, requireAdmin, async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM reviews WHERE review_num = ?', [req.params.reviewNum]);
        if (rows.length === 0) {
            return res.status(404).json({ message: 'Review not found' });
        }

        await pool.query('DELETE FROM reviews WHERE review_num = ?', [req.params.reviewNum]);
        res.json({ message: 'Review deleted successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error while deleting review' });
    }
});

// PUT update Review (Admin Only)
router.put('/:reviewNum', verifyToken, requireAdmin, async (req, res) => {
    const { rating, comment } = req.body;
    const reviewNum = req.params.reviewNum;

    if (!rating || !comment) {
        return res.status(400).json({ message: 'Rating and comment are required' });
    }

    try {
        const [rows] = await pool.query('SELECT * FROM reviews WHERE review_num = ?', [reviewNum]);
        if (rows.length === 0) {
            return res.status(404).json({ message: 'Review not found' });
        }

        const encryptedComment = encryptContentData(comment);

        await pool.query(
            'UPDATE reviews SET rating = ?, comment = ? WHERE review_num = ?',
            [rating, encryptedComment, reviewNum]
        );

        res.json({ message: 'Review updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error while updating review' });
    }
});

module.exports = router;
