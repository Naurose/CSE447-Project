const express = require('express');
const pool = require('../db');

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
        res.json(reviews);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

// Add Review
router.post('/', async (req, res) => {
    const { userId, gameId, rating, comment } = req.body;

    try {
        await pool.query(
            'INSERT INTO reviews (user_id, game_id, rating, comment) VALUES (?, ?, ?, ?)',
            [userId, gameId, rating, comment]
        );
        res.json({ message: 'Review submitted' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

module.exports = router;
