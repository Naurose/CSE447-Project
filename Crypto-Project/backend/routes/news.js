const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const pool = require('../db');

// Ensure uploads directory exists
const uploadDir = path.join(__dirname, '../uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Multer Setup
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        cb(null, 'news-' + Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({ storage });

// GET all articles
router.get('/', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM news_articles ORDER BY created_at DESC');
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

// GET single article
router.get('/:id', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM news_articles WHERE article_id = ?', [req.params.id]);
        
        if (rows.length === 0) {
            return res.status(404).json({ message: 'Article not found' });
        }
        
        res.json(rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

// POST new article
router.post('/', upload.single('image'), async (req, res) => {
    const { title, content, userId } = req.body;
    const imagePath = req.file ? `/uploads/${req.file.filename}` : null;

    if (!title || !content) {
        return res.status(400).json({ message: 'Title and content are required' });
    }

    try {
        await pool.query(
            'INSERT INTO news_articles (user_id, title, content, image_path) VALUES (?, ?, ?, ?)',
            [userId || null, title, content, imagePath]
        );
        res.status(201).json({ message: 'Article posted successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

module.exports = router;
