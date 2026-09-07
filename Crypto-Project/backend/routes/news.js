const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const pool = require('../db');
const { encryptContentData, decryptContentData } = require('../services/keyManager');

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

        // Decrypt ECC-encrypted article contents
        const decryptedArticles = rows.map(article => ({
            ...article,
            content: decryptContentData(article.content)
        }));

        res.json(decryptedArticles);
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
        
        const article = rows[0];
        article.content = decryptContentData(article.content);

        res.json(article);
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
        // Encrypt article content with ECC
        const encryptedContent = encryptContentData(content);

        await pool.query(
            'INSERT INTO news_articles (user_id, title, content, image_path) VALUES (?, ?, ?, ?)',
            [userId || null, title, encryptedContent, imagePath]
        );
        res.status(201).json({ message: 'Article posted successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

const { verifyToken } = require('../middleware/auth');
const { requireAdmin } = require('../middleware/rbac');

// DELETE article (Admin Only)
router.delete('/:id', verifyToken, requireAdmin, async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM news_articles WHERE article_id = ?', [req.params.id]);
        if (rows.length === 0) {
            return res.status(404).json({ message: 'Article not found' });
        }

        await pool.query('DELETE FROM news_articles WHERE article_id = ?', [req.params.id]);
        res.json({ message: 'Article deleted successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error while deleting article' });
    }
});

// PUT update article (Admin Only)
router.put('/:id', verifyToken, requireAdmin, upload.single('image'), async (req, res) => {
    const { title, content } = req.body;
    const articleId = req.params.id;

    if (!title || !content) {
        return res.status(400).json({ message: 'Title and content are required' });
    }

    try {
        const [rows] = await pool.query('SELECT * FROM news_articles WHERE article_id = ?', [articleId]);
        if (rows.length === 0) {
            return res.status(404).json({ message: 'Article not found' });
        }

        const encryptedContent = encryptContentData(content);

        if (req.file) {
            const imagePath = `/uploads/${req.file.filename}`;
            await pool.query(
                'UPDATE news_articles SET title = ?, content = ?, image_path = ? WHERE article_id = ?',
                [title, encryptedContent, imagePath, articleId]
            );
        } else {
            await pool.query(
                'UPDATE news_articles SET title = ?, content = ? WHERE article_id = ?',
                [title, encryptedContent, articleId]
            );
        }

        res.json({ message: 'Article updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error while updating article' });
    }
});

module.exports = router;
