const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const path = require('path');
const db = require('./database/database');

dotenv.config({ path: path.join(__dirname, '.env') });
dotenv.config({ path: path.join(__dirname, '../.env') });

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// SQLite Database Status
console.log('Connected to SQLite database (gamevault.db)');

// Serve Frontend Static Files (HTML, CSS, JS)
app.use(express.static(path.join(__dirname, '../frontend')));

// Serve Uploaded Images
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// API Health Route
app.get('/api', (req, res) => {
    res.json({ message: 'GameVault API is running...' });
});

// Routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/games', require('./routes/games'));
app.use('/api/cart', require('./routes/cart'));
app.use('/api/orders', require('./routes/orders'));
app.use('/api/user', require('./routes/users'));
app.use('/api/reviews', require('./routes/reviews'));
app.use('/api/news', require('./routes/news'));
app.use('/api/keys', require('./routes/key-management'));

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

module.exports = db;
