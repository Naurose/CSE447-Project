const { DatabaseSync } = require('node:sqlite');
const path = require('path');
const fs = require('fs');

// Ensure database directory exists
const dbDir = __dirname;
if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
}

const dbPath = path.join(dbDir, 'gamevault.db');
const db = new DatabaseSync(dbPath);

const bcrypt = require('bcryptjs');

// Enable foreign keys
db.exec('PRAGMA foreign_keys = ON;');

// Initialize Tables Schema
const initSchema = () => {
    db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            address TEXT,               -- Encrypted at rest using RSA
            phone TEXT,                 -- Encrypted at rest using RSA
            role TEXT DEFAULT 'user',
            two_factor_enabled INTEGER DEFAULT 0,
            two_factor_secret TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS otps (
            otp_id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            otp_hash TEXT NOT NULL,
            purpose TEXT NOT NULL CHECK(purpose IN ('login', 'register')),
            expires_at DATETIME NOT NULL,
            attempts INTEGER DEFAULT 0,
            is_verified INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS games (
            game_id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            price REAL NOT NULL,
            rental_price REAL DEFAULT 0.00,
            description TEXT,
            cover_image TEXT,
            publisher TEXT,
            genre TEXT,
            release_date TEXT,
            rating REAL DEFAULT 0.00
        );

        CREATE TABLE IF NOT EXISTS reviews (
            review_num INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            game_id INTEGER,
            comment TEXT,               -- Encrypted at rest using ECC
            rating INTEGER CHECK (rating >= 1 AND rating <= 5),
            review_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(user_id),
            FOREIGN KEY (game_id) REFERENCES games(game_id)
        );

        CREATE TABLE IF NOT EXISTS cart (
            cart_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            game_id INTEGER,
            quantity INTEGER DEFAULT 1,
            acquisition_type TEXT DEFAULT 'buy' CHECK(acquisition_type IN ('buy', 'rent')),
            rent_duration INTEGER DEFAULT 7,
            FOREIGN KEY (user_id) REFERENCES users(user_id),
            FOREIGN KEY (game_id) REFERENCES games(game_id)
        );

        CREATE TABLE IF NOT EXISTS rentals (
            rental_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            game_id INTEGER,
            start_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            end_date TIMESTAMP,
            is_active INTEGER DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(user_id),
            FOREIGN KEY (game_id) REFERENCES games(game_id)
        );

        CREATE TABLE IF NOT EXISTS library (
            library_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            game_id INTEGER,
            date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            type TEXT NOT NULL CHECK(type IN ('buy', 'rent')),
            expiry_date TIMESTAMP NULL,
            FOREIGN KEY (user_id) REFERENCES users(user_id),
            FOREIGN KEY (game_id) REFERENCES games(game_id)
        );

        CREATE TABLE IF NOT EXISTS purchases (
            purchase_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            purchase_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            total_amount REAL,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        );

        CREATE TABLE IF NOT EXISTS news_articles (
            article_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT NOT NULL,
            content TEXT NOT NULL,      -- Encrypted at rest using ECC
            image_path TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        );
    `);
};

initSchema();

const { encryptUserData, decryptUserData } = require('../services/keyManager');

// Migration & Seed Admin User
const seedAdminUser = () => {
    try {
        // Migration: add role column if missing in existing table
        try {
            db.exec("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user';");
        } catch (e) {
            // Column already exists or newly created
        }

        // Fetch all users and check decrypted email / username
        const stmt = db.prepare("SELECT * FROM users");
        const allUsers = stmt.all();

        let adminUser = allUsers.find(u => {
            const decUser = u.username ? decryptUserData(u.username) : u.username;
            const decEmail = u.email ? decryptUserData(u.email) : u.email;
            return decUser === 'admin' || decEmail === 'nfmanik@icloud.com';
        });

        const salt = bcrypt.genSaltSync(10);
        const hashedPassword = bcrypt.hashSync('crypto', salt);

        const encUsername = encryptUserData('admin');
        const encEmail = encryptUserData('nfmanik@icloud.com');
        const encAddress = encryptUserData('HQ, California, USA');
        const encPhone = encryptUserData('+1800-ADMIN');

        if (!adminUser) {
            const insertStmt = db.prepare(`
                INSERT INTO users (username, email, password, address, phone, role)
                VALUES (?, ?, ?, ?, ?, 'admin')
            `);
            insertStmt.run(encUsername, encEmail, hashedPassword, encAddress, encPhone);
            console.log('Admin account created successfully with RSA encryption (admin / nfmanik@icloud.com / crypto)');
        } else {
            const updateStmt = db.prepare(`
                UPDATE users SET username = ?, email = ?, password = ?, address = ?, phone = ?, role = 'admin' WHERE user_id = ?
            `);
            updateStmt.run(encUsername, encEmail, hashedPassword, encAddress, encPhone, adminUser.user_id);
            console.log('Admin account updated with RSA encryption');
        }
    } catch (err) {
        console.error('Error seeding admin user:', err);
    }
};

seedAdminUser();

// Helper to run query matching mysql2 promise interface [rows/result, fields]
const query = async (sql, params = []) => {
    const trimmed = sql.trim();
    const isReadQuery = /^\s*(SELECT|PRAGMA|WITH)\b/i.test(trimmed);

    if (isReadQuery) {
        const stmt = db.prepare(sql);
        const rows = stmt.all(...params);
        return [rows, []];
    } else {
        const stmt = db.prepare(sql);
        const res = stmt.run(...params);
        const result = {
            insertId: Number(res.lastInsertRowid),
            affectedRows: res.changes
        };
        return [result, []];
    }
};

const execute = async (sql, params = []) => {
    return query(sql, params);
};

const getConnection = async () => {
    return {
        query: (sql, params) => query(sql, params),
        execute: (sql, params) => execute(sql, params),
        beginTransaction: async () => {
            db.exec('BEGIN TRANSACTION');
        },
        commit: async () => {
            db.exec('COMMIT');
        },
        rollback: async () => {
            db.exec('ROLLBACK');
        },
        release: () => {}
    };
};

module.exports = {
    db,
    query,
    execute,
    getConnection
};
