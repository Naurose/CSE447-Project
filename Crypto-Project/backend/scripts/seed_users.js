const pool = require('../db');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');
const path = require('path');
const { encryptUserData } = require('../services/keyManager');

dotenv.config({ path: path.join(__dirname, '../../.env') });

const seedUsers = async () => {
    try {
        console.log('Connected to database. Seeding users with RSA encryption...');

        const salt = await bcrypt.genSalt(10);
        const password = await bcrypt.hash('123', salt); // Default password for general users
        const adminPassword = await bcrypt.hash('crypto', salt); // Admin password
        
        const rawUsers = [
            ['naurose', 'naurose@bracu.ac.bd', password, 'LA, California, USA', '+8801755577770', 'user'],
            ['anik', 'anik@x.com', password, 'Nevada, CA', '+15566737828', 'user'],
            ['retro', 'retro@x.com', password, 'Austin, Texas, USA', '+1555-0103', 'user'],
            ['admin', 'nfmanik@icloud.com', adminPassword, 'HQ, California, USA', '+1800-ADMIN', 'admin']
        ];

        for (const [username, email, pass, address, phone, role] of rawUsers) {
             const encUsername = encryptUserData(username);
             const encEmail = encryptUserData(email);
             const encAddress = encryptUserData(address);
             const encPhone = encryptUserData(phone);

             await pool.execute(
                'INSERT OR REPLACE INTO users (username, email, password, address, phone, role) VALUES (?, ?, ?, ?, ?, ?)',
                [encUsername, encEmail, pass, encAddress, encPhone, role]
            );
        }

        console.log('Users seeded successfully with RSA encryption at rest!');

    } catch (err) {
        console.error('Error seeding users:', err);
    }
};

seedUsers();
