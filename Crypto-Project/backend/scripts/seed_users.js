const pool = require('../db');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');
const path = require('path');

dotenv.config({ path: path.join(__dirname, '../../.env') });

const seedUsers = async () => {
    try {
        console.log('Connected to database. Seeding users...');

        const salt = await bcrypt.genSalt(10);
        const password = await bcrypt.hash('123', salt); // Default password for all
        
        const users = [
            ['naurose', 'naurose@bracu.ac.bd', password, 'LA, California, USA', '+8801755577770'],
            ['anik', 'anik@x.com', password, 'Nevada, CA', '+15566737828'],
            ['retro', 'retro@x.com', password, 'Austin, Texas, USA', '+1555-0103']
        ];

        for (const user of users) {
             await pool.execute(
                'INSERT OR IGNORE INTO users (username, email, password, address, phone) VALUES (?, ?, ?, ?, ?)',
                user
            );
        }

        console.log('Users seeded successfully!');

    } catch (err) {
        console.error('Error seeding users:', err);
    }
};

seedUsers();
