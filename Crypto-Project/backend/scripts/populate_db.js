const axios = require('axios');
const pool = require('../db');
const dotenv = require('dotenv');
const path = require('path');

dotenv.config({ path: path.join(__dirname, '../../.env') });

const populateGames = async () => {
    const API_KEY = process.env.RAWG_API_KEY; // this is in .env
    if (!API_KEY) {
        console.error('RAWG_API_KEY is missing in .env file');
        process.exit(1);
    }

    try {
        console.log('Connected to database. Cleaning old data...');
        
        // Clear existing data when running seed-games to avoid repeated seeding
        await pool.query('PRAGMA foreign_keys = OFF');
        await pool.query('DELETE FROM games');
        await pool.query('DELETE FROM cart');
        await pool.query('DELETE FROM library');
        await pool.query('DELETE FROM reviews');
        await pool.query('DELETE FROM rentals');
        await pool.query('PRAGMA foreign_keys = ON');
        console.log('Old data cleared.');

        console.log('Fetching games from RAWG...');

        // Fetches 320 games (8 pages * 40 per page from rawg api catalog template; code from apidocs)
        const games = [];
        console.log('Fetching 320 games from RAWG (this may take a moment)...');
        for (let page = 1; page <= 8; page++) {
            try {
                const response = await axios.get(`https://api.rawg.io/api/games?key=${API_KEY}&page_size=40&page=${page}`);
                games.push(...response.data.results);
                console.log(`Fetched page ${page}/8...`);
            } catch (e) {
                console.error(`Failed to fetch page ${page}: ${e.message}`);
            }
        }

        console.log(`Fetched ${games.length} games. Inserting into database...`);

        let insertedCount = 0;
        for (const game of games) {
            // Check if game already exists to avoid duplicates when fetching from RAWG API
            const [existing] = await pool.query('SELECT game_id FROM games WHERE title = ?', [game.name]);
            if (existing.length > 0) continue;

            // Fetching Detailed Description
            let description = `Description for ${game.name}.`;
            try {
                //small delay added to solve API fetching getting stuck (hangs if without timeout)
                await new Promise(resolve => setTimeout(resolve, 150)); 
                const detailsRes = await axios.get(`https://api.rawg.io/api/games/${game.id}?key=${API_KEY}`);
                description = detailsRes.data.description_raw || detailsRes.data.description || description;
                // Truncate if too long
                if (description.length > 5000) description = description.substring(0, 5000) + '...';
            } catch (err) {
                console.warn(`Could not fetch details for ${game.name}, using default.`);
            }

            // Map RAWG data to our schema. Generating random price because free tier api
            const price = (Math.random() * (60 - 10) + 10).toFixed(2);
            const rental_price = (price * 0.1).toFixed(2); 
            
            const genre = game.genres && game.genres.length > 0 ? game.genres[0].name : 'Action';

            await pool.execute(
                `INSERT INTO games (title, price, rental_price, description, cover_image, publisher, genre, release_date, rating) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    game.name, 
                    price, 
                    rental_price, 
                    description, 
                    game.background_image, 
                    'Unknown Publisher',
                    genre, 
                    game.released, 
                    game.rating
                ]
            );
            insertedCount++;
            if (insertedCount % 10 === 0) console.log(`Inserted ${insertedCount} games...`);
        }

        console.log('Database successfully populated!');

    } catch (err) {
        console.error('Error populating database:', err);
    }
};

populateGames();
