const express = require('express');
const pool = require('../db');

const router = express.Router();

// Checkout
router.post('/checkout', async (req, res) => {
    const { userId } = req.body;

    if (!userId) return res.status(400).json({ message: 'User ID required' });

    const connection = await pool.getConnection();
    try {
        await connection.beginTransaction();

        // Get Cart Items
        const [cartItems] = await connection.query(
            'SELECT user_id, game_id, acquisition_type, rent_duration, quantity FROM cart WHERE user_id = ?', 
            [userId]
        );
        //base case: when nothing in cart
        if (cartItems.length === 0) {
            return res.status(400).json({ message: 'Cart is empty' });
        }

        let totalAmount = 0;

        // Process each item
        for (const item of cartItems) {
            // Get Game Price
            const [gameData] = await connection.query('SELECT price, rental_price, title FROM games WHERE game_id = ?', [item.game_id]);
            const game = gameData[0];
            
            let price = game.price;
            
            if (item.acquisition_type === 'rent') {
                let multiplier = 1;
                // Fetch duration from cart item (requires selecting it in query above, updated below)
                const duration = item.rent_duration || 7;
                
                if (duration === 14) multiplier = 1.8;
                if (duration === 30) multiplier = 3.5;
                
                price = (parseFloat(game.rental_price) * multiplier).toFixed(2);
            }
            
            totalAmount += parseFloat(price);

            // Calculate Expiry for Rentals
            let expiryDate = null;
            if (item.acquisition_type === 'rent') {
                const duration = item.rent_duration || 7;
                const date = new Date();
                date.setDate(date.getDate() + duration);
                expiryDate = date.toISOString().slice(0, 19).replace('T', ' ');
            }

            // Perform duplicate check before processing/confirming checkout
            const [libraryItem] = await connection.query(
                'SELECT * FROM library WHERE user_id = ? AND game_id = ? ORDER BY date_added DESC LIMIT 1',
                [userId, item.game_id]
            );

            if (libraryItem.length > 0) {
                const libItem = libraryItem[0];
                const isRentalActive = libItem.type === 'rent' && new Date(libItem.expiry_date) > new Date();

                if (libItem.type === 'buy') {
                    throw new Error(`You already own ${game.title}`);
                }
                
                if (isRentalActive && item.acquisition_type === 'rent') {
                     throw new Error(`You already have an active rental for ${game.title}`);
                }
            }
            
            // Add to Library
            await connection.query(
                `INSERT INTO library (user_id, game_id, type, expiry_date) VALUES (?, ?, ?, ?)`,
                [userId, item.game_id, item.acquisition_type, expiryDate]
            );
        }

        // Record Purchase
        await connection.query(
            'INSERT INTO purchases (user_id, total_amount) VALUES (?, ?)',
            [userId, totalAmount]
        );

        // Clear Cart
        await connection.query('DELETE FROM cart WHERE user_id = ?', [userId]);

        await connection.commit();
        res.json({ message: 'Purchase successful', total: totalAmount });
    //Error text templates    
    } catch (err) {
        await connection.rollback();
        console.error(err);
        const status = err.message.startsWith('You already') ? 400 : 500;
        res.status(status).json({ message: err.message || 'Checkout failed' });
    } finally {
        connection.release();
    }
});

module.exports = router;
