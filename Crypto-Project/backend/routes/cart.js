const express = require('express');
const pool = require('../db');

const router = express.Router();

// Get User Cart
router.get('/:userId', async (req, res) => {
    try {
        const query = `
            SELECT c.cart_id, c.quantity, c.acquisition_type, c.rent_duration, g.game_id, g.title, g.price, g.rental_price, g.cover_image 
            FROM cart c
            JOIN games g ON c.game_id = g.game_id
            WHERE c.user_id = ?
        `;
        const [cartItems] = await pool.query(query, [req.params.userId]);
        
        // Calculate rental price 
        const processedItems = cartItems.map(item => {
            if (item.acquisition_type === 'rent') {
                let multiplier = 1;
                if (item.rent_duration === 14) multiplier = 1.8;
                if (item.rent_duration === 30) multiplier = 3.5;
                
                // Override rental_price with calculated value
                item.rental_price = (parseFloat(item.rental_price) * multiplier).toFixed(2);
            }
            return item;
        });

        res.json(processedItems);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

// Add to Cart
router.post('/', async (req, res) => {
    const { userId, gameId, type, rentDuration } = req.body; // type = 'buy' or 'rent', duration = 7, 14, 30

    try {
        // Check if already in cart
        const [existing] = await pool.query(
            'SELECT * FROM cart WHERE user_id = ? AND game_id = ?', 
            [userId, gameId]
        );

        if (existing.length > 0) {
            // Update existing item to allow duration/type change 
            // (If same item selected from catalog, update the type in cart)
            const duration = (type === 'rent' && rentDuration) ? rentDuration : 7;
            
            await pool.query(
                `UPDATE cart SET acquisition_type = ?, rent_duration = ? WHERE cart_id = ?`,
                [type || 'buy', duration, existing[0].cart_id]
            );
            
            return res.json({ message: 'Cart updated' });
        }

        // Check availability in Library (Ownership/Rental)
        const [libraryItem] = await pool.query(
            'SELECT * FROM library WHERE user_id = ? AND game_id = ? ORDER BY date_added DESC LIMIT 1',
            [userId, gameId]
        );

        if (libraryItem.length > 0) {
            const item = libraryItem[0];
            const isRentalActive = item.type === 'rent' && new Date(item.expiry_date) > new Date();

            if (item.type === 'buy') {
                return res.status(400).json({ message: 'You already own this game' });
            }
            
            if (isRentalActive && (type === 'rent' || !type)) {
                 if (type === 'rent') {
                     return res.status(400).json({ message: 'You already have an active rental for this game' });
                 }
            }
        }

        const duration = (type === 'rent' && rentDuration) ? rentDuration : 7; // Default 7

        await pool.query(
            'INSERT INTO cart (user_id, game_id, acquisition_type, rent_duration) VALUES (?, ?, ?, ?)',
            [userId, gameId, type || 'buy', duration]
        );

        res.json({ message: 'Added to cart' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

// Remove from Cart
router.delete('/:cartId', async (req, res) => {
    try {
        await pool.query('DELETE FROM cart WHERE cart_id = ?', [req.params.cartId]);
        res.json({ message: 'Item removed' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

module.exports = router;
