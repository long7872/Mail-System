// routes/email.routes.js
const express = require('express');
const forge = require('node-forge');
const pool = require('../db/connection.promise');
const jwt = require('jsonwebtoken');

const router = express.Router();

// Auth middleware
function auth(req, res, next) {
	const header = req.headers.authorization;
	if (!header) return res.status(401).json({ message: 'No token' });
	try {
		const token = header.split(' ')[1];
		req.user = jwt.verify(token, process.env.JWT_SECRET);
		next();
	} catch {
		return res.status(401).json({ message: 'Invalid token' });
	}
}

// Get Public Key from Email
router.get('/public_key', async (req, res) => {
    const { email } = req.query;
    if (!email)
        return res.status(400).json({ message: 'Missing email' });

    try {
        const [rows] = await pool.query(
            'SELECT public_key FROM users WHERE email = ?',
            [email]
        );

        if (rows.length === 0)
            return res.status(404).json({ message: 'User not found' });

        res.json({ public_key: rows[0].public_key });

    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

// Send email (sign + encrypt)
router.post('/send', auth, async (req, res) => {
	const senderId = req.user.id;
	const { to, encrypted_key, ciphertext, iv } = req.body;

	try {
		if (!to || !encrypted_key || !ciphertext || !iv) {
            return res.status(400).json({ message: "Missing fields." });
        }

		// 1) Get recipient user
        const [rows] = await pool.query(
			"SELECT id FROM users WHERE email = ?", 
			[to]
		);
		if (rows.length === 0) {
            return res.status(404).json({ message: "Recipient not found." });
        }

		const recipientId = rows[0].id;

		// 2) Insert encrypted email (subject is placeholder)
        await pool.query(
            `INSERT INTO emails (sender_id, recipient_id, encrypted_key, ciphertext, iv)
             VALUES (?, ?, ?, ?, ?)`,
            [senderId, recipientId, encrypted_key, ciphertext, iv]
        );

		return res.status(201).json({ message: "Encrypted email stored successfully." });

	} catch (err) {
		console.error("Email send error:", err);
		return res.status(500).json({ message: "Internal server error." });
	}
});

// Get received emails (decrypt)
router.get('/inbox', auth, async (req, res) => {
	try {
		const [emails] = await pool.query(
		'SELECT e.*, u.username AS sender_name, u.email AS sender_email FROM emails e JOIN users u ON e.sender_id = u.id WHERE recipient_id = ? ORDER BY e.created_at DESC',
		[req.user.id]
		);
		res.json(emails);
	} catch (err) {
		console.error(err);
		res.status(500).json({ message: 'Error fetching inbox' });
	}
});

module.exports = router;
