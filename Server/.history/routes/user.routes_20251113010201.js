// routes/user.routes.js
const express = require('express');
const pool = require('../db/connection.promise');
const jwt = require('jsonwebtoken');

const router = express.Router();

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
router.get('/public_key', auth, async (req, res) => {
  	const userId = req.user.id;
    const { email } = req.query;
    if (!email)
        return res.status(400).json({ message: 'Missing email' });


    try {
        const [rows] = await pool.query(
            'SELECT public_key FROM users WHERE id = ?',
            [userId]
        );

        if (rows.length === 0)
            return res.status(404).json({ message: 'User not found' });

        res.json({ public_key: rows[0].public_key });

    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

// Profile info
router.get('/profile', auth, async (req, res) => {
  try {
    const [[user]] = await pool.query(
      'SELECT id, username, email, created_at FROM users WHERE id = ?',
      [req.user.id]
    );
    res.json(user);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error fetching profile' });
  }
});

// Public certificate / key
router.get('/cert/:userId', async (req, res) => {
  try {
    const [[key]] = await pool.query(
      'SELECT public_key, certificate FROM user_keys WHERE user_id = ?',
      [req.params.userId]
    );
    if (!key) return res.status(404).json({ message: 'Not found' });
    res.json(key);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error fetching certificate' });
  }
});

module.exports = router;
