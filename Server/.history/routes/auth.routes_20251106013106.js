// routes/auth.routes.js
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const forge = require('node-forge');
const pool = require('../db/connection.promise');

const router = express.Router();

// ✅ Signup: create user + generate RSA keypair
router.post('/signup', async (req, res) => {
    const { email, password_hash, public_key } = req.body;
    if (!email || !password_hash || !public_key)
        return res.status(400).json({ message: 'Missing fields' });

    try {
        const [existing] = await pool.query(
            'SELECT id FROM users WHERE email = ?',
            [email]
        );
        if (existing.length > 0)
        return res.status(400).json({ message: 'User already exists' });

        const [result] = await pool.query(
        'INSERT INTO users (email, password_hash, public_key) VALUES (?, ?)',
        [email, password_hash, public_key]
        );
        const user_id = result.insertId;



        await pool.query(
        'INSERT INTO user_keys (user_id, public_key, private_key_encrypted) VALUES (?, ?, ?)',
        [user_id, publicPem, encryptedData]
        );

        res.status(201).json({ message: 'User created successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

// ✅ Login: verify + JWT
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password)
        return res.status(400).json({ message: 'Missing fields' });

    try {
        const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length === 0)
        return res.status(401).json({ message: 'Invalid email or password' });

        const user = rows[0];
        const valid = await bcrypt.compare(password, user.password_hash);
        if (!valid) return res.status(401).json({ message: 'Invalid email or password' });

        const [[keys]] = await pool.query(
            'SELECT public_key, private_key_encrypted FROM user_keys WHERE user_id = ?',
            [user.id]
        );

        const token = jwt.sign(
        { id: user.id, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN || '1d' }
        );

        try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log(decoded);
        } catch (err) {
        console.error('Invalid token');
        }

        res.json({
            token,
            public_key: keys.public_key,
            private_key_encrypted: keys.private_key_encrypted
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

module.exports = router;
