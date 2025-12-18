// routes/auth.routes.js
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const forge = require('node-forge');
const pool = require('../db/connection.promise');

const router = express.Router();

// ✅ Signup: create user + generate RSA keypair
router.post('/signup', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password)
        return res.status(400).json({ message: 'Missing fields' });

    try {
        const [existing] = await pool.query(
        'SELECT id FROM users WHERE email = ?',
        [email]
        );
        if (existing.length > 0)
        return res.status(400).json({ message: 'User already exists' });

        const password_hash = await bcrypt.hash(password, 10);

        const [result] = await pool.query(
        'INSERT INTO users (email, password_hash) VALUES (?, ?)',
        [email, password_hash]
        );
        const user_id = result.insertId;

        // 🔐 Generate RSA keypair
        const keypair = forge.pki.rsa.generateKeyPair(2048);
        const publicPem = forge.pki.publicKeyToPem(keypair.publicKey);
        const privatePem = forge.pki.privateKeyToPem(keypair.privateKey);

        // Encrypt private key with user password
        // const privateEncrypted = forge.util.encode64(
        //   forge.pbe.encrypt(privatePem, password, {
        //     algorithm: 'aes256',
        //     count: 10000,
        //     saltSize: 16
        //   })
        // );

        // Generate random salt and derive key from password
        const salt = forge.random.getBytesSync(16);
        // 32 bytes for AES-256
        const derivedKey = forge.pkcs5.pbkdf2(password, salt, 10000, 32);

        // Create IV (initialization vector)
        const iv = forge.random.getBytesSync(16);

        // Encrypt private key using AES-CBC
        const cipher = forge.cipher.createCipher('AES-CBC', derivedKey);
        cipher.start({ iv });
        cipher.update(forge.util.createBuffer(privatePem, 'utf8'));
        cipher.finish();

        // Combine salt + iv + ciphertext to save
        const encryptedData = forge.util.encode64(salt + iv + cipher.output.getBytes());

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

        res.json({ token });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

module.exports = router;
