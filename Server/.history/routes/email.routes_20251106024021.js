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
router.get('/public_key', auth, async (req, res) => {
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
	const { to, ciphertext } = req.body;

	try {
		if (!to || !ciphertext) {
            return res.status(400).json({ message: "Missing fields." });
        }

		// 1) Get recipient user
        const [rows] = await pool.execute("SELECT id FROM users WHERE email = ?", [to]);

		// Get sender keys
		const [[senderKey]] = await pool.query(
		'SELECT public_key, private_key_encrypted FROM user_keys WHERE user_id = ?',
		[req.user.id]
		);

		if (!senderKey) return res.status(400).json({ message: 'Sender key not found' });


		// Get recipient public key
		const [[recipientKey]] = await pool.query(
		'SELECT u.id AS recipient_id, k.public_key FROM users u JOIN user_keys k ON u.id = k.user_id WHERE u.email = ?',
		[recipientEmail]
		);
		if (!recipientKey) return res.status(404).json({ message: 'Recipient not found' });

		// 🔏 Sign message
		// const privateKeyPem = forge.pki.privateKeyFromPem(
		// 	forge.pki.privateKeyToPem(
		// 		forge.pki.privateKeyFromPem(
		// 			forge.pki.privateKeyToPem(forge.pki.privateKeyFromPem(''))
		// 		)
		// 	)
		// );
		// Decrypt private key encrypted with AES-CBC + PBKDF2
		const encryptedBytes = forge.util.decode64(senderKey.private_key_encrypted);
		
		// Get salt (16 bytes), iv (16 bytes), and ciphertext (the rest)
		const salt = encryptedBytes.slice(0, 16);
		const iv = encryptedBytes.slice(16, 32);
		const ciphertext = encryptedBytes.slice(32);

		// Derive key from password
		const derivedKey = forge.pkcs5.pbkdf2(req.user.password, salt, 10000, 32);

		// Create decipher
		const decipher = forge.cipher.createDecipher('AES-CBC', derivedKey);
		decipher.start({ iv });
		decipher.update(forge.util.createBuffer(ciphertext));
		const success = decipher.finish();

		if (!success) {
			return res.status(400).json({ message: 'Failed to decrypt private key' });
		}

		const decryptedPrivateKeyPem = decipher.output.toString('utf8');

		// Parse PEM to create key object
		const privateKey = forge.pki.privateKeyFromPem(decryptedPrivateKeyPem);

		const md = forge.md.sha256.create();
		md.update(content, 'utf8');
		const signature = forge.util.encode64(privateKey.sign(md));

		// 🔐 Encrypt for recipient
		const recipientPublic = forge.pki.publicKeyFromPem(recipientKey.public_key);
		const encryptedContent = forge.util.encode64(recipientPublic.encrypt(content, 'RSA-OAEP'));

		await pool.query(
		'INSERT INTO emails (sender_id, recipient_id, subject, content, signature, is_encrypted) VALUES (?, ?, ?, ?, ?, ?)',
		[req.user.id, recipientKey.recipient_id, subject, encryptedContent, signature, true]
		);

		res.json({ message: 'Email sent & encrypted!' });
	} catch (err) {
		console.error(err);
		res.status(500).json({ message: 'Error sending email' });
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
