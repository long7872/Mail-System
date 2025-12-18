// routes/email.routes.js
const express = require('express');
const forge = require('node-forge');
const pool = require('../db/connection.promise');
const jwt = require('jsonwebtoken');
const axios = require("axios");

const EmailStatus = require("../enums/emailStatus");
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

// Send email (sign + encrypt)
router.post('/send', auth, async (req, res) => {
	const senderId = req.user.id;
	const { to, encrypted_key_sender, encrypted_key_recipient, encrypted_key_ml, ciphertext, iv } = req.body;

	try {
		if (!to || !encrypted_key_sender || !encrypted_key_recipient || !ciphertext || !iv) {
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

		// 2) Insert encrypted email
        const [result] = await pool.query(
            `INSERT INTO emails (sender_id, recipient_id, encrypted_key_sender, encrypted_key_recipient, encrypted_key_ml, ciphertext, iv)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [senderId, recipientId, encrypted_key_sender, encrypted_key_recipient, encrypted_key_ml,ciphertext, iv]
        );

		console.log("SERVER encrypted_key_sender:", encrypted_key_sender);
		console.log("SERVER encrypted_key_recipient:", encrypted_key_recipient);
		console.log("SERVER encrypted_key_ml:", encrypted_key_ml);
		console.log("SERVER iv:", iv);

		let email = {
			id: result.insertId,
			to,
			encrypted_key_sender,
			encrypted_key_recipient,
			encrypted_key_ml,
			ciphertext,
			iv,
			ml_scan_status: "PENDING",
			ml_spam_result: "null",
			ml_spam_score: "null",
			ml_sentiment_result: "null",
			ml_sentiment_score: "null",
		}
		// 3) Call ML service async (non-blocking)
		try {
			const response = await axios.post("http://localhost:3001/scan", {
				email_id: result.insertId,
				encrypted_key_ml,
				ciphertext,
				iv
			});

			const { 
                spam_ham,
                spam_score,
                sentiment,
                sentiment_score,
            } = response.data;
			console.log("ML data: ", response.data);

			// cập nhật DB
			await pool.query(
				`UPDATE emails
				SET ml_scan_status = ?, ml_spam_result = ?, ml_spam_score = ?, ml_sentiment_result = ?, ml_sentiment_score = ?
				WHERE id = ?`,
				[EmailStatus.SCANNED, spam_ham, spam_score, sentiment, sentiment_score, result.insertId]
			);

			// Update 
			email = {
				...email,
				ml_scan_status: "SCANNED",
				ml_spam_result: spam_ham,
				ml_spam_score: spam_score.toString(),
				ml_sentiment_result: sentiment,
				ml_sentiment_score: sentiment_score.toString(),
			};

		} catch (err) {
			console.error("ML Service scan failed:", err.message);

			// CALLBACK CŨNG CÓ ASYNC
			await pool.query(
				`UPDATE emails SET ml_scan_status = ? WHERE id = ?`,
				[EmailStatus.FAILED, result.insertId]
			);

			// Set email scan failed
			email.ml_scan_status = EmailStatus.FAILED;
		}

		return res.status(201).json({ 
			message: "Encrypted email stored successfully.",
			email: email
		});

	} catch (err) {
		console.error("Email send error:", err);
		return res.status(500).json({ message: "Internal server error." });
	}
});

// Get received emails (decrypt)
router.get('/received', auth, async (req, res) => {
	try {
		const userId = req.user.id;
		const { email } = req.query;

		const [rows] = await pool.query(
            `SELECT e.id, u.email AS sender_email, e.encrypted_key_recipient, e.ciphertext, e.iv, e.created_at
             FROM emails e
             JOIN users u ON e.sender_id = u.id
             WHERE e.recipient_id = ?
             ORDER BY e.created_at DESC`,
            [userId]
        );

		return res.status(200).json(rows);
	} catch (err) {
		console.error("Inbox load error:", err);
        return res.status(500).json({ message: "Internal server error." });
	}
});

router.get('/sent', auth, async (req, res) => {
    try {
        const userId = req.user.id;

        const [rows] = await pool.query(
            `SELECT e.id, u.email AS recipient_email, e.encrypted_key_sender, e.ciphertext, e.iv, e.created_at
             FROM emails e
             JOIN users u ON e.recipient_id = u.id
             WHERE e.sender_id = ?
             ORDER BY e.created_at DESC`,
            [userId]
        );

        return res.status(200).json(rows);

    } catch (err) {
        console.error("Sent load error:", err);
        return res.status(500).json({ message: "Internal server error." });
    }
});


module.exports = router;
