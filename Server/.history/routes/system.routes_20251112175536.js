// routes/system.routes.js
const express = require('express');
const pool = require('../db/connection.promise');

const router = express.Router();

router.get('/public_key', async (req, res) => {
	const { service } = req.query;

	if (!service)
		return res.status(400).json({ message: "Missing service name" });

	try {
		const [rows] = await pool.query(
			"SELECT public_key FROM system_keys WHERE service_name = ?",
			[service]
		);

		if (rows.length === 0)
			return res.status(404).json({ message: "Service not found" });

		return res.json({ public_key: rows[0].public_key });

	} catch (err) {
		console.error("System key fetch error:", err);
		return res.status(500).json({ message: "Internal server error" });
	}
});

module.exports = router;
