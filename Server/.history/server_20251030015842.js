import express from "express";
import pool from "./db/connection.promise.js";

const app = express();
app.use(express.json());

// 🚀 Route: Setup DB
app.get("/setup", async (req, res) => {
  try {
    await initializeDatabase();
    res.json({ message: "Database initialized successfully!" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to initialize database" });
  }
});

// ✅ Test route
app.get("/", (req, res) => {
  res.send("Email App API running ✅");
});

// Start server
const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
