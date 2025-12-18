import express from "express";
const db = require("../db/connection.promise");

const app = express();
app.use(express.json());





app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
