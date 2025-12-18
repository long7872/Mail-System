const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const pool = require('./db/connection.promise');

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

// Import routes
const authRoutes = require('./routes/auth.routes');
const userRoutes = require('./routes/user.routes');
const emailRoutes = require('./routes/email.routes');
const systemRoutes = require('./routes/system.routes');

// Use routes
app.use('/auth', authRoutes);
app.use('/user', userRoutes);
app.use('/email', emailRoutes);
app.use('/system', systemRoutes);

// Default route
app.get('/', (req, res) => {
  res.send('📧 Email App Server is running!');
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
