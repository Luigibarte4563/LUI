const express = require('express');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

const app = express();
app.use(helmet());
app.use(express.json());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});
app.use('/api/', limiter);

const SALT_ROUNDS = 12;

// Secure password hashing
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hash = await bcrypt.hash(password, SALT_ROUNDS);
  // Store user with hash
  res.json({ success: true });
});

// Parameterized query
app.get('/api/users/:id', async (req, res) => {
  const userId = parseInt(req.params.id, 10);
  if (isNaN(userId)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }
  // Use parameterized query
  db.query('SELECT id, username, email FROM users WHERE id = ?', [userId], (err, results) => {
    if (err) {
      console.error('Database error');
      return res.status(500).json({ error: 'Internal server error' });
    }
    res.json(results[0] || null);
  });
});

// Secure JWT with expiration
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRY = '1h';

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  // Verify user...
  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: JWT_EXPIRY });
  res.cookie('token', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
  });
  res.json({ success: true });
});

// Secure CORS
app.use((req, res, next) => {
  const allowedOrigins = ['https://example.com'];
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', true);
  }
  next();
});

// Input validation
const { body, validationResult } = require('express-validator');
app.post('/api/data',
  body('email').isEmail(),
  body('name').isLength({ min: 1, max: 100 }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    res.json({ success: true });
  }
);

// Secure error handling
app.use((err, req, res, next) => {
  console.error('Error:', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(3000, () => {
  console.log('Server running');
});
