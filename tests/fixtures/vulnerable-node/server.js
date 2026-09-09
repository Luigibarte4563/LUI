const express = require('express');
const jwt = require('jsonwebtoken');
const mysql = require('mysql');
const bcrypt = require('bcrypt');

const app = express();
const SECRET_KEY = 'super_secret_key_12345';
const JWT_SECRET = 'my_jwt_secret_key';

// Hardcoded credentials
const DB_PASSWORD = 'admin123';
const API_KEY = 'FAKE_API_KEY_FOR_TESTING_ONLY';

app.use(express.json());

// SQL Injection vulnerability
app.get('/api/users', (req, res) => {
  const userId = req.query.id;
  const query = 'SELECT * FROM users WHERE id = ' + userId;
  db.query(query, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});

// XSS vulnerability
app.get('/search', (req, res) => {
  const searchTerm = req.query.q;
  res.send('<h1>Results for: ' + searchTerm + '</h1>');
});

// Command injection
app.get('/ping', (req, res) => {
  const host = req.query.host;
  const { exec } = require('child_process');
  exec('ping -c 4 ' + host, (err, stdout) => {
    res.send(stdout);
  });
});

// Weak password hashing
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const crypto = require('crypto');
  const hash = crypto.createHash('md5').update(password).digest('hex');
  // Store user
  res.json({ success: true });
});

// JWT without expiration
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  // Verify user...
  const token = jwt.sign({ username }, JWT_SECRET);
  res.json({ token });
});

// Token in localStorage (frontend pattern logged)
console.log('Frontend stores token in localStorage');

// Missing authorization check
app.get('/api/admin/users', (req, res) => {
  // No auth check
  db.query('SELECT * FROM users', (err, results) => {
    res.json(results);
  });
});

// CORS wildcard with credentials
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Credentials', true);
  next();
});

// Debug mode enabled
const DEBUG = true;

// Sensitive data in logs
app.post('/auth/login', (req, res) => {
  console.log('Login attempt with password:', req.body.password);
  res.json({ success: true });
});

// Path traversal
const fs = require('fs');
app.get('/file', (req, res) => {
  const filePath = req.query.path;
  const content = fs.readFileSync(filePath, 'utf-8');
  res.send(content);
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
