// server.js
require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { randomUUID } = require('crypto');
const nodemailer = require('nodemailer');
const { DataTypes } = require('sequelize');
const sequelize = require('./db');

const app = express();
app.use(express.json());
app.use(express.static('public')); // serves /public/*

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const APP_BASE_URL = process.env.APP_BASE_URL || `http://localhost:${PORT}`;

const User = sequelize.define('User', {
  name: { type: DataTypes.STRING, allowNull: false },
  email: { type: DataTypes.STRING, allowNull: false, unique: true }, // DB-level UNIQUE index ✅
  password_hash: { type: DataTypes.STRING, allowNull: false },
  status: { type: DataTypes.ENUM('unverified','active','blocked'), defaultValue: 'unverified' },
  last_login: { type: DataTypes.DATE },
  last_activity: { type: DataTypes.DATE },
  created_at: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
  email_verify_token: { type: DataTypes.STRING },
  reset_token: { type: DataTypes.STRING, allowNull: true },
  reset_expires: { type: DataTypes.DATE, allowNull: true },
}, { tableName: 'users', timestamps: false });

sequelize.sync({ alter: true }); // creates table with UNIQUE(email) if not exists

// ---------- helpers ----------
function signToken(user) { return jwt.sign({ uid: user.id, status: user.status }, JWT_SECRET, { expiresIn: '1d' }); }

const { Resend } = require('resend');
const resend = new Resend(process.env.RESEND_API_KEY);

async function sendEmail(to, subject, html) {
  try {
    await resend.emails.send({
      from: process.env.EMAIL_FROM,
      to,
      subject,
      html
    });
  } catch (err) {
    console.error('❌ Email send failed:', err);
  }
}


async function authGuard(req, res, next) {
  try {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Not authenticated', redirectTo: '/login.html' });

    const payload = jwt.verify(token, JWT_SECRET);
    const user = await User.findByPk(payload.uid);
    if (!user) return res.status(401).json({ error: 'User not found', redirectTo: '/login.html' });
    if (user.status === 'blocked') return res.status(403).json({ error: 'Blocked', redirectTo: '/login.html' });

    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token', redirectTo: '/login.html' });
  }
}

// ---------- AUTH ----------
// REGISTER
app.post('/auth/register', async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password)
    return res.status(400).json({ error: 'Missing fields' });

  try {
    const password_hash = await bcrypt.hash(password, 10);
    const token = randomUUID();
    await User.create({
      name,
      email: email.toLowerCase(),
      password_hash,
      email_verify_token: token
    });

    const verifyLink = `${process.env.APP_BASE_URL}/auth/verify?token=${token}`;
    await sendEmail(
      email,
      'Verify your Task5 account',
      `<p>Hello ${name},</p>
       <p>Thanks for signing up! Please verify your email:</p>
       <p><a href="${verifyLink}">${verifyLink}</a></p>`
    );

    res.json({ message: 'Registration successful. Check your inbox to verify your account.' });
  } catch (err) {
    if (err.name === 'SequelizeUniqueConstraintError')
      return res.status(409).json({ error: 'Email already registered' });
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// VERIFY EMAIL
app.get('/auth/verify', async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).send('Missing token');

  const user = await User.findOne({ where: { email_verify_token: token } });
  if (!user) return res.status(400).send('Invalid or expired link');

  if (user.status === 'unverified') user.status = 'active';
  user.email_verify_token = null;
  await user.save();

  res.send(`<h3>Email verified!</h3><p>You can now <a href="/login.html">log in</a>.</p>`);
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });

  const user = await User.findOne({ where: { email: email.trim().toLowerCase() } });
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  if (user.status === 'blocked') return res.status(403).json({ error: 'Blocked' });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

  user.last_login = new Date();
  await user.save();

  const token = signToken(user);
  res.json({ token, message: 'Logged in' });
});

// REQUEST PASSWORD RESET
app.post('/auth/forgot', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email required' });

  const user = await User.findOne({ where: { email: email.toLowerCase() } });
  if (!user) return res.json({ message: 'If that account exists, a reset link has been sent.' }); // don't leak info

  const token = randomUUID();
  const expires = new Date(Date.now() + 1000 * 60 * 30); // 30 min
  user.reset_token = token;
  user.reset_expires = expires;
  await user.save();

  const resetLink = `${process.env.APP_BASE_URL}/reset.html?token=${token}`;
  await sendEmail(
    email,
    'Reset your Task5 password',
    `<p>Hello,</p>
     <p>Click the link below to reset your password (expires in 30 minutes):</p>
     <p><a href="${resetLink}">${resetLink}</a></p>`
  );

  res.json({ message: 'If that account exists, a reset link has been sent.' });
});

// RESET PASSWORD (API called by reset.html)
app.post('/auth/reset', async (req, res) => {
  const { token, password } = req.body || {};
  if (!token || !password) return res.status(400).json({ error: 'Missing data' });

  const user = await User.findOne({ where: { reset_token: token } });
  if (!user || !user.reset_expires || new Date() > user.reset_expires)
    return res.status(400).json({ error: 'Invalid or expired token' });

  user.password_hash = await bcrypt.hash(password, 10);
  user.reset_token = null;
  user.reset_expires = null;
  await user.save();

  res.json({ message: 'Password successfully reset. You may now log in.' });
});


// ---------- USERS (Protected) ----------
app.get('/api/users', authGuard, async (req, res) => {
  const sort = req.query.sort || 'last_login';
  const dir = (req.query.dir || 'desc').toLowerCase() === 'asc' ? 'ASC' : 'DESC';
  const allowed = ['name','email','status','last_login','created_at'];
  const sortCol = allowed.includes(sort) ? sort : 'last_login';

  const users = await User.findAll({ order: [[sortCol, dir], ['id','ASC']] });
  res.json(users);
});

app.patch('/api/users/block', authGuard, async (req, res) => {
  const { ids } = req.body || {};
  if (!Array.isArray(ids) || !ids.length) return res.status(400).json({ error: 'No ids' });
  await User.update({ status: 'blocked' }, { where: { id: ids } });
  res.json({ message: 'Blocked' });
});

app.patch('/api/users/unblock', authGuard, async (req, res) => {
  const { ids } = req.body || {};
  if (!Array.isArray(ids) || !ids.length) return res.status(400).json({ error: 'No ids' });
  await User.update({ status: 'active' }, { where: { id: ids } });
  res.json({ message: 'Unblocked' });
});

app.delete('/api/users', authGuard, async (req, res) => {
  const { ids } = req.body || {};
  if (!Array.isArray(ids) || !ids.length) return res.status(400).json({ error: 'No ids' });
  await User.destroy({ where: { id: ids } });
  res.json({ message: 'Deleted' });
});

app.delete('/api/users/unverified', authGuard, async (_req, res) => {
  await User.destroy({ where: { status: 'unverified' } });
  res.json({ message: 'Deleted unverified' });
});

// ---------- START ----------

// Redirect root URL to login page
app.get('/', (req, res) => {
  res.redirect('/login.html');
});

app.listen(PORT, () => {
  console.log(`Server running at ${APP_BASE_URL}`);
});
