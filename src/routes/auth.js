// src/routes/auth.js
const router  = require('express').Router();
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const crypto  = require('crypto');
const pool    = require('../db/pool');
const { requireAuth } = require('../middleware/auth');
 
// ── Helpers ──────────────────────────────────────────────────────────────────
 
function signAccess(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role, organizationId: user.organization_id },
    process.env.JWT_ACCESS_SECRET,
    { expiresIn: process.env.JWT_ACCESS_EXPIRES || '15m' }
  );
}
 
function signRefresh(user) {
  return jwt.sign(
    { id: user.id },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: process.env.JWT_REFRESH_EXPIRES || '7d' }
  );
}
 
// Hash the refresh token before storing (so DB breach ≠ session hijack)
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}
 
// ── POST /api/auth/login ─────────────────────────────────────────────────────
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
 
  // FIX: type validation — prevents crashes from non-string inputs
  if (typeof email !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Email and password must be strings' });
  }
 
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
 
  // FIX: bcrypt DoS protection — bcrypt is CPU-heavy on very long strings
  if (password.length > 128) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }
 
  try {
    const [rows] = await pool.execute(
      'SELECT * FROM users WHERE email = ? LIMIT 1',
      [email.toLowerCase().trim()]
    );
    const user = rows[0];
 
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
 
    // Update last_login
    await pool.execute('UPDATE users SET last_login = NOW() WHERE id = ?', [user.id]);
 
    const accessToken  = signAccess(user);
    const refreshToken = signRefresh(user);
 
    // Store hashed refresh token
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    await pool.execute(
      'INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)',
      [user.id, hashToken(refreshToken), expiresAt]
    );
 
    // Refresh token in httpOnly cookie (not accessible by JS)
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure:   process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge:   7 * 24 * 60 * 60 * 1000, // 7 days
    });
 
    return res.json({
      accessToken,
      user: {
        id:             user.id,
        name:           user.name,
        email:          user.email,
        role:           user.role,
        organizationId: user.organization_id,
      },
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});
 
// ── POST /api/auth/refresh ───────────────────────────────────────────────────
router.post('/refresh', async (req, res) => {
  const token = req.cookies?.refreshToken;
  if (!token) return res.status(401).json({ error: 'No refresh token' });
 
  try {
    const payload = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
 
    // Check token exists in DB and is not revoked
    const [rows] = await pool.execute(
      `SELECT * FROM refresh_tokens
       WHERE user_id = ? AND token_hash = ? AND revoked = FALSE AND expires_at > NOW()
       LIMIT 1`,
      [payload.id, hashToken(token)]
    );
    if (!rows[0]) return res.status(401).json({ error: 'Refresh token invalid or expired' });
 
    const [users] = await pool.execute('SELECT * FROM users WHERE id = ? LIMIT 1', [payload.id]);
    const user = users[0];
    if (!user) return res.status(401).json({ error: 'User not found' });
 
    // Rotate: revoke old token, issue new pair
    await pool.execute(
      'UPDATE refresh_tokens SET revoked = TRUE WHERE token_hash = ?',
      [hashToken(token)]
    );
 
    const newAccess  = signAccess(user);
    const newRefresh = signRefresh(user);
    const expiresAt  = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
 
    await pool.execute(
      'INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)',
      [user.id, hashToken(newRefresh), expiresAt]
    );
 
    res.cookie('refreshToken', newRefresh, {
      httpOnly: true,
      secure:   process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge:   7 * 24 * 60 * 60 * 1000,
    });
 
    return res.json({ accessToken: newAccess });
  } catch (err) {
    return res.status(401).json({ error: 'Invalid refresh token' });
  }
});
 
// ── POST /api/auth/logout ────────────────────────────────────────────────────
router.post('/logout', async (req, res) => {
  const token = req.cookies?.refreshToken;
  if (token) {
    try {
      await pool.execute(
        'UPDATE refresh_tokens SET revoked = TRUE WHERE token_hash = ?',
        [hashToken(token)]
      );
    } catch (_) {}
  }
  res.clearCookie('refreshToken');
  return res.json({ message: 'Logged out' });
});
 
// ── GET /api/auth/me ─────────────────────────────────────────────────────────
router.get('/me', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT id, name, email, role, organization_id, preferences, last_login FROM users WHERE id = ?',
      [req.user.id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'User not found' });
    return res.json(rows[0]);
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
});
 
// ── POST /api/auth/register ──────────────────────────────────────────────────
router.post('/register', async (req, res) => {
  const { firstName, lastName, email, password, role } = req.body;

  if (!firstName || !lastName || !email || !password) {
    return res.status(400).json({ error: 'All fields required' });
  }

  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }

  const validRoles = ['admin', 'bcba', 'teacher', 'aide', 'parent'];
  const userRole = validRoles.includes(role) ? role : 'aide';

  try {
    const [existing] = await pool.execute(
      'SELECT id FROM users WHERE email = ? LIMIT 1',
      [email.toLowerCase().trim()]
    );
    if (existing[0]) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const name = `${firstName} ${lastName}`;

    const [result] = await pool.execute(
      'INSERT INTO users (organization_id, name, email, password_hash, role) VALUES (?, ?, ?, ?, ?)',
      [1, name, email.toLowerCase().trim(), passwordHash, userRole]
    );

    return res.status(201).json({ message: 'Account created successfully', userId: result.insertId });
  } catch (err) {
    console.error('Register error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;