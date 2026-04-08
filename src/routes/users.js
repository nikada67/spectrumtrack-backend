// src/routes/users.js — User management routes
const router = require('express').Router();
const bcrypt = require('bcryptjs');
const pool   = require('../db/pool');
const { requireAuth, requireRole, auditLog } = require('../middleware/auth');

router.use(requireAuth);

// ── GET /api/users ────────────────────────────────────────────────────────────
// Admins see all users in org; others see only themselves
router.get('/', auditLog('VIEW'), async (req, res) => {
  try {
    if (!['admin', 'bcba'].includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    const [rows] = await pool.execute(
      `SELECT id, name, email, role, last_login, created_at
       FROM users
       WHERE organization_id = ?
       ORDER BY name`,
      [req.user.organizationId]
    );
    return res.json(rows);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// ── GET /api/users/:id ────────────────────────────────────────────────────────
router.get('/:id', auditLog('VIEW'), async (req, res) => {
  try {
    // Users can only see their own profile unless admin/bcba
    const targetId = parseInt(req.params.id);
    if (!['admin', 'bcba'].includes(req.user.role) && req.user.id !== targetId) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const [rows] = await pool.execute(
      `SELECT id, name, email, role, preferences, last_login, created_at
       FROM users
       WHERE id = ? AND organization_id = ?`,
      [targetId, req.user.organizationId]
    );
    if (!rows[0]) return res.status(404).json({ error: 'User not found' });
    return res.json(rows[0]);
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
});

// ── POST /api/users — Create a new user (admin only) ─────────────────────────
router.post('/', requireRole(['admin']), auditLog('CREATE'), async (req, res) => {
  const { name, email, password, role } = req.body;

  if (typeof name !== 'string' || typeof email !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'name, email, and password must be strings' });
  }
  if (!name.trim() || !email.trim() || !password) {
    return res.status(400).json({ error: 'name, email, and password are required' });
  }
  if (password.length < 8 || password.length > 128) {
    return res.status(400).json({ error: 'Password must be 8–128 characters' });
  }

  const validRoles = ['admin', 'bcba', 'teacher', 'aide', 'parent'];
  if (!validRoles.includes(role)) {
    return res.status(400).json({ error: `role must be one of: ${validRoles.join(', ')}` });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12);

    const [result] = await pool.execute(
      `INSERT INTO users (organization_id, name, email, password_hash, role)
       VALUES (?, ?, ?, ?, ?)`,
      [req.user.organizationId, name.trim(), email.toLowerCase().trim(), passwordHash, role]
    );
    return res.status(201).json({ id: result.insertId, message: 'User created' });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Email already in use' });
    }
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// ── PATCH /api/users/:id ──────────────────────────────────────────────────────
// Users can update their own name/preferences; admins can change role too
router.patch('/:id', auditLog('UPDATE'), async (req, res) => {
  const targetId = parseInt(req.params.id);
  const isSelf   = req.user.id === targetId;
  const isAdmin  = req.user.role === 'admin';

  if (!isSelf && !isAdmin) {
    return res.status(403).json({ error: 'Access denied' });
  }

  const fields = [];
  const values = [];

  if (req.body.name && typeof req.body.name === 'string') {
    fields.push('name = ?');
    values.push(req.body.name.trim());
  }
  if (req.body.preferences !== undefined) {
    fields.push('preferences = ?');
    values.push(JSON.stringify(req.body.preferences));
  }
  // Only admins can change roles
  if (isAdmin && req.body.role) {
    const validRoles = ['admin', 'bcba', 'teacher', 'aide', 'parent'];
    if (!validRoles.includes(req.body.role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }
    fields.push('role = ?');
    values.push(req.body.role);
  }
  // Password change — requires current_password if self
  if (req.body.new_password) {
    if (req.body.new_password.length < 8 || req.body.new_password.length > 128) {
      return res.status(400).json({ error: 'Password must be 8–128 characters' });
    }
    if (isSelf) {
      if (!req.body.current_password) {
        return res.status(400).json({ error: 'current_password required to change password' });
      }
      const [rows] = await pool.execute('SELECT password_hash FROM users WHERE id = ?', [targetId]);
      const valid  = await bcrypt.compare(req.body.current_password, rows[0]?.password_hash || '');
      if (!valid) return res.status(401).json({ error: 'Current password is incorrect' });
    }
    fields.push('password_hash = ?');
    values.push(await bcrypt.hash(req.body.new_password, 12));
  }

  if (fields.length === 0) {
    return res.status(400).json({ error: 'No valid fields to update' });
  }

  values.push(targetId, req.user.organizationId);

  try {
    const [result] = await pool.execute(
      `UPDATE users SET ${fields.join(', ')} WHERE id = ? AND organization_id = ?`,
      values
    );
    if (result.affectedRows === 0) return res.status(404).json({ error: 'User not found' });
    return res.json({ message: 'User updated' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// ── DELETE /api/users/:id (admin only) ────────────────────────────────────────
router.delete('/:id', requireRole(['admin']), auditLog('DELETE'), async (req, res) => {
  if (parseInt(req.params.id) === req.user.id) {
    return res.status(400).json({ error: 'Cannot delete your own account' });
  }
  try {
    const [result] = await pool.execute(
      'DELETE FROM users WHERE id = ? AND organization_id = ?',
      [req.params.id, req.user.organizationId]
    );
    if (result.affectedRows === 0) return res.status(404).json({ error: 'User not found' });
    return res.json({ message: 'User deleted' });
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
});

// ── POST /api/users/:id/assign/:studentId ─────────────────────────────────────
// Assign a user to a student (admin/bcba only)
router.post('/:id/assign/:studentId', requireRole(['admin', 'bcba']), async (req, res) => {
  try {
    await pool.execute(
      `INSERT IGNORE INTO student_assignments (student_id, user_id) VALUES (?, ?)`,
      [req.params.studentId, req.params.id]
    );
    return res.json({ message: 'Assignment created' });
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
});

// ── DELETE /api/users/:id/assign/:studentId ───────────────────────────────────
router.delete('/:id/assign/:studentId', requireRole(['admin', 'bcba']), async (req, res) => {
  try {
    await pool.execute(
      'DELETE FROM student_assignments WHERE student_id = ? AND user_id = ?',
      [req.params.studentId, req.params.id]
    );
    return res.json({ message: 'Assignment removed' });
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;