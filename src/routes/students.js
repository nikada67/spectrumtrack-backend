// src/routes/students.js
const router = require('express').Router();
const pool   = require('../db/pool');
const { requireAuth, requireRole, auditLog } = require('../middleware/auth');

// All student routes require a valid token
router.use(requireAuth);

// ── GET /api/students ─────────────────────────────────────────────────────────
// Returns only students assigned to the logged-in user (role-scoped)
// Admins, BCBAs & teachers see all students in their org
router.get('/', auditLog('VIEW'), async (req, res) => {
  try {
    const { id: userId, role, organizationId } = req.user;

    let rows;
    if (['admin', 'bcba', 'teacher'].includes(role)) {
      [rows] = await pool.execute(
        `SELECT s.*,
          (SELECT COUNT(*) FROM behavior_logs bl WHERE bl.student_id = s.id
           AND DATE(bl.start_time) = CURDATE()) AS logs_today,
          (SELECT MAX(bl2.start_time) FROM behavior_logs bl2 WHERE bl2.student_id = s.id) AS last_log_time
         FROM students s
         WHERE s.organization_id = ?
         ORDER BY s.first_name`,
        [organizationId]
      );
    } else {
      // Aides & parents see only their assigned students
      [rows] = await pool.execute(
        `SELECT s.*,
          (SELECT COUNT(*) FROM behavior_logs bl WHERE bl.student_id = s.id
           AND DATE(bl.start_time) = CURDATE()) AS logs_today,
          (SELECT MAX(bl2.start_time) FROM behavior_logs bl2 WHERE bl2.student_id = s.id) AS last_log_time
         FROM students s
         JOIN student_assignments sa ON sa.student_id = s.id
         WHERE sa.user_id = ? AND s.organization_id = ?
         ORDER BY s.first_name`,
        [userId, organizationId]
      );
    }

    return res.json(rows);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// ── GET /api/students/:id ─────────────────────────────────────────────────────
router.get('/:id', auditLog('VIEW'), async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT s.* FROM students s WHERE s.id = ? AND s.organization_id = ?`,
      [req.params.id, req.user.organizationId]
    );
    if (!rows[0]) return res.status(404).json({ error: 'Student not found' });

    // Parents: enforce assignment check
    if (req.user.role === 'parent') {
      const [assigned] = await pool.execute(
        'SELECT 1 FROM student_assignments WHERE student_id = ? AND user_id = ?',
        [req.params.id, req.user.id]
      );
      if (!assigned[0]) return res.status(403).json({ error: 'Access denied' });
    }

    return res.json(rows[0]);
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
});

// ── POST /api/students ────────────────────────────────────────────────────────
router.post('/', requireRole(['admin', 'bcba', 'teacher']), async (req, res) => {
  const { first_name, last_name, date_of_birth, iep_goals, behavior_plan, sensory_profile, reinforcers } = req.body;

  // FIX: type validation to prevent SQL errors from bad input types
  if (typeof first_name !== 'string' || typeof last_name !== 'string') {
    return res.status(400).json({ error: 'first_name and last_name must be strings' });
  }
  if (!first_name.trim() || !last_name.trim()) {
    return res.status(400).json({ error: 'first_name and last_name required' });
  }

  try {
    const [result] = await pool.execute(
      `INSERT INTO students (organization_id, first_name, last_name, date_of_birth, iep_goals, behavior_plan, sensory_profile, reinforcers)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        req.user.organizationId,
        first_name.trim(),
        last_name.trim(),
        date_of_birth || null,
        iep_goals       ? JSON.stringify(iep_goals)       : null,
        behavior_plan   ? JSON.stringify(behavior_plan)   : null,
        sensory_profile ? JSON.stringify(sensory_profile) : null,
        reinforcers     ? JSON.stringify(reinforcers)     : null,
      ]
    );
    return res.status(201).json({ id: result.insertId, message: 'Student created' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// ── PATCH /api/students/:id ───────────────────────────────────────────────────
// FIX: Replaced PUT with PATCH so only fields present in body are updated.
// This avoids the COALESCE bug where you couldn't clear a nullable field.
router.patch('/:id', requireRole(['admin', 'bcba', 'teacher']), auditLog('UPDATE'), async (req, res) => {
  const allowed = ['first_name', 'last_name', 'date_of_birth', 'iep_goals', 'behavior_plan', 'sensory_profile', 'reinforcers'];
  const jsonFields = ['iep_goals', 'behavior_plan', 'sensory_profile', 'reinforcers'];

  const fields = [];
  const values = [];

  for (const key of allowed) {
    if (Object.prototype.hasOwnProperty.call(req.body, key)) {
      fields.push(`${key} = ?`);
      const val = req.body[key];
      values.push(jsonFields.includes(key) && val !== null ? JSON.stringify(val) : val);
    }
  }

  if (fields.length === 0) {
    return res.status(400).json({ error: 'No valid fields to update' });
  }

  values.push(req.params.id, req.user.organizationId);

  try {
    const [result] = await pool.execute(
      `UPDATE students SET ${fields.join(', ')} WHERE id = ? AND organization_id = ?`,
      values
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Student not found' });
    }
    return res.json({ message: 'Student updated' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// ── DELETE /api/students/:id ──────────────────────────────────────────────────
router.delete('/:id', requireRole(['admin', 'bcba']), auditLog('DELETE'), async (req, res) => {
  try {
    const [result] = await pool.execute(
      'DELETE FROM students WHERE id = ? AND organization_id = ?',
      [req.params.id, req.user.organizationId]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Student not found' });
    }
    return res.json({ message: 'Student deleted' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;