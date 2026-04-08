// src/routes/logs.js — Behavior log routes
const router = require('express').Router();
const pool   = require('../db/pool');
const { requireAuth, requireRole, auditLog } = require('../middleware/auth');

router.use(requireAuth);

// ── GET /api/logs?student_id=&limit=&offset= ──────────────────────────────────
// Fetch behavior logs for a student. Scoped to org.
router.get('/', auditLog('VIEW'), async (req, res) => {
  const { student_id, limit = 50, offset = 0 } = req.query;

  if (!student_id) {
    return res.status(400).json({ error: 'student_id query param required' });
  }

  try {
    // Verify student belongs to org
    const [students] = await pool.execute(
      'SELECT id FROM students WHERE id = ? AND organization_id = ?',
      [student_id, req.user.organizationId]
    );
    if (!students[0]) return res.status(404).json({ error: 'Student not found' });

    // Parents: check assignment
    if (req.user.role === 'parent') {
      const [assigned] = await pool.execute(
        'SELECT 1 FROM student_assignments WHERE student_id = ? AND user_id = ?',
        [student_id, req.user.id]
      );
      if (!assigned[0]) return res.status(403).json({ error: 'Access denied' });
    }

    const [rows] = await pool.execute(
      `SELECT bl.*, u.name AS recorded_by_name
       FROM behavior_logs bl
       LEFT JOIN users u ON u.id = bl.recorded_by
       WHERE bl.student_id = ?
       ORDER BY bl.start_time DESC
       LIMIT ? OFFSET ?`,
      [student_id, parseInt(limit), parseInt(offset)]
    );

    return res.json(rows);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// ── GET /api/logs/:id ─────────────────────────────────────────────────────────
router.get('/:id', auditLog('VIEW'), async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT bl.*, u.name AS recorded_by_name
       FROM behavior_logs bl
       JOIN students s ON s.id = bl.student_id
       LEFT JOIN users u ON u.id = bl.recorded_by
       WHERE bl.id = ? AND s.organization_id = ?`,
      [req.params.id, req.user.organizationId]
    );
    if (!rows[0]) return res.status(404).json({ error: 'Log not found' });
    return res.json(rows[0]);
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
});

// ── POST /api/logs ────────────────────────────────────────────────────────────
router.post('/', async (req, res) => {
  const {
    student_id, behavior_type, intensity, start_time, end_time,
    antecedent, consequence, location, activity,
    intervention_used, intervention_successful, notes, synced_from_offline,
  } = req.body;

  if (!student_id || !behavior_type) {
    return res.status(400).json({ error: 'student_id and behavior_type are required' });
  }

  if (typeof behavior_type !== 'string') {
    return res.status(400).json({ error: 'behavior_type must be a string' });
  }

  if (intensity !== undefined && (typeof intensity !== 'number' || intensity < 1 || intensity > 5)) {
    return res.status(400).json({ error: 'intensity must be a number between 1 and 5' });
  }

  try {
    // Verify student belongs to org
    const [students] = await pool.execute(
      'SELECT id FROM students WHERE id = ? AND organization_id = ?',
      [student_id, req.user.organizationId]
    );
    if (!students[0]) return res.status(404).json({ error: 'Student not found' });

    const [result] = await pool.execute(
      `INSERT INTO behavior_logs
         (student_id, recorded_by, behavior_type, intensity, start_time, end_time,
          antecedent, consequence, location, activity,
          intervention_used, intervention_successful, notes, synced_from_offline)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        student_id,
        req.user.id,
        behavior_type,
        intensity || null,
        start_time || new Date(),
        end_time || null,
        antecedent || null,
        consequence || null,
        location || null,
        activity || null,
        intervention_used || null,
        intervention_successful !== undefined ? intervention_successful : null,
        notes || null,
        synced_from_offline || false,
      ]
    );

    // Check alert rules for this student after logging
    checkAlertRules(student_id, behavior_type, req.user.organizationId).catch(err =>
      console.error('Alert rule check failed:', err.message)
    );

    return res.status(201).json({ id: result.insertId, message: 'Log created' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// ── PATCH /api/logs/:id ───────────────────────────────────────────────────────
// Only the original recorder or admin/bcba can edit a log
router.patch('/:id', auditLog('UPDATE'), async (req, res) => {
  const allowed = ['behavior_type', 'intensity', 'end_time', 'antecedent', 'consequence',
                   'location', 'activity', 'intervention_used', 'intervention_successful', 'notes'];

  const fields = [];
  const values = [];

  for (const key of allowed) {
    if (Object.prototype.hasOwnProperty.call(req.body, key)) {
      fields.push(`${key} = ?`);
      values.push(req.body[key]);
    }
  }

  if (fields.length === 0) {
    return res.status(400).json({ error: 'No valid fields to update' });
  }

  try {
    // Verify the log exists in this org
    const [logs] = await pool.execute(
      `SELECT bl.recorded_by FROM behavior_logs bl
       JOIN students s ON s.id = bl.student_id
       WHERE bl.id = ? AND s.organization_id = ?`,
      [req.params.id, req.user.organizationId]
    );
    if (!logs[0]) return res.status(404).json({ error: 'Log not found' });

    // Only original recorder, admin, or bcba can edit
    const canEdit = ['admin', 'bcba'].includes(req.user.role) || logs[0].recorded_by === req.user.id;
    if (!canEdit) return res.status(403).json({ error: 'Cannot edit this log' });

    values.push(req.params.id);
    await pool.execute(
      `UPDATE behavior_logs SET ${fields.join(', ')} WHERE id = ?`,
      values
    );

    return res.json({ message: 'Log updated' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// ── DELETE /api/logs/:id ──────────────────────────────────────────────────────
router.delete('/:id', requireRole(['admin', 'bcba']), auditLog('DELETE'), async (req, res) => {
  try {
    const [result] = await pool.execute(
      `DELETE bl FROM behavior_logs bl
       JOIN students s ON s.id = bl.student_id
       WHERE bl.id = ? AND s.organization_id = ?`,
      [req.params.id, req.user.organizationId]
    );
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Log not found' });
    return res.json({ message: 'Log deleted' });
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
});

// ── Internal: check alert rules after a new log ───────────────────────────────
async function checkAlertRules(studentId, behaviorType, organizationId) {
  const [rules] = await pool.execute(
    `SELECT * FROM alert_rules WHERE student_id = ? AND active = TRUE`,
    [studentId]
  );

  for (const rule of rules) {
    const condition = rule.rule_condition;
    if (condition.behavior !== behaviorType) continue;

    const windowMs = (condition.window_minutes || 60) * 60 * 1000;
    const since    = new Date(Date.now() - windowMs);

    const [counts] = await pool.execute(
      `SELECT COUNT(*) AS cnt FROM behavior_logs
       WHERE student_id = ? AND behavior_type = ? AND start_time >= ?`,
      [studentId, behaviorType, since]
    );

    if (counts[0].cnt >= condition.threshold) {
      await pool.execute(
        'UPDATE alert_rules SET last_triggered = NOW() WHERE id = ?',
        [rule.id]
      );
      // TODO: send notification based on rule.rule_action (email, push, etc.)
      console.log(`🔔 Alert triggered for student ${studentId}: ${JSON.stringify(rule.rule_action)}`);
    }
  }
}

module.exports = router;