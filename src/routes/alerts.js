// src/routes/alerts.js — Alert rule routes
const router = require('express').Router();
const pool   = require('../db/pool');
const { requireAuth, requireRole, auditLog } = require('../middleware/auth');

router.use(requireAuth);

// ── GET /api/alerts?student_id= ───────────────────────────────────────────────
router.get('/', auditLog('VIEW'), async (req, res) => {
  const { student_id } = req.query;

  try {
    let rows;
    if (student_id) {
      // Verify student belongs to org
      const [students] = await pool.execute(
        'SELECT id FROM students WHERE id = ? AND organization_id = ?',
        [student_id, req.user.organizationId]
      );
      if (!students[0]) return res.status(404).json({ error: 'Student not found' });

      [rows] = await pool.execute(
        `SELECT ar.*, u.name AS created_by_name
         FROM alert_rules ar
         LEFT JOIN users u ON u.id = ar.created_by
         WHERE ar.student_id = ?
         ORDER BY ar.id DESC`,
        [student_id]
      );
    } else {
      // Admin/BCBA: get all alerts for the org
      if (!['admin', 'bcba'].includes(req.user.role)) {
        return res.status(403).json({ error: 'Insufficient permissions' });
      }
      [rows] = await pool.execute(
        `SELECT ar.*, u.name AS created_by_name, s.first_name, s.last_name
         FROM alert_rules ar
         LEFT JOIN users u ON u.id = ar.created_by
         JOIN students s ON s.id = ar.student_id
         WHERE s.organization_id = ?
         ORDER BY ar.id DESC`,
        [req.user.organizationId]
      );
    }

    return res.json(rows);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// ── GET /api/alerts/:id ───────────────────────────────────────────────────────
router.get('/:id', auditLog('VIEW'), async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT ar.* FROM alert_rules ar
       JOIN students s ON s.id = ar.student_id
       WHERE ar.id = ? AND s.organization_id = ?`,
      [req.params.id, req.user.organizationId]
    );
    if (!rows[0]) return res.status(404).json({ error: 'Alert rule not found' });
    return res.json(rows[0]);
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
});

// ── POST /api/alerts ──────────────────────────────────────────────────────────
// Create an alert rule. Only bcba/admin.
// Example body:
// {
//   "student_id": 1,
//   "rule_condition": { "behavior": "aggression", "threshold": 3, "window_minutes": 120 },
//   "rule_action":    { "notify_role": "bcba", "message": "High aggression frequency" }
// }
router.post('/', requireRole(['admin', 'bcba']), auditLog('CREATE'), async (req, res) => {
  const { student_id, rule_condition, rule_action } = req.body;

  if (!student_id || !rule_condition || !rule_action) {
    return res.status(400).json({ error: 'student_id, rule_condition, and rule_action are required' });
  }

  // Validate condition shape
  if (!rule_condition.behavior || typeof rule_condition.threshold !== 'number') {
    return res.status(400).json({ error: 'rule_condition must have behavior (string) and threshold (number)' });
  }

  try {
    // Verify student belongs to org
    const [students] = await pool.execute(
      'SELECT id FROM students WHERE id = ? AND organization_id = ?',
      [student_id, req.user.organizationId]
    );
    if (!students[0]) return res.status(404).json({ error: 'Student not found' });

    const [result] = await pool.execute(
      `INSERT INTO alert_rules (student_id, created_by, rule_condition, rule_action, active)
       VALUES (?, ?, ?, ?, TRUE)`,
      [student_id, req.user.id, JSON.stringify(rule_condition), JSON.stringify(rule_action)]
    );
    return res.status(201).json({ id: result.insertId, message: 'Alert rule created' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// ── PATCH /api/alerts/:id ─────────────────────────────────────────────────────
router.patch('/:id', requireRole(['admin', 'bcba']), auditLog('UPDATE'), async (req, res) => {
  const fields = [];
  const values = [];

  if (req.body.rule_condition !== undefined) {
    if (!req.body.rule_condition.behavior || typeof req.body.rule_condition.threshold !== 'number') {
      return res.status(400).json({ error: 'Invalid rule_condition' });
    }
    fields.push('rule_condition = ?');
    values.push(JSON.stringify(req.body.rule_condition));
  }
  if (req.body.rule_action !== undefined) {
    fields.push('rule_action = ?');
    values.push(JSON.stringify(req.body.rule_action));
  }
  if (req.body.active !== undefined) {
    fields.push('active = ?');
    values.push(req.body.active ? 1 : 0);
  }

  if (fields.length === 0) {
    return res.status(400).json({ error: 'No valid fields to update' });
  }

  values.push(req.params.id, req.user.organizationId);

  try {
    const [result] = await pool.execute(
      `UPDATE alert_rules ar
       JOIN students s ON s.id = ar.student_id
       SET ${fields.join(', ')}
       WHERE ar.id = ? AND s.organization_id = ?`,
      values
    );
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Alert rule not found' });
    return res.json({ message: 'Alert rule updated' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// ── DELETE /api/alerts/:id ────────────────────────────────────────────────────
router.delete('/:id', requireRole(['admin', 'bcba']), auditLog('DELETE'), async (req, res) => {
  try {
    const [result] = await pool.execute(
      `DELETE ar FROM alert_rules ar
       JOIN students s ON s.id = ar.student_id
       WHERE ar.id = ? AND s.organization_id = ?`,
      [req.params.id, req.user.organizationId]
    );
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Alert rule not found' });
    return res.json({ message: 'Alert rule deleted' });
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;