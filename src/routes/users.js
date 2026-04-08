// src/routes/users.js
const router = require('express').Router();
const pool   = require('../db/pool');
const { requireAuth, requireRole } = require('../middleware/auth');

router.use(requireAuth);

// GET /api/users — admin only
router.get('/', requireRole(['admin','bcba']), async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT id, name, email, role, last_login, created_at FROM users WHERE organization_id = ? ORDER BY name',
      [req.user.organizationId]
    );
    return res.json(rows);
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
