// src/middleware/auth.js
const jwt = require('jsonwebtoken');

// Verifies the Bearer access token on protected routes
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const token = header.slice(7);
  try {
    const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    req.user = payload; // { id, email, role, organizationId }
    next();
  } catch (err) {
    const msg = err.name === 'TokenExpiredError' ? 'Token expired' : 'Invalid token';
    return res.status(401).json({ error: msg });
  }
}

// Role guard — pass allowed roles as an array
// Usage: requireRole(['bcba', 'admin'])
function requireRole(roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

// Audit logger — call after requireAuth to record access
function auditLog(action) {
  return async (req, res, next) => {
    const pool = require('../db/pool');
    try {
      await pool.execute(
        `INSERT INTO audit_logs (user_id, action, table_name, record_id, ip_address)
         VALUES (?, ?, ?, ?, ?)`,
        [
          req.user?.id || null,
          action,
          req.baseUrl.replace('/api/', ''),
          req.params.id || null,
          req.ip,
        ]
      );
    } catch (err) {
      // Audit failure must never break the request, but we log it
      console.error('Audit log failed:', err.message);
    }
    next();
  };
}

module.exports = { requireAuth, requireRole, auditLog };

