const { hasPermission } = require('../permissions');

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: "Forbidden: Insufficient role." });
    }
    next();
  };
}

function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.user || !hasPermission(req.user, permission)) {
      return res.status(403).json({ error: "Forbidden: Missing resource clearance claim." });
    }
    next();
  };
}

module.exports = { requireRole, requirePermission };
