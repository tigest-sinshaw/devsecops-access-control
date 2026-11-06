const jwt = require('jsonwebtoken');
const config = require('../config');
const { users } = require('../data/seed');

function authenticate(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const [scheme, token] = authHeader.split(" ");

  if (scheme !== "Bearer" || !token) {
    return res.status(401).json({ error: "Unauthorized: Missing or malformed token." });
  }

  try {
    const payload = jwt.verify(token, config.jwtSecret, {
      algorithms: ["HS256"],
      issuer: config.jwtIssuer,
      audience: config.jwtAudience
    });

    const systemUser = users.find(u => u.id === payload.sub);
    if (!systemUser) {
      return res.status(401).json({ error: "Unauthorized: Profile inactive." });
    }

    req.user = {
      id: systemUser.id,
      role: systemUser.role,
      branchId: systemUser.branchId
    };

    next();
  } catch (err) {
    return res.status(401).json({ error: "Unauthorized: Invalid or expired token." });
  }
}

module.exports = authenticate;
