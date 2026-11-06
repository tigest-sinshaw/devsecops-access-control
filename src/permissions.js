const ROLE_PERMISSIONS = {
  waiter:  ["orders:create", "orders:read"],
  cashier: ["orders:read", "payments:create"],
  manager: ["orders:read", "reports:read"],
  admin:   ["users:manage", "orders:read", "reports:read"]
};

function hasPermission(user, permission) {
  if (!user || !user.role) return false;
  const permissions = ROLE_PERMISSIONS[user.role];
  if (!permissions) return false;
  return permissions.includes(permission);
}

module.exports = { ROLE_PERMISSIONS, hasPermission };
