function canAccessOrder(user, order) { if (!user || !order) return false; if (user.role === "admin") return true; return user.branchId === order.branchId; } module.exports = { canAccessOrder };
