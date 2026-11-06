const bcrypt = require('bcrypt');

// Password for everyone: "Password123!"
const hashedSecret = bcrypt.hashSync("Password123!", 10);

const users = [
  { id: "u1", email: "bole.waiter@dinedesk.com", passwordHash: hashedSecret, role: "waiter", branchId: "Bole" },
  { id: "u2", email: "piassa.waiter@dinedesk.com", passwordHash: hashedSecret, role: "waiter", branchId: "Piassa" },
  { id: "u3", email: "bole.cashier@dinedesk.com", passwordHash: hashedSecret, role: "cashier", branchId: "Bole" },
  { id: "u4", email: "piassa.cashier@dinedesk.com", passwordHash: hashedSecret, role: "cashier", branchId: "Piassa" },
  { id: "u5", email: "bole.manager@dinedesk.com", passwordHash: hashedSecret, role: "manager", branchId: "Bole" },
  { id: "u6", email: "piassa.manager@dinedesk.com", passwordHash: hashedSecret, role: "manager", branchId: "Piassa" },
  { id: "u7", email: "admin@dinedesk.com", passwordHash: hashedSecret, role: "admin", branchId: null }
];

const orders = [
  { id: "o1", branchId: "Bole", items: ["Kitfo", "Tej"], total: 1200 },
  { id: "o2", branchId: "Bole", items: ["Beyaynetu"], total: 450 },
  { id: "o3", branchId: "Piassa", items: ["Tibs", "Beer"], total: 950 },
  { id: "o4", branchId: "Piassa", items: ["Shiro Wot"], total: 300 }
];

module.exports = { users, orders };
