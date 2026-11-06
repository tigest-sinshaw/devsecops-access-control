const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const config = require('./config');
const { users, orders } = require('./data/seed');
const { canAccessOrder } = require('./policies');
const authenticate = require('./middleware/authenticate');
const { requireRole, requirePermission } = require('./middleware/authorize');

const app = express();
app.use(express.json());

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  const passwordMatch = user ? await bcrypt.compare(password, user.passwordHash) : false;

  if (!user || !passwordMatch) {
    return res.status(401).json({ error: "Invalid email or password" });
  }

  const token = jwt.sign(
    { sub: user.id },
    config.jwtSecret,
    { expiresIn: '15m', issuer: config.jwtIssuer, audience: config.jwtAudience }
  );

  return res.json({ token });
});

// GET /api/orders
app.get('/api/orders', authenticate, requirePermission('orders:read'), (req, res) => {
  // Scope the array output directly to the tenant's branch context
  const filtered = orders.filter(o => req.user.role === 'admin' || o.branchId === req.user.branchId);
  res.json({ orders: filtered });
});

// GET /api/orders/:id
app.get('/api/orders/:id', authenticate, requirePermission('orders:read'), (req, res) => {
  const order = orders.find(o => o.id === req.params.id);
  
  // Object Level Access Check: Return 404 if not found OR if it belongs to another branch
  if (!order || !canAccessOrder(req.user, order)) {
    return res.status(404).json({ error: "Order not found" });
  }
  res.json(order);
});

// POST /api/orders
app.post('/api/orders', authenticate, requirePermission('orders:create'), (req, res) => {
  res.status(201).json({ message: "Order placed securely." });
});

// POST /api/payments
app.post('/api/payments', authenticate, requirePermission('payments:create'), (req, res) => {
  res.status(201).json({ message: "Payment processed securely." });
});

// GET /api/reports/branch (Fixed branch lookup vulnerability)
app.get('/api/reports/branch', authenticate, requirePermission('reports:read'), (req, res) => {
  // Use user identity context instead of client query variables
  const branch = req.user.branchId || "All Branches"; 
  const branchOrders = orders.filter(o => req.user.role === 'admin' || o.branchId === branch);
  
  res.json({
    branch: branch,
    totalOrdersCount: branchOrders.length,
    revenue: branchOrders.reduce((sum, o) => sum + o.total, 0)
  });
});

// GET /api/admin/users
app.get('/api/admin/users', authenticate, requireRole('admin'), (req, res) => {
  const cleanUsers = users.map(({ passwordHash, ...safeFields }) => safeFields);
  res.json({ users: cleanUsers });
});

module.exports = app;
