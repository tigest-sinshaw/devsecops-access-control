const request = require('supertest');
const jwt = require('jsonwebtoken');

// 1. INJECT MOCK ENVIRONMENT SECRETS FIRST (Fixes startup validation block)
const TEST_SECRET = "supersecretmocksigningkeyformanytests123!";
process.env.JWT_SECRET = TEST_SECRET;
process.env.JWT_ISSUER = "dinedesk-api";
process.env.JWT_AUDIENCE = "dinedesk-app";


const app = require('../src/app');


function mintToken(userId, secret = TEST_SECRET, options = {}) {

  return jwt.sign(
    { sub: userId },
    secret,
    { expiresIn: '15m', issuer: 'dinedesk-api', audience: 'dinedesk-app', ...options }
  );
}

describe('DineDesk API Access Control Tests', () => {

  // Test 1: Missing authentication vector
  it('should return 401 if no token is provided on a protected endpoint', async () => {
    const res = await request(app).get('/api/orders');
    expect(res.status).toBe(401);
    expect(res.body.error).toContain('Missing or malformed token');
  });

  // Test 2: Invalid signing key vector
  it('should return 401 if a token is signed with a malicious or wrong key', async () => {
    const badToken = mintToken('u1', 'completely-wrong-and-fake-key-12345');
    const res = await request(app)
      .get('/api/orders')
      .set('Authorization', `Bearer ${badToken}`);
    expect(res.status).toBe(401);
  });

  // Test 3: Expired token vector
  it('should return 401 if an expired token is provided', async () => {
    const expiredToken = mintToken('u1', TEST_SECRET, { expiresIn: '-1s' });
    const res = await request(app)
      .get('/api/orders')
      .set('Authorization', `Bearer ${expiredToken}`);
    expect(res.status).toBe(401);
  });

  // Test 4: Role access block (Waiter hitting admin endpoint)
  it('should return 403 when a waiter calls GET /api/admin/users', async () => {
    const token = mintToken('u1'); // u1 = Bole Waiter
    const res = await request(app)
      .get('/api/admin/users')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(403);
  });

  // Test 5: Role access allowed (Admin hitting admin endpoint, stripping passwords)
  it('should return 200 with no password hashes when an administrator calls GET /api/admin/users', async () => {
    const token = mintToken('u7'); // u7 = Admin
    const res = await request(app)
      .get('/api/admin/users')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.users).toBeDefined();
    expect(res.body.users[0].passwordHash).toBeUndefined(); // Verification that hash is stripped
  });

  // Test 6: Permission match allowed (Waiter creating order)
  it('should return 201 when a waiter creates an order', async () => {
    const token = mintToken('u1'); // u1 = Waiter
    const res = await request(app)
      .post('/api/orders')
      .set('Authorization', `Bearer ${token}`)
      .send({ items: ['Tej'], total: 200 });
    expect(res.status).toBe(201);
  });

  // Test 7: Permission mismatch denied (Cashier creating order)
  it('should return 403 when a cashier attempts to create an order', async () => {
    const token = mintToken('u3'); // u3 = Cashier
    const res = await request(app)
      .post('/api/orders')
      .set('Authorization', `Bearer ${token}`)
      .send({ items: ['Kitfo'], total: 600 });
    expect(res.status).toBe(403);
  });

  // Test 8: Intra-branch access allowed (Bole manager reading Bole order)
  it('should return 200 when a Bole manager reads a Bole order', async () => {
    const token = mintToken('u5'); // u5 = Bole Manager
    const res = await request(app)
      .get('/api/orders/o1') // o1 = Bole order
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.id).toBe('o1');
  });

  // Test 9: Inter-branch isolation check (Bole manager reading Piassa order)
  it('should return 404 (masked) when a Bole manager attempts to read a Piassa order', async () => {
    const token = mintToken('u5'); // u5 = Bole Manager
    const res = await request(app)
      .get('/api/orders/o3') // o3 = Piassa order
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(404); // Verifies the defensive masking rule
  });

  // Test 10: Non-permitted role hitting reports
  it('should return 403 when a waiter attempts to call GET /api/reports/branch', async () => {
    const token = mintToken('u1'); // u1 = Waiter
    const res = await request(app)
      .get('/api/reports/branch')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(403);
  });

  // Test 11: Parameter pollution isolation test (Query injection validation)
  it('should bypass query branch strings and enforce token branch context on GET /api/reports/branch', async () => {
    const token = mintToken('u6'); // u6 = Piassa Manager
    const res = await request(app)
      .get('/api/reports/branch?branchId=Bole') // Attempt to manipulate parameter to steal Bole metrics
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.branch).toBe('Piassa'); // Enforces token data over user parameters
    expect(res.body.branch).not.toBe('Bole');
  });

  // Test 12: Broad data scoping verification
  it('should restrict order indexes to corresponding branch listings for branch accounts', async () => {
    const token = mintToken('u1'); // u1 = Bole Waiter
    const res = await request(app)
      .get('/api/orders')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    const elements = res.body.orders;
    // Assert all returned items belong exclusively to Bole branch scope
    elements.forEach(order => {
      expect(order.branchId).toBe('Bole');
      expect(order.branchId).not.toBe('Piassa');
    });
  });
});
