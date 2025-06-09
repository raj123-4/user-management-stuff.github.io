const http = require('http');
const crypto = require('crypto');
const fs = require('fs');

const DATA_FILE = 'users.json';
const SECRET = 'mysecret';

function loadUsers() {
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE));
  } catch (e) {
    return [];
  }
}

function saveUsers(users) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(users, null, 2));
}

function hashPassword(password, salt) {
  const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
  return { salt, hash };
}

function verifyPassword(password, user) {
  const hashed = crypto.pbkdf2Sync(password, user.salt, 1000, 64, 'sha512').toString('hex');
  return hashed === user.hash;
}

function generateToken(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(data).digest('base64url');
  return data + '.' + sig;
}

function verifyToken(token) {
  const [data, sig] = token.split('.');
  if (!data || !sig) return null;
  const check = crypto.createHmac('sha256', SECRET).update(data).digest('base64url');
  if (check !== sig) return null;
  return JSON.parse(Buffer.from(data, 'base64url').toString());
}

function send(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
}

function logActivity(user, action) {
  user.logs = user.logs || [];
  user.logs.push({ action, time: Date.now() });
}

function getStatus(user) {
  if (user.revoked) return 'Revoked';
  if (user.accessExpires && Date.now() > user.accessExpires) return 'Expired';
  return 'Active';
}

const server = http.createServer((req, res) => {
  let body = '';
  req.on('data', chunk => body += chunk);
  req.on('end', () => {
    const users = loadUsers();
    const url = new URL(req.url, 'http://localhost');
    // registration
    if (req.method === 'POST' && url.pathname === '/register') {
      const { name, email, password } = JSON.parse(body || '{}');
      if (!email || !password) return send(res, 400, { error: 'Invalid' });
      if (users.find(u => u.email === email)) return send(res, 400, { error: 'Exists' });
      const id = crypto.randomUUID();
      const { salt, hash } = hashPassword(password, crypto.randomBytes(16).toString('hex'));
      const user = { id, name, email, salt, hash, role: 'user', revoked: false };
      logActivity(user, 'register');
      users.push(user);
      saveUsers(users);
      send(res, 201, { message: 'registered' });
    // login
    } else if (req.method === 'POST' && url.pathname === '/login') {
      const { email, password } = JSON.parse(body || '{}');
      const user = users.find(u => u.email === email);
      if (!user || !verifyPassword(password, user)) return send(res, 401, { error: 'Unauthorized' });
      logActivity(user, 'login');
      saveUsers(users);
      const token = generateToken({ id: user.id, role: user.role });
      send(res, 200, { token });
    // get current user data
    } else if (req.method === 'GET' && url.pathname === '/me') {
      const token = req.headers['authorization'];
      const payload = token && verifyToken(token);
      if (!payload) return send(res, 401, { error: 'Unauthorized' });
      const user = users.find(u => u.id === payload.id);
      if (!user) return send(res, 404, { error: 'Not found' });
      send(res, 200, { id: user.id, name: user.name, email: user.email, status: getStatus(user) });
    // admin list users
    } else if (req.method === 'GET' && url.pathname === '/admin/users') {
      const token = req.headers['authorization'];
      const payload = token && verifyToken(token);
      if (!payload || payload.role !== 'admin') return send(res, 401, { error: 'Unauthorized' });
      const result = users.map(u => ({ id: u.id, email: u.email, role: u.role, status: getStatus(u) }));
      send(res, 200, result);
    // grant access
    } else if (req.method === 'POST' && url.pathname.startsWith('/admin/grant/')) {
      const token = req.headers['authorization'];
      const payload = token && verifyToken(token);
      if (!payload || payload.role !== 'admin') return send(res, 401, { error: 'Unauthorized' });
      const id = url.pathname.split('/').pop();
      const user = users.find(u => u.id === id);
      if (!user) return send(res, 404, { error: 'Not found' });
      const { days } = JSON.parse(body || '{}');
      user.accessExpires = Date.now() + (days || 7) * 86400000;
      user.revoked = false;
      logActivity(user, `grant ${days}`);
      saveUsers(users);
      send(res, 200, { message: 'granted', until: user.accessExpires });
    // revoke access
    } else if (req.method === 'POST' && url.pathname.startsWith('/admin/revoke/')) {
      const token = req.headers['authorization'];
      const payload = token && verifyToken(token);
      if (!payload || payload.role !== 'admin') return send(res, 401, { error: 'Unauthorized' });
      const id = url.pathname.split('/').pop();
      const user = users.find(u => u.id === id);
      if (!user) return send(res, 404, { error: 'Not found' });
      user.revoked = true;
      logActivity(user, 'revoke');
      saveUsers(users);
      send(res, 200, { message: 'revoked' });
    // user logs
    } else if (req.method === 'GET' && url.pathname.startsWith('/admin/logs/')) {
      const token = req.headers['authorization'];
      const payload = token && verifyToken(token);
      if (!payload || payload.role !== 'admin') return send(res, 401, { error: 'Unauthorized' });
      const id = url.pathname.split('/').pop();
      const user = users.find(u => u.id === id);
      if (!user) return send(res, 404, { error: 'Not found' });
      send(res, 200, { logs: user.logs || [] });
    } else {
      send(res, 404, { error: 'Not found' });
    }
  });
});

server.listen(3000, () => console.log('Server running on 3000'));
