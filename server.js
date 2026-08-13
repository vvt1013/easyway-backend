const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const allowedOrigins = String(process.env.CORS_ALLOW_ORIGINS || '')
  .split(',').map(origin => origin.trim()).filter(Boolean);
const rootDir = __dirname;
const dataDir = path.join(rootDir, 'data');
const usersPath = path.join(dataDir, 'users.json');
const shipmentsPath = path.join(dataDir, 'shipments.json');

fs.mkdirSync(dataDir, { recursive: true });

function loadJson(filePath, fallback) {
  if (!fs.existsSync(filePath)) {
    return fallback;
  }

  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (error) {
    return fallback;
  }
}

function saveJson(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `scrypt:${salt}:${hash}`;
}

function passwordMatches(password, storedPassword) {
  if (storedPassword && storedPassword.startsWith('scrypt:')) {
    const [, salt, expected] = storedPassword.split(':');
    const actual = crypto.scryptSync(password, salt, 64).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(expected, 'hex'));
  }
  // Supports existing local accounts created by older versions. They are
  // upgraded to scrypt automatically after a successful login.
  return storedPassword === crypto.createHash('sha256').update(password).digest('hex');
}

function createToken() {
  return crypto.randomBytes(16).toString('hex');
}

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, { ...res.corsHeaders, 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(payload));
}

function sendText(res, statusCode, text, contentType = 'text/plain; charset=utf-8') {
  res.writeHead(statusCode, { ...res.corsHeaders, 'Content-Type': contentType });
  res.end(text);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';

    req.on('data', chunk => {
      body += chunk;
      if (body.length > 1e6) {
        req.destroy();
      }
    });

    req.on('end', () => {
      if (!body) {
        resolve({});
        return;
      }

      try {
        resolve(JSON.parse(body));
      } catch (error) {
        reject(new Error('Invalid JSON body'));
      }
    });

    req.on('error', reject);
  });
}

function getAuthUser(req, users) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';

  if (!token) {
    return null;
  }

  return users.find(user => user.token === token) || null;
}

function setCorsHeaders(req, res) {
  const origin = req.headers.origin;
  if (!origin || allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
    res.corsHeaders = origin ? {
      'Access-Control-Allow-Origin': allowedOrigins.includes('*') ? '*' : origin,
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      Vary: 'Origin'
    } : {};
  } else {
    res.corsHeaders = {};
  }
}

const mimeTypes = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.webp': 'image/webp'
};

const routeMap = {
  '/': 'index.html',
  '/register': 'register.html',
  '/admin': 'admin.html',
  '/ship': 'ship.html',
  '/track': 'track.html',
  '/contact': 'contact.html'
};

function serveStatic(res, pathname) {
  const fileName = routeMap[pathname] || pathname.replace(/^\/+/, '');
  const normalizedPath = path.normalize(fileName || 'index.html');
  const fullPath = path.join(rootDir, normalizedPath);

  if (!fullPath.startsWith(rootDir)) {
    sendText(res, 403, 'Forbidden');
    return;
  }

  fs.stat(fullPath, (error, stats) => {
    if (error || !stats.isFile()) {
      sendText(res, 404, 'Not found');
      return;
    }

    const ext = path.extname(fullPath);
    const contentType = mimeTypes[ext] || 'application/octet-stream';

    fs.readFile(fullPath, (readError, data) => {
      if (readError) {
        sendText(res, 500, 'Server error');
        return;
      }
      sendText(res, 200, data.toString('binary'), contentType);
    });
  });
}

function startServer() {
  let users = loadJson(usersPath, []);
  let shipments = loadJson(shipmentsPath, []);

  const adminEmail = String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();
  const adminPassword = String(process.env.ADMIN_PASSWORD || '');

  if (adminEmail && adminPassword && !users.some(user => user.email === adminEmail && user.role === 'admin')) {
    users.unshift({ id: crypto.randomUUID(), email: adminEmail, password: hashPassword(adminPassword), role: 'admin', token: '', createdAt: new Date().toISOString() });
    saveJson(usersPath, users);
    console.log('Admin fallback account created from environment variables.');
  }

  const server = http.createServer(async (req, res) => {
    setCorsHeaders(req, res);
    if (req.method === 'OPTIONS') {
      res.writeHead(204, res.corsHeaders);
      res.end();
      return;
    }
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const pathname = url.pathname;

    if (req.method === 'GET' && pathname === '/health') {
      sendJson(res, 200, { ok: true, service: 'easyway-shipping' });
      return;
    }

    if (req.method === 'POST' && pathname === '/register') {
      try {
        const body = await readBody(req);
        const email = String(body.email || '').trim().toLowerCase();
        const password = String(body.password || '');

        if (!email || !password) {
          sendJson(res, 400, { error: 'Email and password are required' });
          return;
        }

        if (users.some(user => user.email === email)) {
          sendJson(res, 409, { error: 'A user with that email already exists' });
          return;
        }

        const newUser = {
          id: Date.now().toString(36),
          email,
          password: hashPassword(password),
          role: 'user',
          token: createToken(),
          createdAt: new Date().toISOString()
        };

        users.push(newUser);
        saveJson(usersPath, users);

        sendJson(res, 201, {
          token: newUser.token,
          user: { email: newUser.email, role: newUser.role }
        });
      } catch (error) {
        sendJson(res, 400, { error: error.message || 'Invalid registration data' });
      }
      return;
    }

    if (req.method === 'POST' && pathname === '/login') {
      try {
        const body = await readBody(req);
        const email = String(body.email || '').trim().toLowerCase();
        const password = String(body.password || '');

        const user = users.find(item => item.email === email && passwordMatches(password, item.password));

        if (!user) {
          sendJson(res, 401, { error: 'Invalid email or password' });
          return;
        }

        if (!user.password.startsWith('scrypt:')) user.password = hashPassword(password);
        user.token = createToken();
        saveJson(usersPath, users);

        sendJson(res, 200, {
          token: user.token,
          user: { email: user.email, role: user.role || 'admin' }
        });
      } catch (error) {
        sendJson(res, 400, { error: error.message || 'Invalid login payload' });
      }
      return;
    }

    if (req.method === 'POST' && pathname === '/admin/register') {
      try {
        const body = await readBody(req);
        const email = String(body.email || '').trim().toLowerCase();
        const password = String(body.password || '');

        if (!email || !password) {
          sendJson(res, 400, { error: 'Email and password are required' });
          return;
        }

        if (users.some(user => user.email === email)) {
          sendJson(res, 409, { error: 'A user with that email already exists' });
          return;
        }

        const newAdmin = {
          id: Date.now().toString(36),
          email,
          password: hashPassword(password),
          role: 'admin',
          token: createToken(),
          createdAt: new Date().toISOString()
        };

        users.push(newAdmin);
        saveJson(usersPath, users);

        sendJson(res, 201, { user: { email: newAdmin.email, role: newAdmin.role } });
      } catch (error) {
        sendJson(res, 400, { error: error.message || 'Invalid admin payload' });
      }
      return;
    }

    if (req.method === 'POST' && pathname === '/contact') {
      try {
        const body = await readBody(req);
        const name = String(body.name || '').trim();
        const email = String(body.email || '').trim();
        const message = String(body.message || '').trim();

        if (!name || !email || !message) {
          sendJson(res, 400, { error: 'Name, email, and message are required' });
          return;
        }

        sendJson(res, 200, { ok: true, message: 'Message received successfully' });
      } catch (error) {
        sendJson(res, 400, { error: error.message || 'Invalid contact payload' });
      }
      return;
    }

    if (req.method === 'POST' && pathname === '/create-shipment') {
      try {
        const body = await readBody(req);
        const shipment = {
          id: Date.now().toString(36),
          trackingNumber: body.trackingNumber || `EW${Date.now().toString().slice(-8)}`,
          sender: body.sender || 'Not available',
          receiver: body.receiver || 'Not available',
          origin: body.origin || 'Origin pending',
          destination: body.destination || 'Destination pending',
          email: body.email || '',
          weight: body.weight || '',
          type: body.type || 'Standard',
          status: body.status || 'Processing',
          location: body.location || body.origin || 'Origin pending',
          date: body.date || new Date().toLocaleString(),
          createdAt: new Date().toISOString()
        };

        shipments.unshift(shipment);
        saveJson(shipmentsPath, shipments);

        sendJson(res, 201, shipment);
      } catch (error) {
        sendJson(res, 400, { error: error.message || 'Invalid shipment payload' });
      }
      return;
    }

    if (req.method === 'GET' && pathname.startsWith('/track/')) {
      const trackingNumber = pathname.split('/').filter(Boolean).slice(1).join('/');
      const shipment = shipments.find(item => String(item.trackingNumber).toLowerCase() === trackingNumber.toLowerCase());

      if (!shipment) {
        sendJson(res, 404, { error: 'Shipment not found' });
        return;
      }

      sendJson(res, 200, shipment);
      return;
    }

    if (req.method === 'GET' && pathname === '/admin/shipments') {
      sendJson(res, 200, shipments);
      return;
    }

    if (req.method === 'POST' && pathname.startsWith('/admin/update-shipment/')) {
      const trackingNumber = pathname.split('/').filter(Boolean).slice(2).join('/');
      const body = await readBody(req).catch(() => ({}));
      const shipment = shipments.find(item => String(item.trackingNumber).toLowerCase() === trackingNumber.toLowerCase());

      if (!shipment) {
        sendJson(res, 404, { error: 'Shipment not found' });
        return;
      }

      shipment.status = body.status || shipment.status;
      shipment.location = body.location || shipment.location;
      shipment.date = body.date || new Date().toLocaleString();
      saveJson(shipmentsPath, shipments);
      sendJson(res, 200, shipment);
      return;
    }

    if (req.method === 'GET' && pathname === '/admin') {
      serveStatic(res, '/admin');
      return;
    }

    if (req.method === 'GET' && (pathname === '/' || pathname === '/index.html' || pathname === '/register' || pathname === '/ship' || pathname === '/track' || pathname === '/contact')) {
      serveStatic(res, pathname === '/' ? '/' : pathname);
      return;
    }

    if (req.method === 'GET') {
      serveStatic(res, pathname);
      return;
    }

    sendJson(res, 404, { error: 'Route not found' });
  });

  server.listen(PORT, () => {
    console.log(`EasyWay shipping server running on http://localhost:${PORT}`);
  });
}

startServer();
