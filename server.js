const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const allowedOrigins = String(process.env.CORS_ALLOW_ORIGINS || '')
  .split(',').map(origin => origin.trim()).filter(Boolean);
const rootDir = __dirname;
const dataDir = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.join(rootDir, 'data');
const usersPath = path.join(dataDir, 'users.json');
const shipmentsPath = path.join(dataDir, 'shipments.json');
const supportPath = path.join(dataDir, 'support.json');

fs.mkdirSync(dataDir, { recursive: true });

if (path.resolve(dataDir) !== path.resolve(path.join(rootDir, 'data'))) {
  for (const fileName of ['users.json', 'shipments.json']) {
    const sourcePath = path.join(rootDir, 'data', fileName);
    const targetPath = path.join(dataDir, fileName);
    if (!fs.existsSync(targetPath) && fs.existsSync(sourcePath)) {
      fs.copyFileSync(sourcePath, targetPath);
    }
  }
}

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
  let support = loadJson(supportPath, []);

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
        const trackingNumber = String(body.trackingNumber || '').trim();
        const message = String(body.message || '').trim();

        if (!name || !email || !message) {
          sendJson(res, 400, { error: 'Name, email, and message are required' });
          return;
        }

        const now = new Date().toISOString();
        const conversation = {
          id: crypto.randomUUID(),
          name,
          email,
          trackingNumber,
          status: 'Open',
          createdAt: now,
          updatedAt: now,
          messages: [{ id: crypto.randomUUID(), sender: 'customer', message, createdAt: now }]
        };
        support.unshift(conversation);
        saveJson(supportPath, support);
        sendJson(res, 201, { ok: true, conversationId: conversation.id });
      } catch (error) {
        sendJson(res, 400, { error: error.message || 'Invalid contact payload' });
      }
      return;
    }

    if (req.method === 'POST' && pathname === '/create-shipment') {
      try {
        const body = await readBody(req);
        const sender = String(body.sender || '').trim();
        const receiver = String(body.receiver || '').trim();
        const origin = String(body.origin || '').trim();
        const destination = String(body.destination || '').trim();
        if (!sender || !receiver || !origin || !destination) {
          sendJson(res, 400, { error: 'Sender, receiver, origin, and destination are required' });
          return;
        }
        const createdAt = new Date().toISOString();
        const shipment = {
          id: Date.now().toString(36),
          trackingNumber: body.trackingNumber || `EW${Date.now().toString().slice(-8)}`,
          sender,
          receiver,
          origin,
          destination,
          email: body.email || '',
          weight: body.weight || '',
          type: body.type || 'Standard',
          status: body.status || 'Processing',
          location: body.location || origin,
          date: createdAt,
          createdAt,
          updatedAt: createdAt,
          history: []
        };

        shipment.history.push({
          id: crypto.randomUUID(),
          status: shipment.status,
          location: shipment.location,
          notes: String(body.notes || '').trim(),
          createdAt
        });

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

      const status = String(body.status || '').trim();
      const location = String(body.location || '').trim();
      if (!status || !location) {
        sendJson(res, 400, { error: 'Status and location are required' });
        return;
      }
      const updatedAt = new Date().toISOString();
      shipment.status = status;
      shipment.location = location;
      shipment.date = updatedAt;
      shipment.updatedAt = updatedAt;
      if (!Array.isArray(shipment.history)) shipment.history = [];
      shipment.history.push({
        id: crypto.randomUUID(),
        status,
        location,
        notes: String(body.notes || '').trim(),
        createdAt: updatedAt
      });
      saveJson(shipmentsPath, shipments);
      sendJson(res, 200, shipment);
      return;
    }

    if (req.method === 'GET' && pathname === '/admin/support') {
      sendJson(res, 200, support);
      return;
    }

    if (req.method === 'POST' && pathname.match(/^\/admin\/support\/[^/]+\/reply$/)) {
      const conversationId = pathname.split('/')[3];
      const body = await readBody(req).catch(() => ({}));
      const message = String(body.message || '').trim();
      const conversation = support.find(item => item.id === conversationId);
      if (!conversation) {
        sendJson(res, 404, { error: 'Support conversation not found' });
        return;
      }
      if (!message) {
        sendJson(res, 400, { error: 'Reply message is required' });
        return;
      }
      const now = new Date().toISOString();
      conversation.messages.push({ id: crypto.randomUUID(), sender: 'admin', message, createdAt: now });
      conversation.status = 'In Progress';
      conversation.updatedAt = now;
      saveJson(supportPath, support);
      sendJson(res, 200, conversation);
      return;
    }

    if (req.method === 'POST' && pathname.match(/^\/admin\/support\/[^/]+\/status$/)) {
      const conversationId = pathname.split('/')[3];
      const body = await readBody(req).catch(() => ({}));
      const status = String(body.status || '').trim();
      const conversation = support.find(item => item.id === conversationId);
      if (!conversation) {
        sendJson(res, 404, { error: 'Support conversation not found' });
        return;
      }
      if (!['Open', 'In Progress', 'Resolved'].includes(status)) {
        sendJson(res, 400, { error: 'Invalid support status' });
        return;
      }
      conversation.status = status;
      conversation.updatedAt = new Date().toISOString();
      saveJson(supportPath, support);
      sendJson(res, 200, conversation);
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
