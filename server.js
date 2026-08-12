const express = require('express');
const cors = require('cors');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

const app = express();
const FRONTEND_ORIGIN = 'https://easywaycourierservice.pages.dev';
const corsOptions = {
  origin(origin, callback) {
    // Requests without an Origin header (for example Render health checks) are
    // not cross-origin browser requests, so do not emit CORS headers for them.
    if (!origin || origin === FRONTEND_ORIGIN) {
      return callback(null, origin === FRONTEND_ORIGIN ? FRONTEND_ORIGIN : false);
    }
    return callback(null, false);
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  optionsSuccessStatus: 204
};

app.use(cors(corsOptions));
app.options(/.*/, cors(corsOptions));
app.use(express.json());

const PORT = process.env.PORT || 3000;

// ================= FILES =================

const DATA_FILE = 'data.json';
const USERS_FILE = 'users.json';

// Ensure files exist
if (!fs.existsSync(DATA_FILE)) {
  fs.writeFileSync(DATA_FILE, JSON.stringify([]));
}
if (!fs.existsSync(USERS_FILE)) {
  fs.writeFileSync(USERS_FILE, JSON.stringify([]));
}

// ================= HELPERS =================

const readData = () => JSON.parse(fs.readFileSync(DATA_FILE));
const writeData = (data) => fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));

const readUsers = () => JSON.parse(fs.readFileSync(USERS_FILE));
const writeUsers = (data) => fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2));

const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
if (!ADMIN_EMAIL || !ADMIN_PASSWORD) {
  throw new Error('ADMIN_EMAIL and ADMIN_PASSWORD must be configured before the server starts.');
}
// A separately configured secret is preferred. The fallback keeps existing
// deployments working while never storing credentials in source code.
const AUTH_SECRET = process.env.AUTH_SECRET || crypto
  .createHash('sha256')
  .update(`${ADMIN_EMAIL || ''}:${ADMIN_PASSWORD || ''}`)
  .digest('hex');

const base64urlEncode = (value) =>
  Buffer.from(value)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

const base64urlDecode = (value) =>
  Buffer.from(value.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');

const hashPassword = (password) => bcrypt.hashSync(password, 10);
const verifyPassword = (password, hash) => bcrypt.compareSync(password, hash);
const isValidEmail = (email) =>
  typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

const generateTracking = () =>
  'TRK' + Math.floor(100000 + Math.random() * 900000);

const getEventDate = (event) => new Date(event.timestamp || event.date || 0).getTime();

const getTrackingHistory = (shipment) => {
  const history = Array.isArray(shipment.trackingHistory)
    ? shipment.trackingHistory
    : [{
        status: shipment.status,
        location: shipment.location,
        timestamp: shipment.date,
        message: shipment.description || shipment.message
      }];

  return history.sort((first, second) => getEventDate(first) - getEventDate(second));
};

// ================= USER SYSTEM =================

const generateToken = (user) => {
  const payload = JSON.stringify({
    email: user.email || user.username,
    role: user.role || 'user',
    exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24
  });
  const signature = crypto
    .createHmac('sha256', AUTH_SECRET)
    .update(payload)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  return `${base64urlEncode(payload)}.${signature}`;
};

const verifyToken = (token) => {
  if (!token || !token.includes('.')) return null;

  const [payloadPart, signature] = token.split('.');
  const payload = base64urlDecode(payloadPart);
  const expectedSignature = crypto
    .createHmac('sha256', AUTH_SECRET)
    .update(payload)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  const signaturesMatch =
    signature.length === expectedSignature.length &&
    crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature));

  if (!signaturesMatch) {
    return null;
  }

  try {
    const parsed = JSON.parse(payload);
    if (parsed.exp && parsed.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
};

const requireAuth = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Authorization header missing or invalid' });
  }

  const token = authHeader.slice(7);
  const user = verifyToken(token);

  if (!user) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }

  req.user = user;
  next();
};

const requireAdmin = (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admin access required' });
  }
  next();
};

const ensureAdminAccount = () => {
  if (!ADMIN_EMAIL || !ADMIN_PASSWORD) {
    return;
  }

  const users = readUsers();
  if (users.find(u => u.email === ADMIN_EMAIL)) {
    return;
  }

  users.push({
    id: crypto.randomUUID(),
    email: ADMIN_EMAIL,
    role: 'admin',
    passwordHash: hashPassword(ADMIN_PASSWORD),
    createdAt: new Date().toISOString()
  });
  writeUsers(users);
  console.log('Created initial admin user.');
};

ensureAdminAccount();

// ADMIN REGISTER: only authenticated administrators can create administrators.
app.post('/admin/register', requireAuth, requireAdmin, (req, res) => {
  const { email, password } = req.body;
  const normalizedEmail = typeof email === 'string' ? email.trim().toLowerCase() : '';

  if (!isValidEmail(normalizedEmail)) {
    return res.status(400).json({ message: 'A valid email is required' });
  }

  if (typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ message: 'Password must be at least 8 characters' });
  }

  const users = readUsers();
  if (users.some(user => (user.email || '').toLowerCase() === normalizedEmail)) {
    return res.status(409).json({ message: 'User already exists' });
  }

  const newAdmin = {
    id: crypto.randomUUID(),
    email: normalizedEmail,
    role: 'admin',
    passwordHash: hashPassword(password),
    createdAt: new Date().toISOString()
  };

  users.push(newAdmin);
  writeUsers(users);

  return res.status(201).json({
    user: {
      email: newAdmin.email,
      role: newAdmin.role
    }
  });
});

// REGISTER
app.post('/register', (req, res) => {
  const users = readUsers();
  const { username, email, password } = req.body;
  const accountEmail = email || username;

  if (!accountEmail || !password) {
    return res.status(400).json({ message: 'Fill all fields' });
  }

  if (users.find(u => u.email === accountEmail || u.username === accountEmail)) {
    return res.status(400).json({ message: 'User already exists' });
  }

  const newUser = {
    email: accountEmail,
    role: 'user',
    passwordHash: hashPassword(password),
    createdAt: new Date().toISOString()
  };

  if (username) {
    newUser.username = username;
  }

  users.push(newUser);
  writeUsers(users);

  res.json({ message: 'Account created successfully' });
});

// LOGIN
app.post('/login', (req, res) => {
  const users = readUsers();
  const { email, username, password } = req.body;
  const loginId = email || username;

  if (!loginId || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  const user = users.find(
    u => u.email === loginId || u.username === loginId
  );

  if (!user) {
    return res.status(401).json({ message: 'Invalid login' });
  }

  const isValid = user.passwordHash
    ? verifyPassword(password, user.passwordHash)
    : user.password === password;

  if (!isValid) {
    return res.status(401).json({ message: 'Invalid login' });
  }

  const token = generateToken(user);
  res.json({
    token,
    user: {
      email: user.email || user.username,
      role: user.role || 'user'
    }
  });
});

// ================= SHIPMENT =================

// CREATE
app.post('/create-shipment', (req, res) => {
  const data = readData();
  const createdAt = new Date().toISOString();

  const shipment = {
    trackingNumber: generateTracking(),
    sender: req.body.sender,
    receiver: req.body.receiver,
    origin: req.body.origin,
    destination: req.body.destination,
    status: "Processing",
    location: "Warehouse",
    date: createdAt,
    trackingHistory: [{
      status: "Shipment created",
      location: "Warehouse",
      timestamp: createdAt,
      message: "Item received"
    }]
  };

  data.push(shipment);
  writeData(data);

  res.json({ trackingNumber: shipment.trackingNumber });
});

// GET ALL (ADMIN)
app.get('/admin/shipments', requireAuth, requireAdmin, (req, res) => {
  res.json(readData());
});

// UPDATE STATUS
const updateShipmentStatus = (req, res) => {
  const trackingNumber = req.params.trackingNumber || req.body.trackingNumber;
  const { status, location, timestamp, date, message, description } = req.body;
  const data = readData();

  if (!trackingNumber || !status) {
    return res.status(400).json({ message: "trackingNumber and status are required" });
  }

  const shipment = data.find(s => s.trackingNumber === trackingNumber);

  if (!shipment) {
    return res.status(404).json({ message: "Shipment not found" });
  }

  const eventTimestamp = timestamp || date || new Date().toISOString();
  const event = {
    status,
    location: location || shipment.location,
    timestamp: eventTimestamp
  };

  if (message || description) {
    event.message = message || description;
  }

  shipment.status = status;
  shipment.location = event.location;
  shipment.date = eventTimestamp;
  shipment.trackingHistory = getTrackingHistory(shipment);
  shipment.trackingHistory.push(event);
  shipment.trackingHistory.sort((first, second) => getEventDate(first) - getEventDate(second));

  writeData(data);

  res.json({ message: "Shipment status updated successfully", shipment });
};

app.post('/admin/update-shipment/:trackingNumber', requireAuth, requireAdmin, updateShipmentStatus);

// TRACK
app.get('/track/:trackingNumber', (req, res) => {
  const data = readData();

  const shipment = data.find(s => s.trackingNumber === req.params.trackingNumber);

  if (!shipment) {
    return res.status(404).json({ message: "Not found" });
  }

  res.json({
    ...shipment,
    trackingHistory: getTrackingHistory(shipment)
  });
});

// HOME
app.get('/', (req, res) => {
  res.send("Backend running 🚀");
});

app.listen(PORT, () => {
  console.log("Server running...");
});
