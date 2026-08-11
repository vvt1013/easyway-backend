const express = require('express');
const cors = require('cors');
const fs = require('fs');

const app = express();
app.use(cors());
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

// SIGNUP
app.post('/signup', (req, res) => {
  const users = readUsers();
  const { username, password } = req.body;

  if (!username || !password) {
    return res.json({ message: "Fill all fields" });
  }

  if (users.find(u => u.username === username)) {
    return res.json({ message: "User already exists" });
  }

  users.push({ username, password });
  writeUsers(users);

  res.json({ message: "Account created successfully" });
});

// LOGIN
app.post('/login', (req, res) => {
  const users = readUsers();
  const { username, password } = req.body;

  const user = users.find(u => u.username === username && u.password === password);

  if (!user) {
    return res.json({ message: "Invalid login" });
  }

  res.json({ message: "Login successful" });
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
app.get('/shipments', (req, res) => {
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

app.post('/update-status', updateShipmentStatus);
app.put('/update-status/:trackingNumber', updateShipmentStatus);
app.patch('/shipments/:trackingNumber', updateShipmentStatus);
app.put('/shipments/:trackingNumber/status', updateShipmentStatus);

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
