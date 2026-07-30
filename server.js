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

  const shipment = {
    trackingNumber: generateTracking(),
    sender: req.body.sender,
    receiver: req.body.receiver,
    origin: req.body.origin,
    destination: req.body.destination,
    status: "Processing",
    location: "Warehouse",
    date: new Date().toLocaleString()
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
app.post('/update-status', (req, res) => {
  const { trackingNumber, status, location } = req.body;
  const data = readData();

  const shipment = data.find(s => s.trackingNumber === trackingNumber);

  if (!shipment) {
    return res.json({ message: "Not found" });
  }

  shipment.status = status;
  shipment.location = location;
  shipment.date = new Date().toLocaleString();

  writeData(data);

  res.json({ message: "Updated successfully" });
});

// TRACK
app.get('/track/:trackingNumber', (req, res) => {
  const data = readData();

  const shipment = data.find(s => s.trackingNumber === req.params.trackingNumber);

  if (!shipment) {
    return res.status(404).json({ message: "Not found" });
  }

  res.json(shipment);
});

// HOME
app.get('/', (req, res) => {
  res.send("Backend running 🚀");
});

app.listen(PORT, () => {
  console.log("Server running...");
});