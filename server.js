#!/usr/bin/env node

const express = require('express');
const bodyParser = require('body-parser');
const { getRouter } = require('stremio-addon-sdk');
const addonInterface = require('./addon');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');

// —— CONFIG ——
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'secret';
const MOUNT_PATH = '/:token/:deviceMac';
const MAC_REGEX = /^[0-9A-F]{2}(?::[0-9A-F]{2}){5}$/i;

const MONGODB_URI = process.env.MONGODB_URI;
let conn = null;

async function connectDB() {
  if (conn == null) {
    conn = mongoose.connect(MONGODB_URI, { serverSelectionTimeoutMS: 5000 }).then(() => mongoose);
    await conn;
  }
  return conn;
};

// --- Schemas ---
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, index: true },
  hash: { type: String, required: true },
  expiresAt: { type: Date, required: true },
});
const User = mongoose.models.User || mongoose.model('User', UserSchema);

const TokenSchema = new mongoose.Schema({
  username: { type: String, required: true, index: true },
  token: { type: String, required: true, unique: true },
  deviceId: { type: String, required: true },
});
TokenSchema.index({ token: 1, deviceId: 1 });
const Token = mongoose.models.Token || mongoose.model('Token', TokenSchema);

const app = express();

// Middleware to handle database connection first
app.use(async (req, res, next) => {
  try {
    await connectDB();
    next();
  } catch (error) {
    console.error('Database connection failed:', error);
    return res.status(500).send('Database connection failed.');
  }
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));


// --- Admin Authentication ---
function adminAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Basic ')) {
    res.set('WWW-Authenticate', 'Basic realm="Admin Area"');
    return res.status(401).send('Auth required');
  }
  const [u, p] = Buffer.from(auth.split(' ')[1], 'base64').toString().split(':');
  if (u === ADMIN_USER && p === ADMIN_PASS) return next();
  res.set('WWW-Authenticate', 'Basic realm="Admin Area"');
  return res.status(401).send('Invalid credentials');
}

function calcExpiry(days) {
  return Date.now() + days * 24 * 60 * 60 * 1000;
}


// —— ADMIN DASHBOARD ——
app.get('/admin', adminAuth, async (req, res) => {
    const users = await User.find().lean();
    const tokens = await Token.find().lean();
    const host = req.headers['x-forwarded-host'] || req.headers.host;
    const protocol = req.headers['x-forwarded-proto'] || 'https';

    let rowsHtml = '';
    users.forEach(u => {
        const userTokens = tokens.filter(t => t.username === u.username);
        if (userTokens.length === 0) {
            const exp = new Date(u.expiresAt).toLocaleString();
            rowsHtml += `<tr><td>${u.username}</td><td>${exp}</td><td colspan="3">No devices</td><td>
                            <form style="display:inline" method="POST" action="/admin/reset"><input type="hidden" name="username"  value="${u.username}"><input type="number" name="daysValid" min="1" placeholder="Days" required><button>Reset</button></form>
                        </td></tr>`;
        } else {
            userTokens.forEach(tkn => {
                const exp = new Date(u.expiresAt).toLocaleString();
                const url = `${protocol}://${host}/${tkn.token}/${tkn.deviceId}/manifest.json`;
                rowsHtml += `
                    <tr>
                        <td>${u.username}</td>
                        <td>${exp}</td>
                        <td>${tkn.deviceId}</td>
                        <td><a href="${url}" target="_blank">Install URL</a></td>
                        <td>
                            <form style="display:inline" method="POST" action="/admin/revoke"><input type="hidden" name="username" value="${u.username}"><input type="hidden" name="deviceMac" value="${tkn.deviceId}"><button>Revoke</button></form>
                            <form style="display:inline" method="POST" action="/admin/reset"><input type="hidden" name="username" value="${u.username}"><input type="number" name="daysValid" min="1" placeholder="Days" required><button>Reset</button></form>
                        </td>
                    </tr>`;
            });
        }
    });

    const html = `
    <!DOCTYPE html><html><head><meta charset="utf-8"><title>Admin Dashboard</title><style>body{font-family:sans-serif;max-width:1100px;margin:auto;} table{width:100%; border-collapse: collapse;} th,td{border:1px solid #ccc; padding: 8px; text-align:left;} form{margin-bottom:2em;}</style></head>
    <body>
      <h1>Admin Dashboard</h1>
      <h2>Register New User</h2>
      <form method="POST" action="/admin/register"><label>Username:<br><input name="username" required></label><br><label>Password:<br><input type="password" name="password" required></label><br><label>Device MAC:<br><input name="deviceMac" required placeholder="AA:BB:CC:DD:EE:FF"></label><br><label>Days Valid:<br><input name="daysValid" type="number" min="1" required></label><br><button>Create</button></form>
      <h2>Add Device to Existing User</h2>
      <form method="POST" action="/admin/add-device"><label>Username:<br><select name="username">${users.map(u => `<option>${u.username}</option>`).join('')}</select></label><br><label>Device MAC:<br><input name="deviceMac" required placeholder="AA:BB:CC:DD:EE:FF"></label><br><button>Add Device</button></form>
      <h2>Existing Users & Devices</h2>
      <table><tr><th>User</th><th>Expires</th><th>Device MAC</th><th>Install Link</th><th>Actions</th></tr>${rowsHtml}</table>
    </body></html>`;
    res.send(html);
});

// —— ADMIN ACTIONS ——
app.post('/admin/register', adminAuth, async (req, res) => {
    const { username, password, daysValid, deviceMac } = req.body;
    if (!username || !password || !daysValid || !deviceMac) return res.status(400).send('All fields required');
    if (!MAC_REGEX.test(deviceMac)) return res.status(400).send('Bad MAC format');
    if (await User.findOne({ username })) return res.status(409).send('User exists');
    const hash = await bcrypt.hash(password, 10);
    await User.create({ username, hash, expiresAt: calcExpiry(+daysValid) });
    const token = uuidv4();
    await Token.create({ username, token, deviceId: deviceMac });
    res.redirect('/admin');
});
app.post('/admin/add-device', adminAuth, async (req, res) => {
    const { username, deviceMac } = req.body;
    if (!username || !deviceMac) return res.status(400).send('Fields required');
    if (!MAC_REGEX.test(deviceMac)) return res.status(400).send('Bad MAC format');
    if (!await User.findOne({ username })) return res.status(404).send('No such user');
    const token = uuidv4();
    await Token.create({ username, token, deviceId: deviceMac });
    res.redirect('/admin');
});
app.post('/admin/revoke', adminAuth, async (req, res) => {
    const { username, deviceMac } = req.body;
    await Token.deleteOne({ username, deviceId: deviceMac });
    res.redirect('/admin');
});
app.post('/admin/reset', adminAuth, async (req, res) => {
    const { username, daysValid } = req.body;
    if (!daysValid) return res.status(400).send('Days required');
    await User.findOneAndUpdate({ username }, { expiresAt: calcExpiry(+daysValid) });
    res.redirect('/admin');
});

// --- Core Addon Authentication and Router ---
const authMiddleware = async (req, res, next) => {
    const { token, deviceMac } = req.params;
    if (!token || !deviceMac || !MAC_REGEX.test(deviceMac)) {
        return res.status(400).send('Bad request: Invalid token or MAC
