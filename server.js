#!/usr/bin/env node

const express = require('express');
const bodyParser = require('body-parser');
const { getRouter } = require('stremio-addon-sdk');
const addonInterface = require('./addon');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const mongoose = require('mongoose'); // ++ NAHRADILI JSME lowdb za mongoose

// —— CONFIG ——
// Heslo a uživatel pro admina se nyní nastavují přes Environment Variables na Vercelu
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'secret';
const MOUNT_PATH = '/:token/:deviceMac';
const MAC_REGEX = /^[0-9A-F]{2}(?::[0-9A-F]{2}){5}$/i;

// ++ MONGOOSE DATABASE SETUP ++

// Připojovací řetězec bereme z Environment Variable na Vercelu
const MONGODB_URI = process.env.MONGODB_URI;

// Funkce pro připojení k databázi (optimalizováno pro serverless prostředí jako Vercel)
let conn = null;
const connectDB = async () => {
  if (conn == null) {
    console.log('Creating new database connection...');
    conn = mongoose.connect(MONGODB_URI, {
      serverSelectionTimeoutMS: 5000, // Timeout po 5s pokud se nepřipojí
    }).then(() => mongoose);
    // Vyhneme se duplicitním připojením při čekání
    await conn;
  }
  console.log('Database connection established.');
  return conn;
};

// Schéma pro uživatele
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, index: true },
  hash: { type: String, required: true },
  expiresAt: { type: Date, required: true },
});
const User = mongoose.models.User || mongoose.model('User', UserSchema);

// Schéma pro tokeny/zařízení
const TokenSchema = new mongoose.Schema({
  username: { type: String, required: true, index: true },
  token: { type: String, required: true, unique: true },
  deviceId: { type: String, required: true },
  userAgent: { type: String },
});
// Umožní rychlé vyhledávání podle tokenu a zařízení
TokenSchema.index({ token: 1, deviceId: 1 });
const Token = mongoose.models.Token || mongoose.model('Token', TokenSchema);


// —— EXPRESS SETUP ——
const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Připojení k DB hned na začátku
app.use(async (req, res, next) => {
  try {
    await connectDB();
    next();
  } catch (error) {
    console.error('Database connection error:', error);
    res.status(500).send('Could not connect to the database.');
  }
});


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
  // ++ Převedeno na mongoose
  const users = await User.find().lean();
  const tokens = await Token.find().lean();
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  const protocol = req.headers['x-forwarded-proto'] || 'https';

  let rowsHtml = '';
  users.forEach(u => {
    const userTokens = tokens.filter(t => t.username === u.username);
    if (userTokens.length === 0) {
        // Zobrazit uživatele i pokud nemá žádné zařízení
        const exp = new Date(u.expiresAt).toLocaleString();
         rowsHtml += `<tr><td>${u.username}</td><td>${exp}</td><td colspan="3">Žádné zařízení</td>
         <td>
            <form style="display:inline" method="POST" action="/admin/reset">
               <input type="hidden" name="username"  value="${u.username}">
               <input type="number" name="daysValid" min="1" placeholder="Days" required>
               <button>Reset</button>
            </form>
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
              <td>${tkn.token}</td>
              <td><a href="${url}" target="_blank">Install URL</a></td>
              <td>
                <form style="display:inline" method="POST" action="/admin/revoke">
                  <input type="hidden" name="username" value="${u.username}">
                  <input type="hidden" name="deviceMac" value="${tkn.deviceId}">
                  <button>Revoke</button>
                </form>
                <form style="display:inline" method="POST" action="/admin/reset">
                  <input type="hidden" name="username"  value="${u.username}">
                  <input type="number" name="daysValid" min="1" placeholder="Days" required>
                  <button>Reset</button>
                </form>
              </td>
            </tr>`;
        });
    }
  });

  const html = `
    <!DOCTYPE html><html><head><meta charset="utf-8"><title>Admin Dashboard</title><style>body{font-family:sans-serif;max-width:900px;margin:auto;} table{width:100%; border-collapse: collapse;} th,td{border:1px solid #ccc; padding: 8px; text-align:left;} form{margin-bottom:2em;}</style></head>
    <body>
      <h1>Admin Dashboard</h1>
      <h2>Register New User</h2>
      <form method="POST" action="/admin/register">
        <label>Username:<br><input name="username" required></label><br>
        <label>Password:<br><input type="password" name="password" required></label><br>
        <label>Device MAC:<br><input name="deviceMac" required placeholder="AA:BB:CC:DD:EE:FF"></label><br>
        <label>Days Valid:<br><input name="daysValid" type="number" min="1" required></label><br>
        <button>Create</button>
      </form>
      <h2>Add Device to Existing User</h2>
      <form method="POST" action="/admin/add-device">
        <label>Username:<br><select name="username">${users.map(u => `<option>${u.username}</option>`).join('')}</select></label><br>
        <label>Device MAC:<br><input name="deviceMac" required placeholder="AA:BB:CC:DD:EE:FF"></label><br>
        <button>Add Device</button>
      </form>
      <h2>Existing Users & Devices</h2>
      <table>
        <tr><th>User</th><th>Expires</th><th>Device MAC</th><th>Token</th><th>Install Link</th><th>Actions</th></tr>
        ${rowsHtml}
      </table>
    </body></html>`;

  res.send(html);
});

// —— ADMIN ACTIONS ——
app.post('/admin/register', adminAuth, async (req, res) => {
  // ++ Převedeno na mongoose
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
    // ++ Převedeno na mongoose
  const { username, deviceMac } = req.body;
  if (!username || !deviceMac) return res.status(400).send('Fields required');
  if (!MAC_REGEX.test(deviceMac)) return res.status(400).send('Bad MAC format');
  if (!await User.findOne({ username })) return res.status(404).send('No such user');
  
  const token = uuidv4();
  await Token.create({ username, token, deviceId: deviceMac });

  res.redirect('/admin');
});

app.post('/admin/revoke', adminAuth, async (req, res) => {
    // ++ Převedeno na mongoose
  const { username, deviceMac } = req.body;
  await Token.deleteOne({ username, deviceId: deviceMac });
  res.redirect('/admin');
});

app.post('/admin/reset', adminAuth, async (req, res) => {
    // ++ Převedeno na mongoose
  const { username, daysValid } = req.body;
  if (!daysValid) return res.status(400).send('Days required');
  await User.findOneAndUpdate({ username }, { expiresAt: calcExpiry(+daysValid) });
  res.redirect('/admin');
});

// —— PUBLIC ENDPOINTS (ponecháno pro případnou API integraci) ——
app.post('/register', async (req, res) => {
    // ++ Převedeno na mongoose
  const { username, password, daysValid } = req.body;
  if (!username || !password || !daysValid) return res.status(400).json({ error: 'username,password,daysValid required' });
  if (await User.findOne({ username })) return res.status(409).json({ error: 'User exists' });

  const hash = await bcrypt.hash(password, 10);
  await User.create({ username, hash, expiresAt: calcExpiry(+daysValid) });
  res.json({ message: 'Registered!' });
});

app.post('/login', async (req, res) => {
    // ++ Převedeno na mongoose
  const { username, password, deviceId } = req.body;
  if (!username || !password || !deviceId) return res.status(400).json({ error: 'username,password,deviceId required' });
  if (!MAC_REGEX.test(deviceId)) return res.status(400).json({ error: 'Bad MAC format' });

  const user = await User.findOne({ username });
  if (!user || !(await bcrypt.compare(password, user.hash))) return res.status(401).json({ error: 'Invalid creds' });
  if (Date.now() > user.expiresAt) return res.status(403).json({ error: 'Account expired' });

  let entry = await Token.findOne({ username, deviceId });
  let token = entry ? entry.token : uuidv4();
  if (!entry) {
    await Token.create({ username, token, deviceId });
  }
  res.json({ token });
});

// —— PROTECT, UA‑LOCK & MOUNT ADDON ——
app.use(MOUNT_PATH, async (req, res, next) => {
  // ++ Převedeno na mongoose
  const { token, deviceMac } = req.params;
  if (!MAC_REGEX.test(deviceMac)) return res.status(400).end('Bad MAC format');

  const entry = await Token.findOne({ token, deviceId: deviceMac });
  if (!entry) return res.status(401).end('Invalid token/device');

  const user = await User.findOne({ username: entry.username });
  if (!user) return res.status(401).end('User not found'); // Pojistka
  if (Date.now() > user.expiresAt) return res.status(403).end('Account expired');

  // UA-lock a manifest se nyní kontroluje uvnitř, po kontrole expirace
  if (req.path.endsWith('/manifest.json')) {
    return next();
  }

  if (req.method === 'GET' && req.path.match(/\/stream\//)) {
    const ua = req.headers['user-agent'] || '';
    if (!entry.userAgent) {
      await Token.updateOne({ _id: entry._id }, { userAgent: ua });
    } else if (entry.userAgent !== ua) {
      return res.json({ streams: [{
        name: "🔒 Chyba",
        title: 'Tento účet je již používán na jiném zařízení.',
        url: 'https://via.placeholder.com/1280x720/000000/FFFFFF?text=Error:%20Device%20lock'
      }]});
    }
  }

  next();
});
app.use(MOUNT_PATH, getRouter(addonInterface));

// -- START SERVER --
// Původní app.listen je odstraněno. Vercel spouští server automaticky.
// Místo toho exportujeme `app` pro Vercel.
module.exports = app;