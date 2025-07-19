#!/usr/bin/env node

const express        = require('express');
const bodyParser     = require('body-parser');
const { getRouter }  = require('stremio-addon-sdk');
const addonInterface = require('./addon');
const bcrypt         = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const low            = require('lowdb');
const FileSync       = require('lowdb/adapters/FileSync');

// —— CONFIG ——
const ADMIN_USER = 'admin';
const ADMIN_PASS = 'secret';
const PORT       = process.env.PORT || 8000;
const MOUNT_PATH = '/:token/:deviceMac';
const MAC_REGEX  = /^[0-9A-F]{2}(?::[0-9A-F]{2}){5}$/i;

// —— DB SETUP ——
const adapter = new FileSync('db.json');
const db      = low(adapter);
db.defaults({ users: [], tokens: [] }).write();

// —— EXPRESS SETUP ——
const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

function adminAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Basic ')) {
    res.set('WWW-Authenticate','Basic realm="Admin Area"');
    return res.status(401).send('Auth required');
  }
  const [u,p] = Buffer.from(auth.split(' ')[1], 'base64').toString().split(':');
  if (u === ADMIN_USER && p === ADMIN_PASS) return next();
  res.set('WWW-Authenticate','Basic realm="Admin Area"');
  return res.status(401).send('Invalid credentials');
}

function calcExpiry(days) {
  return Date.now() + days * 24 * 60 * 60 * 1000;
}

// —— ADMIN DASHBOARD ——
app.get('/admin', adminAuth, (req, res) => {
  const users  = db.get('users').value();
  const tokens = db.get('tokens').value();
  const host   = req.headers.host; // e.g. "192.168.1.5:8000"

  // Build table rows with install links
  let rowsHtml = '';
  users.forEach(u => {
    const userTokens = tokens.filter(t => t.username === u.username);
    userTokens.forEach(tkn => {
      const exp = new Date(u.expiresAt).toLocaleString();
      const url = 'http://' + host + '/' + tkn.token + '/' + tkn.deviceId + '/manifest.json';
      rowsHtml += ''
        + '<tr>'
        +   '<td>' + u.username        + '</td>'
        +   '<td>' + exp               + '</td>'
        +   '<td>' + tkn.deviceId      + '</td>'
        +   '<td>' + tkn.token         + '</td>'
        +   '<td><a href="' + url + '" target="_blank">Install URL</a></td>'
        +   '<td>'
        +     '<form style="display:inline" method="POST" action="/admin/revoke">'
        +       '<input type="hidden" name="username" value="' + u.username + '">'
        +       '<input type="hidden" name="deviceMac" value="' + tkn.deviceId + '">'
        +       '<button>Revoke</button>'
        +     '</form> '
        +     '<form style="display:inline" method="POST" action="/admin/reset">'
        +       '<input type="hidden" name="username" value="' + u.username + '">'
        +       '<input type="number" name="daysValid" min="1" placeholder="Days">'
        +       '<button>Reset</button>'
        +     '</form>'
        +   '</td>'
        + '</tr>';
    });
  });

  // Build the full HTML
  const html = ''
    + '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Admin Dashboard</title></head>'
    + '<body style="font-family:sans-serif;max-width:900px;margin:auto;">'
    +   '<h1>Admin Dashboard</h1>'

    +   '<h2>Register New User</h2>'
    +   '<form method="POST" action="/admin/register">'
    +     '<label>Username:<br><input name="username" required></label><br>'
    +     '<label>Password:<br><input type="password" name="password" required></label><br>'
    +     '<label>Device MAC:<br><input name="deviceMac" required placeholder="AA:BB:CC:DD:EE:FF"></label><br>'
    +     '<label>Days Valid:<br><input name="daysValid" type="number" min="1" required></label><br>'
    +     '<button>Create</button>'
    +   '</form>'

    +   '<h2>Existing Users & Devices</h2>'
    +   '<table border="1" cellpadding="5" cellspacing="0" width="100%">'
    +     '<tr><th>User</th><th>Expires</th><th>Device MAC</th><th>Token</th><th>Install Link</th><th>Actions</th></tr>'
    +     rowsHtml
    +   '</table>'

    +   '<h2>Add Device to Existing User</h2>'
    +   '<form method="POST" action="/admin/add-device">'
    +     '<label>Username:<br><select name="username">'
    +       users.map(u => '<option>' + u.username + '</option>').join('')
    +     '</select></label><br>'
    +     '<label>Device MAC:<br><input name="deviceMac" required placeholder="AA:BB:CC:DD:EE:FF"></label><br>'
    +     '<button>Add Device</button>'
    +   '</form>'

    + '</body></html>';

  res.send(html);
});

// —— ADMIN ACTIONS ——
app.post('/admin/register', adminAuth, async (req, res) => {
  const { username, password, daysValid, deviceMac } = req.body;
  if (!username || !password || !daysValid || !deviceMac) {
    return res.status(400).send('All fields required');
  }
  if (!MAC_REGEX.test(deviceMac)) {
    return res.status(400).send('Bad MAC format');
  }
  if (db.get('users').find({ username }).value()) {
    return res.status(409).send('User exists');
  }
  const hash = await bcrypt.hash(password, 10);
  db.get('users')
    .push({ username, hash, expiresAt: calcExpiry(+daysValid) })
    .write();
  const token = uuidv4();
  db.get('tokens')
    .push({ username, token, deviceId: deviceMac })
    .write();
  res.redirect('/admin');
});

app.post('/admin/add-device', adminAuth, (req, res) => {
  const { username, deviceMac } = req.body;
  if (!username || !deviceMac) {
    return res.status(400).send('Fields required');
  }
  if (!MAC_REGEX.test(deviceMac)) {
    return res.status(400).send('Bad MAC format');
  }
  if (!db.get('users').find({ username }).value()) {
    return res.status(404).send('No such user');
  }
  const token = uuidv4();
  db.get('tokens')
    .push({ username, token, deviceId: deviceMac })
    .write();
  res.redirect('/admin');
});

app.post('/admin/revoke', adminAuth, (req, res) => {
  const { username, deviceMac } = req.body;
  db.get('tokens').remove({ username, deviceId: deviceMac }).write();
  res.redirect('/admin');
});

app.post('/admin/reset', adminAuth, (req, res) => {
  const { username, daysValid } = req.body;
  if (!daysValid) return res.status(400).send('Days required');
  db.get('users')
    .find({ username })
    .assign({ expiresAt: calcExpiry(+daysValid) })
    .write();
  res.redirect('/admin');
});

// —— PUBLIC ENDPOINTS ——
app.post('/register', async (req, res) => {
  const { username, password, daysValid } = req.body;
  if (!username || !password || !daysValid) {
    return res.status(400).json({ error: 'username,password,daysValid required' });
  }
  if (db.get('users').find({ username }).value()) {
    return res.status(409).json({ error: 'User exists' });
  }
  const hash = await bcrypt.hash(password, 10);
  db.get('users')
    .push({ username, hash, expiresAt: calcExpiry(+daysValid) })
    .write();
  res.json({ message: 'Registered!' });
});

app.post('/login', async (req, res) => {
  const { username, password, deviceId } = req.body;
  if (!username || !password || !deviceId) {
    return res.status(400).json({ error: 'username,password,deviceId required' });
  }
  if (!MAC_REGEX.test(deviceId)) {
    return res.status(400).json({ error: 'Bad MAC format' });
  }
  const user = db.get('users').find({ username }).value();
  if (!user || !(await bcrypt.compare(password, user.hash))) {
    return res.status(401).json({ error: 'Invalid creds' });
  }
  if (Date.now() > user.expiresAt) {
    return res.status(403).json({ error: 'Account expired' });
  }
  let entry = db.get('tokens').find({ username, deviceId }).value();
  let token = entry ? entry.token : uuidv4();
  if (!entry) {
    db.get('tokens')
      .push({ username, token, deviceId })
      .write();
  }
  res.json({ token });
});

// —— PROTECT & MOUNT ADDON ——
app.use(MOUNT_PATH, (req, res, next) => {
  const { token, deviceMac } = req.params;
  if (!MAC_REGEX.test(deviceMac)) {
    return res.status(400).end('Bad MAC format');
  }
  const entry = db.get('tokens').find({ token, deviceId: deviceMac }).value();
  if (!entry) {
    return res.status(401).end('Invalid token/device');
  }
  const usr = db.get('users').find({ username: entry.username }).value();
  if (Date.now() > usr.expiresAt) {
    return res.status(403).end('Account expired');
  }
  next();
});
app.use(MOUNT_PATH, getRouter(addonInterface));

// —— START SERVER ——
app.listen(PORT, () => {
  console.log(
    `🚀 Addon running at http://127.0.0.1:${PORT}${MOUNT_PATH}/manifest.json`
  );
});
