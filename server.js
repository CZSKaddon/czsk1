#!/usr/bin/env node

const express = require('express');
const bodyParser = require('body-parser');
const { getRouter } = require('stremio-addon-sdk');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const mongoose = require('mongoose');
const axios = require('axios');
const crypto = require('crypto');

// Načteme si pomocné funkce z addon.js
const { 
    addonInterface,
    searchWebshare, 
    getWebshareStreamUrl, 
    searchHellspy, 
    getStreamUrl, 
    getTitleFromWikidata, 
    searchSeriesWithPattern,
    isLikelyEpisode
} = require('./addon');

// —— CONFIG ——
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'secret';
const MOUNT_PATH = '/:token/:deviceMac';
const MAC_REGEX = /^[0-9A-F]{2}(?::[0-9A-F]{2}){5}$/i;

// ++ MONGOOSE DATABASE SETUP ++
const MONGODB_URI = process.env.MONGODB_URI;
let conn = null;

const connectDB = async () => {
  if (conn == null) {
    conn = mongoose.connect(MONGODB_URI, { serverSelectionTimeoutMS: 5000 }).then(() => mongoose);
    await conn;
  }
  return conn;
};

// Schéma pro uživatele
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, index: true },
  hash: { type: String, required: true },
  expiresAt: { type: Date, required: true },
});
const User = mongoose.models.User || mongoose.model('User', UserSchema);

// ++ UPRAVENO: Schéma pro tokeny s WST a logováním ++
const TokenSchema = new mongoose.Schema({
  username: { type: String, required: true, index: true },
  token: { type: String, required: true, unique: true },
  deviceId: { type: String, required: true },
  wst: { type: String }, // Webshare Token
  userAgent: { type: String },
  lastWatchedType: { type: String },
  lastWatchedImdbId: { type: String },
  lastWatchedInfo: { type: String },
  lastWatchedAt: { type: Date },
  lastIpAddress: { type: String },
  lastUserAgent: { type: String },
});
TokenSchema.index({ token: 1, deviceId: 1 });
const Token = mongoose.models.Token || mongoose.model('Token', TokenSchema);

// —— EXPRESS SETUP ——
const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(async (req, res, next) => {
  try {
    await connectDB();
    next();
  } catch (error) {
    console.error('Database connection error:', error);
    res.status(500).send('Could not connect to the database.');
  }
});

// ++ HELPER FUNKCE PRO WEBSHARE ++
async function getWst(username, password) {
    if (!username || !password) return null;
    try {
        const saltResponse = await axios.get('https://webshare.cz/api/salt/', { params: { login: username } });
        const saltMatch = saltResponse.data.match(/<salt>(.*?)<\/salt>/);
        if (!saltMatch) throw new Error('Could not get salt from Webshare');
        const salt = saltMatch[1];
        const hashedPassword = crypto.createHash('sha1').update(password).digest('hex');
        const finalHash = crypto.createHash('sha1').update(salt + hashedPassword).digest('hex');
        return finalHash;
    } catch (error) {
        console.error('Error getting WST:', error.message);
        return null;
    }
}

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
         rowsHtml += `<tr><td>${u.username}</td><td>${exp}</td><td colspan="4">No devices</td></tr>`;
    } else {
        userTokens.forEach(tkn => {
          const exp = new Date(u.expiresAt).toLocaleString();
          const url = `${protocol}://${host}/${tkn.token}/${tkn.deviceId}/manifest.json`;
          rowsHtml += `
            <tr>
              <td>${u.username}</td>
              <td>${exp}</td>
              <td>${tkn.deviceId}</td>
              <td>${tkn.wst ? 'Ano' : 'Ne'}</td>
              <td><a href="${url}" target="_blank">Install URL</a></td>
              <td>
                 <form style="display:inline" method="POST" action="/admin/revoke"><input type="hidden" name="username" value="${u.username}"><input type="hidden" name="deviceMac" value="${tkn.deviceId}"><button>Revoke</button></form>
                 <form style="display:inline" method="POST" action="/admin/reset"><input type="hidden" name="username"  value="${u.username}"><input type="number" name="daysValid" min="1" placeholder="Days" required><button>Reset</button></form>
              </td>
            </tr>`;
        });
    }
  });

  const html = `
    <!DOCTYPE html><html><head><meta charset="utf-8"><title>Admin Dashboard</title><style>body{font-family:sans-serif;max-width:1100px;margin:auto;} table{width:100%; border-collapse: collapse;} th,td{border:1px solid #ccc; padding: 8px; text-align:left;} form{margin-bottom:2em;}</style></head>
    <body>
      <h1>Admin Dashboard</h1>
      <h2>Register New User / Add Device</h2>
      <form method="POST" action="/admin/add">
        <label>Username:<br><input name="username" required></label><br>
        <label>Password:<br><input type="password" name="password" required></label><br>
        <label>Device MAC:<br><input name="deviceMac" required placeholder="AA:BB:CC:DD:EE:FF"></label><br>
        <label>Days Valid:<br><input name="daysValid" type="number" min="1" required></label><br>
        <hr>
        <h3>Webshare Credentials (Optional)</h3>
        <label>Webshare Username:<br><input name="wsUser"></label><br>
        <label>Webshare Password:<br><input type="password" name="wsPass"></label><br>
        <button>Create / Add Device</button>
      </form>
      <h2>Existing Users & Devices</h2>
      <table><tr><th>User</th><th>Expires</th><th>Device MAC</th><th>Webshare?</th><th>Install Link</th><th>Actions</th></tr>${rowsHtml}</table>
    </body></html>`;

  res.send(html);
});

// —— ADMIN ACTIONS ——
app.post('/admin/add', adminAuth, async (req, res) => {
    const { username, password, daysValid, deviceMac, wsUser, wsPass } = req.body;
    if (!username || !password || !daysValid || !deviceMac) return res.status(400).send('All fields required');
    if (!MAC_REGEX.test(deviceMac)) return res.status(400).send('Bad MAC format');

    let user = await User.findOne({ username });
    if (!user) {
        const hash = await bcrypt.hash(password, 10);
        user = await User.create({ username, hash, expiresAt: calcExpiry(+daysValid) });
    }

    const wst = await getWst(wsUser, wsPass);
    const token = uuidv4();
    await Token.create({ username, token, deviceId: deviceMac, wst });

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

// ++ Hlavní handler pro streamy, který je nyní zde v server.js ++
async function streamHandler(args) {
  const { type, id, config } = args;
  let { name, episode, year } = args;
  const wstToken = config ? config.wstToken : null; // Zde bude WST z databáze

  if (id.includes(":")) {
    const parts = id.split(":");
    id = parts[0];
    episode = { season: parseInt(parts[1]), number: parseInt(parts[2]) };
  }
  if (!name && id.startsWith("tt")) {
    const titleInfo = await getTitleFromWikidata(id);
    if (titleInfo) {
      name = titleInfo.czTitle || titleInfo.enTitle;
      year = titleInfo.year;
    }
  }
  if (!name) return { streams: [] };

  const simplifiedName = name.includes(":") ? name.split(":")[0].trim() : name;
  const queries = [];
  if (type === "series" && episode) {
    const seasonStr = episode.season.toString().padStart(2, "0");
    const episodeStr = episode.number.toString().padStart(2, "0");
    queries.push(`${name} S${seasonStr}E${episodeStr}`, `${name} ${seasonStr}x${episodeStr}`, `${name} - ${episodeStr}`);
    if (simplifiedName !== name) {
        queries.push(`${simplifiedName} S${seasonStr}E${episodeStr}`, `${simplifiedName} ${seasonStr}x${episodeStr}`, `${simplifiedName} - ${episodeStr}`);
    }
  } else if (type === "movie") {
    queries.push(name + (year ? " " + year : ""), name);
    if (simplifiedName !== name) {
        queries.push(simplifiedName + (year ? " " + year : ""), simplifiedName);
    }
  }

  let allResults = [];
  if (type === "series" && episode) {
      allResults = await searchSeriesWithPattern(queries, episode.season, episode.number, wstToken);
  } else {
      const searchPromises = queries.map(q => [searchHellspy(q), searchWebshare(q, wstToken)]).flat();
      const resultsByQuery = await Promise.all(searchPromises);
      allResults = resultsByQuery.flat();
  }
  
  if (allResults.length === 0) return { streams: [] };

  const streams = [];
  const processedResults = allResults.filter(r => type === 'movie' ? !isLikelyEpisode(r.title) : true);
  
  for (const result of processedResults.slice(0, 20)) {
    try {
        if (result.source === 'hellspy' && result.id && result.fileHash) {
            const streamInfo = await getStreamUrl(result.id, result.fileHash);
            if (Array.isArray(streamInfo)) {
                streamInfo.forEach(s => {
                    const sizeGB = result.size ? (result.size / 1024 / 1024 / 1024).toFixed(2) + " GB" : "";
                    streams.push({ url: s.url, title: `[Hellspy ${s.quality}] ${result.title} ${sizeGB}`, name: `Hellspy\n${s.quality}` });
                });
            }
        } else if (result.source === 'webshare' && result.ident) {
            const streamUrl = await getWebshareStreamUrl(result.ident, wstToken);
            if (streamUrl) {
                const sizeGB = result.size ? (result.size / 1024 / 1024 / 1024).toFixed(2) + " GB" : "";
                streams.push({ url: streamUrl, title: `[Webshare] ${result.title} ${sizeGB}`, name: `Webshare` });
            }
        }
    } catch (error) {
      console.error("Error processing result:", error);
    }
  }
  return { streams };
}

// —— Hlavní router doplňku ——
const builder = new addonBuilder(addonInterface.manifest);
builder.defineStreamHandler(streamHandler);
const router = getRouter(builder.getInterface());

app.use(MOUNT_PATH, async (req, res, next) => {
    const { token, deviceMac } = req.params;
    if (!MAC_REGEX.test(deviceMac)) return res.status(400).end('Bad MAC format');

    const entry = await Token.findOne({ token, deviceId: deviceMac });
    if (!entry) return res.status(401).end('Invalid token/device');

    const user = await User.findOne({ username: entry.username });
    if (!user || Date.now() > user.expiresAt) return res.status(403).end('Account expired or user not found');
    
    // Předáme WST do handleru přes config
    req.params.config = JSON.stringify({ wstToken: entry.wst });
    
    next();
}, router);

module.exports = app;
