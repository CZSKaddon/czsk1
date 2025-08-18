#!/usr/bin/env node

const express = require('express');
const { getRouter } = require('stremio-addon-sdk');
const addonInterface = require('./addon');
const mongoose = require('mongoose');

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

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  expiresAt: { type: Date, required: true },
});
const User = mongoose.models.User || mongoose.model('User', UserSchema);

const TokenSchema = new mongoose.Schema({
  username: { type: String, required: true },
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

// Simplified Authentication Middleware
const authMiddleware = async (req, res, next) => {
    const { token, deviceMac } = req.params;

    if (!token || !deviceMac || !MAC_REGEX.test(deviceMac)) {
        return res.status(400).send('Bad request: Invalid token or MAC format');
    }

    try {
        const entry = await Token.findOne({ token, deviceId: deviceMac });
        if (!entry) {
            return res.status(401).send('Invalid token or device');
        }

        const user = await User.findOne({ username: entry.username });
        if (!user || Date.now() > user.expiresAt) {
            return res.status(403).send('Account expired or not found');
        }
        
        // If everything is okay, proceed to the Stremio router
        next();

    } catch (err) {
        console.error("Authentication error:", err);
        return res.status(500).send('Server error during authentication');
    }
};

// Mount the authentication middleware and then the Stremio addon router
app.use(MOUNT_PATH, authMiddleware, getRouter(addonInterface));

// Admin panel and other routes are removed for this test to isolate the problem.
// We will add them back once the core addon functionality is confirmed.

module.exports = app;
