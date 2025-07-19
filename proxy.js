// proxy.js

const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');

// Your login token and device ID from /login
const TOKEN  = '282ab223-a980-490d-8107-36faccd0aea1';
const DEVICE = 'MY_DEVICE_ID';

const app = express();

// Proxy **all** requests to your addon on port 8001
app.use(
  createProxyMiddleware({
    target: 'http://127.0.0.1:8001',
    changeOrigin: true,
    // preserve the full path (no rewrite needed)
    pathRewrite: {},
    onProxyReq: (proxyReq, req, res) => {
      // Inject both headers on every outgoing request
      proxyReq.setHeader('Authorization', `Bearer ${TOKEN}`);
      proxyReq.setHeader('X-Stremio-Device', DEVICE);
    },
  })
);

app.listen(8000, () => {
  console.log('🔀 Proxy running at http://127.0.0.1:8000');
});
