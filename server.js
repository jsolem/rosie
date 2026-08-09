// Rosie — Production Server
// Serves the Rosie frontend and proxies chat requests to Claude.
// Runs alongside Ruthie on the same droplet, fully isolated:
// separate folder, separate port, separate PM2 process.
// Serves HTTPS directly via Let's Encrypt certs, same pattern as Ruthie.

require('dotenv').config();
const express = require('express');
const fetch   = require('node-fetch');
const path    = require('path');
const fs      = require('fs');
const https   = require('https');
const http    = require('http');

const app  = express();
const HTTP_PORT = process.env.PORT || 3002;
const HTTPS_PORT = 443;
const DOMAIN = 'rosieai.duckdns.org';
const CERT_PATH = `/etc/letsencrypt/live/${DOMAIN}`;

app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;

if (!ANTHROPIC_API_KEY) {
  console.error('\n⚠️  ANTHROPIC_API_KEY is not set in .env — Rosie cannot talk to Claude.\n');
}

// ── Chat proxy — keeps the API key on the server, never in the browser ──
app.post('/api/rosie/chat', async (req, res) => {
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify(req.body)
    });

    const data = await response.json();

    if (!response.ok) {
      console.error('Anthropic API error:', data);
      return res.status(response.status).json(data);
    }

    res.json(data);
  } catch (err) {
    console.error('Proxy error:', err);
    res.status(500).json({ error: { message: err.message } });
  }
});

// ── Health check ──
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'rosie' });
});

// ── Fallback: serve index.html for any other route ──
app.get('/*splat', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Try HTTPS first (production), fall back to plain HTTP if certs aren't found ──
try {
  const certExists = fs.existsSync(`${CERT_PATH}/fullchain.pem`) && fs.existsSync(`${CERT_PATH}/privkey.pem`);

  if (certExists) {
    const httpsOptions = {
      cert: fs.readFileSync(`${CERT_PATH}/fullchain.pem`),
      key:  fs.readFileSync(`${CERT_PATH}/privkey.pem`)
    };

    https.createServer(httpsOptions, app).listen(HTTPS_PORT, () => {
      console.log(`✓ Rosie HTTPS server running on port ${HTTPS_PORT} (${DOMAIN})`);
    });

    // Also listen on plain HTTP as a fallback/redirect port
    http.createServer(app).listen(HTTP_PORT, () => {
      console.log(`✓ Rosie HTTP fallback running on port ${HTTP_PORT}`);
    });
  } else {
    console.warn(`⚠️  No SSL cert found at ${CERT_PATH} — falling back to HTTP only on port ${HTTP_PORT}`);
    http.createServer(app).listen(HTTP_PORT, () => {
      console.log(`✓ Rosie HTTP server running on port ${HTTP_PORT}`);
    });
  }
} catch (err) {
  console.error('Failed to start with HTTPS, falling back to HTTP:', err.message);
  http.createServer(app).listen(HTTP_PORT, () => {
    console.log(`✓ Rosie HTTP server running on port ${HTTP_PORT}`);
  });
}
