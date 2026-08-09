// Rosie — Production Server (v2: real accounts, server-side data)
// Serves the frontend, proxies Claude requests, and now owns all
// account/family data so it syncs across every device the user logs in on.

require('dotenv').config();
const express  = require('express');
const fetch    = require('node-fetch');
const path     = require('path');
const fs       = require('fs');
const https    = require('https');
const http     = require('http');
const bcrypt   = require('bcryptjs');
const crypto   = require('crypto');

const app = express();
const HTTP_PORT  = process.env.PORT || 3002;
const HTTPS_PORT = 8443;
const DOMAIN      = 'rosieai.duckdns.org';
const CERT_PATH   = `/etc/letsencrypt/live/${DOMAIN}`;
const DATA_DIR    = path.join(__dirname, 'data');
const USERS_FILE  = path.join(DATA_DIR, 'users.json');

app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
if (!ANTHROPIC_API_KEY) {
  console.error('\n⚠️  ANTHROPIC_API_KEY is not set in .env — Rosie cannot talk to Claude.\n');
}

// ══════════════════════════════════════════════
// DATA LAYER — simple JSON file store, one file for all users
// ══════════════════════════════════════════════
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, JSON.stringify({}));

function readUsers() {
  try {
    return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  } catch (err) {
    console.error('Failed to read users file:', err);
    return {};
  }
}

function writeUsers(users) {
  // Write to a temp file then rename — avoids corruption if the process
  // dies mid-write, same safety pattern as Ruthie's data files.
  const tmpPath = USERS_FILE + '.tmp';
  fs.writeFileSync(tmpPath, JSON.stringify(users, null, 2));
  fs.renameSync(tmpPath, USERS_FILE);
}

function defaultProfile() {
  return {
    family: { name: '', children: [], diet: { type: 'omnivore', allergies: [], dislikes: [], cuisines: [], timeLimit: 30 }, contacts: [] },
    events: [],
    meds: [],
    grocery: [],
    meals: [],
    conversation: [],
    elevenLabsKey: null
  };
}

// ══════════════════════════════════════════════
// AUTH — simple bearer token, tokens stored in memory
// (a restart clears sessions, same tradeoff as a JWT with no persistence;
//  fine for a small family app — everyone just logs in again)
// ══════════════════════════════════════════════
const activeSessions = new Map(); // token -> email

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  const email = token && activeSessions.get(token);
  if (!email) {
    return res.status(401).json({ error: { message: 'Not signed in. Please log in again.' } });
  }
  req.userEmail = email;
  next();
}

// ══════════════════════════════════════════════
// AUTH ENDPOINTS
// ══════════════════════════════════════════════

app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password, securityQuestion, securityAnswer } = req.body;
    if (!name || !email || !password || !securityQuestion || !securityAnswer) {
      return res.status(400).json({ error: { message: 'All fields are required.' } });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: { message: 'Password must be at least 6 characters.' } });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const users = readUsers();

    if (users[normalizedEmail]) {
      return res.status(400).json({ error: { message: 'An account with that email already exists.' } });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const answerHash    = await bcrypt.hash(securityAnswer.trim().toLowerCase(), 10);

    users[normalizedEmail] = {
      name,
      passwordHash,
      securityQuestion,
      securityAnswerHash: answerHash,
      profile: defaultProfile(),
      createdAt: new Date().toISOString()
    };
    writeUsers(users);

    const token = generateToken();
    activeSessions.set(token, normalizedEmail);

    res.json({ token, name, email: normalizedEmail });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: { message: 'Something went wrong creating your account.' } });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: { message: 'Email and password are required.' } });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const users = readUsers();
    const user  = users[normalizedEmail];

    if (!user) {
      return res.status(401).json({ error: { message: 'Incorrect email or password.' } });
    }

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) {
      return res.status(401).json({ error: { message: 'Incorrect email or password.' } });
    }

    const token = generateToken();
    activeSessions.set(token, normalizedEmail);

    res.json({ token, name: user.name, email: normalizedEmail });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: { message: 'Something went wrong signing you in.' } });
  }
});

app.post('/api/auth/logout', requireAuth, (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.slice(7);
  activeSessions.delete(token);
  res.json({ ok: true });
});

// ── Password reset flow ──
app.post('/api/auth/reset/lookup', (req, res) => {
  const { email } = req.body;
  const normalizedEmail = (email || '').trim().toLowerCase();
  const users = readUsers();
  const user = users[normalizedEmail];

  if (!user) {
    return res.status(404).json({ error: { message: 'No account found with that email.' } });
  }
  if (!user.securityQuestion) {
    return res.status(400).json({ error: { message: 'This account has no security question set.' } });
  }

  res.json({ securityQuestion: user.securityQuestion });
});

app.post('/api/auth/reset/verify', async (req, res) => {
  const { email, answer } = req.body;
  const normalizedEmail = (email || '').trim().toLowerCase();
  const users = readUsers();
  const user = users[normalizedEmail];

  if (!user) {
    return res.status(404).json({ error: { message: 'No account found.' } });
  }

  const match = await bcrypt.compare((answer || '').trim().toLowerCase(), user.securityAnswerHash);
  if (!match) {
    return res.status(401).json({ error: { message: "That answer doesn't match. Try again." } });
  }

  // Short-lived reset token, separate from login sessions
  const resetToken = generateToken();
  activeSessions.set('reset:' + resetToken, normalizedEmail);

  res.json({ resetToken });
});

app.post('/api/auth/reset/complete', async (req, res) => {
  const { resetToken, newPassword } = req.body;
  const email = activeSessions.get('reset:' + resetToken);

  if (!email) {
    return res.status(401).json({ error: { message: 'Reset session expired. Start over.' } });
  }
  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: { message: 'Password must be at least 6 characters.' } });
  }

  const users = readUsers();
  const user = users[email];
  if (!user) {
    return res.status(404).json({ error: { message: 'Account not found.' } });
  }

  user.passwordHash = await bcrypt.hash(newPassword, 10);
  writeUsers(users);
  activeSessions.delete('reset:' + resetToken);

  const token = generateToken();
  activeSessions.set(token, email);

  res.json({ token, name: user.name, email });
});

// ══════════════════════════════════════════════
// PROFILE DATA ENDPOINTS — get/save everything, synced per account
// ══════════════════════════════════════════════

app.get('/api/profile', requireAuth, (req, res) => {
  const users = readUsers();
  const user = users[req.userEmail];
  if (!user) return res.status(404).json({ error: { message: 'User not found.' } });
  res.json(user.profile || defaultProfile());
});

app.put('/api/profile', requireAuth, (req, res) => {
  const users = readUsers();
  const user = users[req.userEmail];
  if (!user) return res.status(404).json({ error: { message: 'User not found.' } });

  // Merge shallowly — the client sends the full profile object each time
  user.profile = { ...defaultProfile(), ...user.profile, ...req.body };
  writeUsers(users);
  res.json({ ok: true });
});

// ── Convenience endpoint for just the ElevenLabs key, since Settings saves it independently ──
app.put('/api/profile/elevenlabs-key', requireAuth, (req, res) => {
  const { key } = req.body;
  const users = readUsers();
  const user = users[req.userEmail];
  if (!user) return res.status(404).json({ error: { message: 'User not found.' } });

  user.profile = user.profile || defaultProfile();
  user.profile.elevenLabsKey = key || null;
  writeUsers(users);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════
// CLAUDE CHAT PROXY — unchanged, still keeps the Anthropic key server-side
// ══════════════════════════════════════════════
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

// ── Start server: HTTPS on 8443, HTTP fallback on 3002 ──
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
