// Rosie — Production Server (v3: shared families, invite-code co-parent linking)
// Serves the frontend, proxies Claude requests, and owns all account/family
// data. Multiple parent accounts can now share one family's data via an
// invite code, so both parents stay in sync on the same schedule, meds,
// grocery list, and conversation history.

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
const DOMAIN       = 'rosieai.duckdns.org';
const CERT_PATH    = `/etc/letsencrypt/live/${DOMAIN}`;
const DATA_DIR     = path.join(__dirname, 'data');
const USERS_FILE   = path.join(DATA_DIR, 'users.json');
const FAMILIES_FILE = path.join(DATA_DIR, 'families.json');

app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
if (!ANTHROPIC_API_KEY) {
  console.error('\n⚠️  ANTHROPIC_API_KEY is not set in .env — Rosie cannot talk to Claude.\n');
}

// ══════════════════════════════════════════════
// DATA LAYER
// users.json    -> { email: { name, passwordHash, familyId, elevenLabsKey, ... } }
// families.json -> { familyId: { family, events, meds, grocery, meals, conversation, hasSeenIntro, inviteCode, inviteCodeExpires } }
//
// Login credentials and the ElevenLabs voice key stay per-user (personal).
// Everything else (kids, events, meds, etc.) lives on the family record,
// shared by every user whose account points at that familyId.
// ══════════════════════════════════════════════
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, JSON.stringify({}));
if (!fs.existsSync(FAMILIES_FILE)) fs.writeFileSync(FAMILIES_FILE, JSON.stringify({}));

function readJSON(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (err) {
    console.error(`Failed to read ${filePath}:`, err);
    return {};
  }
}

function writeJSON(filePath, data) {
  const tmpPath = filePath + '.tmp';
  fs.writeFileSync(tmpPath, JSON.stringify(data, null, 2));
  fs.renameSync(tmpPath, filePath);
}

const readUsers      = () => readJSON(USERS_FILE);
const writeUsers     = (u) => writeJSON(USERS_FILE, u);
const readFamilies   = () => readJSON(FAMILIES_FILE);
const writeFamilies  = (f) => writeJSON(FAMILIES_FILE, f);

function defaultFamilyData() {
  return {
    family: { name: '', children: [], diet: { type: 'omnivore', allergies: [], dislikes: [], cuisines: [], timeLimit: 30 }, contacts: [] },
    events: [],
    meds: [],
    grocery: [],
    meals: [],
    conversation: [],
    hasSeenIntro: false,
    inviteCode: null,
    inviteCodeExpires: null,
    members: [], // array of emails belonging to this family
    emergencyInfo: {
      pediatrician: { name: '', phone: '', notes: '' },
      dentist: { name: '', phone: '' },
      insurance: { provider: '', policyNumber: '', phone: '' },
      iceContacts: [], // [{ name, relationship, phone }]
      homeAddress: '',
      generalNotes: '' // e.g. "gate code is 4471", "spare key under mat"
    },
    familyNotes: [], // [{ id, text, author, createdAt }] — real-time notes like "running 10 min late"
    sitterCode: null,
    sitterCodeExpires: null,
    chores: [], // [{ id, title, childName, amount, recurring, doneToday, lastDoneAt, createdAt }]
    allowanceBalances: {} // { childName: dollarAmount } — running total, paid out manually
  };
}

function generateFamilyId() {
  return crypto.randomBytes(12).toString('hex');
}

function generateInviteCode() {
  // Short, readable, no ambiguous characters (no 0/O, 1/I/l)
  const chars = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 6; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}

// ══════════════════════════════════════════════
// AUTH — simple bearer token, tokens stored in memory
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

    // Every new signup gets their own new family by default.
    // They can later join someone else's family via invite code,
    // which re-points familyId and (for now) discards this empty one.
    const families = readFamilies();
    const familyId = generateFamilyId();
    families[familyId] = defaultFamilyData();
    families[familyId].members = [normalizedEmail];
    writeFamilies(families);

    users[normalizedEmail] = {
      name,
      passwordHash,
      securityQuestion,
      securityAnswerHash: answerHash,
      familyId,
      elevenLabsKey: null,
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
// PROFILE DATA ENDPOINTS — reads/writes the shared family record
// ══════════════════════════════════════════════

app.get('/api/profile', requireAuth, (req, res) => {
  const users = readUsers();
  const user  = users[req.userEmail];
  if (!user) return res.status(404).json({ error: { message: 'User not found.' } });

  const families = readFamilies();
  const familyData = families[user.familyId] || defaultFamilyData();

  // elevenLabsKey is personal, not shared — comes from the user record
  res.json({ ...familyData, elevenLabsKey: user.elevenLabsKey || null });
});

app.put('/api/profile', requireAuth, (req, res) => {
  const users = readUsers();
  const user  = users[req.userEmail];
  if (!user) return res.status(404).json({ error: { message: 'User not found.' } });

  const families = readFamilies();
  const existing  = families[user.familyId] || defaultFamilyData();

  // elevenLabsKey never gets written to the shared family record —
  // strip it out before merging, it's saved separately per-user.
  const { elevenLabsKey, ...familyFields } = req.body;

  families[user.familyId] = { ...defaultFamilyData(), ...existing, ...familyFields, members: existing.members };
  writeFamilies(families);

  res.json({ ok: true });
});

app.put('/api/profile/elevenlabs-key', requireAuth, (req, res) => {
  const { key } = req.body;
  const users = readUsers();
  const user = users[req.userEmail];
  if (!user) return res.status(404).json({ error: { message: 'User not found.' } });

  user.elevenLabsKey = key || null;
  writeUsers(users);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════
// CO-PARENT LINKING — invite code system
// ══════════════════════════════════════════════

// Generate (or refresh) an invite code for the current user's family
app.post('/api/family/invite', requireAuth, (req, res) => {
  const users = readUsers();
  const user  = users[req.userEmail];
  if (!user) return res.status(404).json({ error: { message: 'User not found.' } });

  const families = readFamilies();
  const familyData = families[user.familyId] || defaultFamilyData();

  const code = generateInviteCode();
  const expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(); // 24 hours

  familyData.inviteCode = code;
  familyData.inviteCodeExpires = expires;
  families[user.familyId] = familyData;
  writeFamilies(families);

  res.json({ code, expiresAt: expires });
});

// Join another family using their invite code.
// The joining user's OWN family record is abandoned (their data, if any,
// stays in storage but is no longer linked to any active user) and their
// account is re-pointed at the inviting family.
app.post('/api/family/join', requireAuth, (req, res) => {
  const { code } = req.body;
  if (!code || code.trim().length === 0) {
    return res.status(400).json({ error: { message: 'Please enter an invite code.' } });
  }

  const normalizedCode = code.trim().toUpperCase();
  const users = readUsers();
  const joiningUser = users[req.userEmail];
  if (!joiningUser) return res.status(404).json({ error: { message: 'User not found.' } });

  const families = readFamilies();

  // Find the family with this active, unexpired invite code
  const targetFamilyId = Object.keys(families).find(fid => {
    const f = families[fid];
    return f.inviteCode === normalizedCode &&
           f.inviteCodeExpires &&
           new Date(f.inviteCodeExpires) > new Date();
  });

  if (!targetFamilyId) {
    return res.status(404).json({ error: { message: 'That code is invalid or has expired. Ask for a new one.' } });
  }

  if (targetFamilyId === joiningUser.familyId) {
    return res.status(400).json({ error: { message: "You're already part of this family." } });
  }

  // Re-point the joining user at the target family
  const oldFamilyId = joiningUser.familyId;
  joiningUser.familyId = targetFamilyId;
  writeUsers(users);

  // Add them to the members list, remove the old empty family record
  families[targetFamilyId].members = families[targetFamilyId].members || [];
  if (!families[targetFamilyId].members.includes(req.userEmail)) {
    families[targetFamilyId].members.push(req.userEmail);
  }
  // Clear the invite code once used so it can't be reused indefinitely
  families[targetFamilyId].inviteCode = null;
  families[targetFamilyId].inviteCodeExpires = null;

  // Clean up the old family record only if no one else is on it
  if (families[oldFamilyId] && (!families[oldFamilyId].members || families[oldFamilyId].members.length <= 1)) {
    delete families[oldFamilyId];
  } else if (families[oldFamilyId]) {
    families[oldFamilyId].members = families[oldFamilyId].members.filter(m => m !== req.userEmail);
  }

  writeFamilies(families);

  res.json({ ok: true, memberCount: families[targetFamilyId].members.length });
});

// Get info about who's currently sharing this family (for display in Settings)
app.get('/api/family/members', requireAuth, (req, res) => {
  const users = readUsers();
  const user  = users[req.userEmail];
  if (!user) return res.status(404).json({ error: { message: 'User not found.' } });

  const families = readFamilies();
  const familyData = families[user.familyId] || defaultFamilyData();

  const memberNames = (familyData.members || []).map(email => ({
    email,
    name: users[email]?.name || email
  }));

  res.json({ members: memberNames });
});

// ══════════════════════════════════════════════
// FAMILY NOTES — real-time messages like "running 10 min late"
// ══════════════════════════════════════════════

app.post('/api/family/notes', requireAuth, (req, res) => {
  const { text } = req.body;
  if (!text || !text.trim()) {
    return res.status(400).json({ error: { message: 'Note text is required.' } });
  }

  const users = readUsers();
  const user  = users[req.userEmail];
  if (!user) return res.status(404).json({ error: { message: 'User not found.' } });

  const families = readFamilies();
  const familyData = families[user.familyId] || defaultFamilyData();

  familyData.familyNotes = familyData.familyNotes || [];
  familyData.familyNotes.unshift({
    id: crypto.randomBytes(8).toString('hex'),
    text: text.trim(),
    author: user.name || req.userEmail,
    createdAt: new Date().toISOString()
  });

  // Keep only the most recent 50 notes so this doesn't grow forever
  familyData.familyNotes = familyData.familyNotes.slice(0, 50);

  families[user.familyId] = familyData;
  writeFamilies(families);

  res.json({ ok: true, note: familyData.familyNotes[0] });
});

app.delete('/api/family/notes/:noteId', requireAuth, (req, res) => {
  const users = readUsers();
  const user  = users[req.userEmail];
  if (!user) return res.status(404).json({ error: { message: 'User not found.' } });

  const families = readFamilies();
  const familyData = families[user.familyId] || defaultFamilyData();

  familyData.familyNotes = (familyData.familyNotes || []).filter(n => n.id !== req.params.noteId);
  families[user.familyId] = familyData;
  writeFamilies(families);

  res.json({ ok: true });
});

// ══════════════════════════════════════════════
// CHORES & ALLOWANCE
// ══════════════════════════════════════════════

app.post('/api/chores', requireAuth, (req, res) => {
  const { title, childName, amount, recurring } = req.body;
  if (!title || !childName) {
    return res.status(400).json({ error: { message: 'Chore title and child name are required.' } });
  }

  const users = readUsers();
  const user  = users[req.userEmail];
  if (!user) return res.status(404).json({ error: { message: 'User not found.' } });

  const families = readFamilies();
  const familyData = families[user.familyId] || defaultFamilyData();

  const chore = {
    id: crypto.randomBytes(8).toString('hex'),
    title: title.trim(),
    childName: childName.trim(),
    amount: typeof amount === 'number' ? amount : parseFloat(amount) || 0,
    recurring: !!recurring,
    doneToday: false,
    lastDoneAt: null,
    createdAt: new Date().toISOString()
  };

  familyData.chores = familyData.chores || [];
  familyData.chores.push(chore);
  families[user.familyId] = familyData;
  writeFamilies(families);

  res.json({ ok: true, chore });
});

app.put('/api/chores/:choreId/complete', requireAuth, (req, res) => {
  const users = readUsers();
  const user  = users[req.userEmail];
  if (!user) return res.status(404).json({ error: { message: 'User not found.' } });

  const families = readFamilies();
  const familyData = families[user.familyId] || defaultFamilyData();
  familyData.chores = familyData.chores || [];
  familyData.allowanceBalances = familyData.allowanceBalances || {};

  const chore = familyData.chores.find(c => c.id === req.params.choreId);
  if (!chore) return res.status(404).json({ error: { message: 'Chore not found.' } });

  if (chore.doneToday) {
    return res.json({ ok: true, alreadyDone: true, chore, balances: familyData.allowanceBalances });
  }

  chore.doneToday = true;
  chore.lastDoneAt = new Date().toISOString();

  const child = chore.childName;
  familyData.allowanceBalances[child] = (familyData.allowanceBalances[child] || 0) + chore.amount;

  families[user.familyId] = familyData;
  writeFamilies(families);

  res.json({ ok: true, chore, balances: familyData.allowanceBalances });
});

// Reset all recurring chores back to not-done — call this once a day
// (client triggers it on the first load of a new day; simple and reliable
// without needing a real cron job on the server)
app.post('/api/chores/reset-recurring', requireAuth, (req, res) => {
  const users = readUsers();
  const user  = users[req.userEmail];
  if (!user) return res.status(404).json({ error: { message: 'User not found.' } });

  const families = readFamilies();
  const familyData = families[user.familyId] || defaultFamilyData();
  familyData.chores = familyData.chores || [];

  const todayStr = new Date().toISOString().split('T')[0];
  let resetCount = 0;

  familyData.chores.forEach(c => {
    if (c.recurring && c.doneToday) {
      const lastDoneDate = c.lastDoneAt ? c.lastDoneAt.split('T')[0] : null;
      if (lastDoneDate !== todayStr) {
        c.doneToday = false;
        resetCount++;
      }
    }
  });

  if (resetCount > 0) {
    families[user.familyId] = familyData;
    writeFamilies(families);
  }

  res.json({ ok: true, resetCount, chores: familyData.chores });
});

app.delete('/api/chores/:choreId', requireAuth, (req, res) => {
  const users = readUsers();
  const user  = users[req.userEmail];
  if (!user) return res.status(404).json({ error: { message: 'User not found.' } });

  const families = readFamilies();
  const familyData = families[user.familyId] || defaultFamilyData();

  familyData.chores = (familyData.chores || []).filter(c => c.id !== req.params.choreId);
  families[user.familyId] = familyData;
  writeFamilies(families);

  res.json({ ok: true });
});

// Pay out and reset a child's balance to $0
app.post('/api/allowance/payout', requireAuth, (req, res) => {
  const { childName } = req.body;
  if (!childName) {
    return res.status(400).json({ error: { message: 'Child name is required.' } });
  }

  const users = readUsers();
  const user  = users[req.userEmail];
  if (!user) return res.status(404).json({ error: { message: 'User not found.' } });

  const families = readFamilies();
  const familyData = families[user.familyId] || defaultFamilyData();
  familyData.allowanceBalances = familyData.allowanceBalances || {};

  const paidAmount = familyData.allowanceBalances[childName] || 0;
  familyData.allowanceBalances[childName] = 0;

  families[user.familyId] = familyData;
  writeFamilies(families);

  res.json({ ok: true, paidAmount, balances: familyData.allowanceBalances });
});

// ══════════════════════════════════════════════
// BABYSITTER VIEW — no login required, read-only, short-lived code
// ══════════════════════════════════════════════

// Generate (or refresh) a sitter access code — separate from the co-parent invite code
app.post('/api/family/sitter-code', requireAuth, (req, res) => {
  const users = readUsers();
  const user  = users[req.userEmail];
  if (!user) return res.status(404).json({ error: { message: 'User not found.' } });

  const families = readFamilies();
  const familyData = families[user.familyId] || defaultFamilyData();

  const code = generateInviteCode();
  const expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(); // 24 hours

  familyData.sitterCode = code;
  familyData.sitterCodeExpires = expires;
  families[user.familyId] = familyData;
  writeFamilies(families);

  res.json({ code, expiresAt: expires });
});

// Public read-only view — NO auth required, just a valid unexpired sitter code.
// Returns only what a sitter needs: today's events, emergency info, family notes.
// Deliberately excludes: grocery list, meds history beyond today, diet details,
// conversation history, invite codes, or anything else not sitter-relevant.
app.get('/api/sitter/:code', (req, res) => {
  const code = (req.params.code || '').trim().toUpperCase();
  const families = readFamilies();

  const familyId = Object.keys(families).find(fid => {
    const f = families[fid];
    return f.sitterCode === code &&
           f.sitterCodeExpires &&
           new Date(f.sitterCodeExpires) > new Date();
  });

  if (!familyId) {
    return res.status(404).json({ error: { message: 'This sitter link is invalid or has expired.' } });
  }

  const familyData = families[familyId];
  const todayStr = new Date().toISOString().split('T')[0];

  res.json({
    familyName: familyData.family?.name || '',
    children: (familyData.family?.children || []).map(c => ({ name: c.name, age: c.age })),
    todayEvents: (familyData.events || []).filter(e => e.date === todayStr),
    activeMeds: (familyData.meds || []).filter(m => m.active).map(m => ({
      name: m.name, childName: m.childName, dose: m.dose, schedule: m.schedule
    })),
    allergies: familyData.family?.diet?.allergies || [],
    emergencyInfo: familyData.emergencyInfo || defaultFamilyData().emergencyInfo,
    familyNotes: (familyData.familyNotes || []).slice(0, 10)
  });
});

// ══════════════════════════════════════════════
// CLAUDE CHAT PROXY
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
