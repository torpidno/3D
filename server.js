const express = require('express');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const basicAuth = require('express-basic-auth'); // kept for backward compatibility (not used after session auth switch)
const session = require('express-session');
const { randomUUID } = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 80;
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const NOAH_USER = process.env.NOAH_USER || 'noah';
const NOAH_PASSWORD = process.env.NOAH_PASSWORD || 'noah123';
const ALEX_USER = process.env.ALEX_USER || 'alex';
const ALEX_PASSWORD = process.env.ALEX_PASSWORD || 'alex123';
const MASTER_USER = process.env.MASTER_USER || 'Master';
const MASTER_PASSWORD = process.env.MASTER_PASSWORD || '120324';
const SESSION_SECRET = process.env.SESSION_SECRET || 'change_me_session_secret';
const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const DB_FILE = path.join(DATA_DIR, 'submissions.json');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

// Ensure folders and DB file exist
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, '[]', 'utf8');

// Initialize users file with default credentials if it doesn't exist
if (!fs.existsSync(USERS_FILE)) {
  const defaultUsers = [
    { username: MASTER_USER, password: MASTER_PASSWORD, role: 'master', displayName: 'Master' },
    { username: ADMIN_USER, password: ADMIN_PASSWORD, role: 'admin', displayName: 'Admin' },
    { username: NOAH_USER, password: NOAH_PASSWORD, role: 'noah', displayName: 'Noah' },
    { username: ALEX_USER, password: ALEX_PASSWORD, role: 'alex', displayName: 'Alex' }
  ];
  fs.writeFileSync(USERS_FILE, JSON.stringify(defaultUsers, null, 2), 'utf8');
}

// Helpers to read/write the mock DB
function readDb() {
  try {
    const raw = fs.readFileSync(DB_FILE, 'utf8');
    const data = JSON.parse(raw);
    return Array.isArray(data) ? data : [];
  } catch (err) {
    console.error('Failed to read DB file', err);
    return [];
  }
}

function writeDb(entries) {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(entries, null, 2), 'utf8');
  } catch (err) {
    console.error('Failed to write DB file', err);
  }
}

// Helpers to read/write users
function readUsers() {
  try {
    const raw = fs.readFileSync(USERS_FILE, 'utf8');
    const data = JSON.parse(raw);
    return Array.isArray(data) ? data : [];
  } catch (err) {
    console.error('Failed to read users file', err);
    return [];
  }
}

function writeUsers(users) {
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
  } catch (err) {
    console.error('Failed to write users file', err);
  }
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const base = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
    cb(null, `${base}${ext}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['.stl', '.3mf'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Endast .stl eller .3mf filer tillåtna'));
    }
  }
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    sameSite: 'lax',
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24 * 14
  }
}));
app.use(express.static(path.join(__dirname, 'public')));

function authenticate(username, password) {
  if (!username || !password) return null;
  const users = readUsers();
  const match = users.find(u => u.username === username);
  if (!match) return null;
  if (match.password !== password) return null;
  return match;
}

function formatShortDate(dateStr) {
  const d = new Date(dateStr);
  const pad = n => n.toString().padStart(2, '0');
  return `${pad(d.getHours())}:${pad(d.getMinutes())}, ${pad(d.getDate())}/${pad(d.getMonth() + 1)}`;
}

function renderDescriptionCell(text) {
  const raw = typeof text === 'string' ? text : '';
  const trimmed = raw.trim();
  const previewLimit = 160;
  const lineCount = trimmed.split(/\r?\n/).length;
  const isLong = trimmed.length > previewLimit || lineCount > 2;
  const fullHtml = escapeHtml(trimmed).replace(/\n/g, '<br>');
  if (!isLong) {
    return `<td class="wrap beskrivning-cell">${fullHtml || '-'}</td>`;
  }
  const preview = escapeHtml(trimmed.slice(0, previewLimit)).replace(/\n/g, '<br>');
  return `<td class="wrap beskrivning-cell long-desc" data-full="${fullHtml}">${preview}… <span class="show-more">[visa mer]</span></td>`;
}

function renderRows(entries, options = {}) {
  const {
    isDone = false,
    allowClaim = false,
    user = '',
    allowToggle = true,
    allowDelete = true,
    allowUnclaim = true
  } = options;

  return entries
    .map((s, idx) => {
      let claimed = '';
      if ((s.preferens === 'Noah' || s.preferens === 'Alex') && s.originalPreferens === 'Vem som') {
        claimed = ' <span class="claimed">(vem som)</span>';
      }

      const toggleHtml = allowToggle
        ? `<input type="checkbox" class="toggle-done" data-id="${s.id}" aria-label="Markera klar" ${isDone ? 'checked' : ''} />`
        : `<input type="checkbox" class="toggle-done" data-id="${s.id}" aria-label="Markera klar" ${isDone ? 'checked' : ''} disabled aria-disabled="true" />`;

      const actions = [
        `<a href="/admin/download/${s.id}">Ladda ner</a>`
      ];

      if (allowDelete) {
        actions.push(`<button type="button" class="btn-del" data-id="${s.id}">Ta bort</button>`);
      }

      const isTeamMember = user === 'noah' || user === 'alex';
      if (allowClaim && isTeamMember && s.preferens === 'Vem som') {
        actions.push(`<button type="button" class="btn-claim" data-id="${s.id}">Ta över</button>`);
      }

      if (allowUnclaim && isTeamMember && (s.preferens === 'Noah' || s.preferens === 'Alex') && s.originalPreferens === 'Vem som') {
        actions.push(`<button type="button" class="btn-unclaim" data-id="${s.id}">Ångra</button>`);
      }

      const descriptionCell = renderDescriptionCell(s.beskrivning);

      return `
      <tr data-id="${s.id}">
        <td class="idx">${idx + 1}</td>
        <td>${toggleHtml}</td>
        <td>${escapeHtml(s.namn)}</td>
        <td><a href="mailto:${escapeHtml(s.mejl)}">${escapeHtml(s.mejl)}</a></td>
        ${descriptionCell}
        <td>${escapeHtml(s.preferens)}${claimed}</td>
        <td>${escapeHtml(s.brattom)}</td>
        <td data-sort="${new Date(s.submittedAt).getTime()}">${formatShortDate(s.submittedAt)}</td>
        <td>${actions.join(' ')}</td>
      </tr>
      `;
    })
    .join('');
}

function ensureOriginalPreferens(entries) {
  return entries.map(item => {
    if (!item.originalPreferens) {
      item.originalPreferens = item.preferens;
    }
    return item;
  });
}

function normalizePreferens(preferens) {
  if (preferens === 'Noah' || preferens === 'Alex' || preferens === 'Vem som') {
    return preferens;
  }
  return 'Vem som';
}

function wantsJson(req) {
  const accept = req.headers.accept || '';
  return accept.includes('application/json') || accept.includes('text/json');
}

function renderLoginPage(message = '') {
  const errorHtml = message ? `<p class="login-error">${escapeHtml(message)}</p>` : '';
  return `<!doctype html>
<html lang="sv">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Logga in – 3D Admin</title>
  <style>
    :root{--bg:#020617;--card:#0f172a;--accent:#60a5fa;--muted:#94a3b8;--text:#e2e8f0;--error:#f87171}
    *{box-sizing:border-box}
    body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:radial-gradient(circle at 20% 20%,rgba(96,165,250,0.18),transparent),radial-gradient(circle at 80% 20%,rgba(14,165,233,0.12),transparent),#020617;color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
    .login-card{width:100%;max-width:360px;background:rgba(15,23,42,0.8);backdrop-filter:blur(12px);border:1px solid rgba(148,163,184,0.12);border-radius:16px;padding:28px;box-shadow:0 24px 60px rgba(15,23,42,0.35)}
    h1{margin:0 0 18px 0;font-size:24px;font-weight:600;text-align:center}
    label{display:block;font-size:14px;color:var(--muted);margin-bottom:6px}
    input{width:100%;padding:12px 14px;border-radius:10px;border:1px solid rgba(148,163,184,0.18);background:rgba(15,23,42,0.9);color:var(--text);margin-bottom:16px;outline:none;font-size:15px}
    input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(96,165,250,0.25)}
    button{width:100%;padding:12px 14px;border:none;border-radius:10px;background:var(--accent);color:#041120;font-weight:600;font-size:15px;cursor:pointer;transition:transform .15s ease,box-shadow .15s ease}
    button:hover{transform:translateY(-1px);box-shadow:0 10px 30px rgba(96,165,250,0.26)}
    .login-error{margin:0 0 16px 0;padding:10px 12px;border-radius:10px;background:rgba(248,113,113,0.12);border:1px solid rgba(248,113,113,0.32);color:var(--error);font-size:14px;text-align:center}
    .hint{margin:12px 0 0 0;font-size:12px;color:var(--muted);text-align:center}
    .back-link{display:block;margin-top:16px;text-align:center;font-size:14px;color:var(--accent);text-decoration:none;transition:color .15s ease}
    .back-link:hover{color:#93c5fd;text-decoration:underline}
  </style>
</head>
<body>
  <form class="login-card" method="post" action="/admin/login">
    <h1>Logga in</h1>
    ${errorHtml}
    <label for="username">Användarnamn</label>
    <input id="username" name="username" type="text" autocomplete="username" required />
    <label for="password">Lösenord</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required />
    <button type="submit">Fortsätt</button>
    <p class="hint">Kontakta administratören om du behöver hjälp.</p>
    <a href="/" class="back-link">← Tillbaka till startsidan</a>
  </form>
</body>
</html>`;
}

function sessionAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  if (wantsJson(req)) return res.status(401).json({ ok: false, error: 'Inte inloggad' });
  return res.redirect('/admin/login');
}

app.get('/admin/login', (req, res) => {
  if (req.session && req.session.user) return res.redirect('/admin');
  const message = typeof req.query.message === 'string' ? req.query.message : '';
  res.send(renderLoginPage(message));
});

app.post('/admin/login', (req, res) => {
  const username = (req.body?.username || '').trim();
  const password = req.body?.password || '';
  const account = authenticate(username, password);
  if (!account) {
    if (wantsJson(req)) {
      return res.status(401).json({ ok: false, error: 'Fel användarnamn eller lösenord' });
    }
    return res.status(401).send(renderLoginPage('Fel användarnamn eller lösenord.'));
  }
  req.session.user = account.role;
  req.session.username = account.username;
  req.session.displayName = account.displayName;
  req.session.save(err => {
    if (err) {
      console.error('Kunde inte spara session', err);
      if (wantsJson(req)) return res.status(500).json({ ok: false, error: 'Session kunde inte sparas' });
      return res.status(500).send(renderLoginPage('Session kunde inte sparas. Försök igen.'));
    }
    if (wantsJson(req)) return res.json({ ok: true });
    return res.redirect('/admin');
  });
});

app.get('/logout', (req, res) => {
  if (!req.session) return res.redirect('/admin/login');
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.redirect('/admin/login');
  });
});

// Public API: Get list of users for the home page preferens dropdown
app.get('/api/users', (req, res) => {
  const users = readUsers();
  // Return only username and displayName, exclude passwords, admin and master roles
  const publicUsers = users
    .filter(u => u.role !== 'admin' && u.role !== 'master') // Don't show admin or master in public dropdown
    .map(u => ({ 
      username: u.username, 
      displayName: u.displayName,
      role: u.role 
    }));
  res.json(publicUsers);
});

app.post('/api/submit', upload.single('fil'), (req, res) => {
  const { namn, mejl, beskrivning, preferens, brattom } = req.body || {};
  const trimmed = {
    namn: (namn || '').trim(),
    mejl: (mejl || '').trim(),
    beskrivning: (beskrivning || '').trim(),
    preferens: (preferens || '').trim(),
    brattom: (brattom || '').trim()
  };

  if (!trimmed.namn || !trimmed.mejl || !trimmed.beskrivning || !trimmed.preferens || !trimmed.brattom) {
    if (req.file) {
      try { fs.unlinkSync(req.file.path); } catch {}
    }
    return res.status(400).json({ ok: false, error: 'Alla fält är obligatoriska' });
  }

  if (!req.file) {
    return res.status(400).json({ ok: false, error: 'Fil (.stl eller .3mf) krävs' });
  }

  const entry = {
  id: randomUUID(),
    submittedAt: new Date().toISOString(),
    namn: trimmed.namn,
    mejl: trimmed.mejl,
    beskrivning: trimmed.beskrivning,
    preferens: trimmed.preferens,
    originalPreferens: trimmed.preferens,
    brattom: trimmed.brattom,
    done: false,
    file: {
      storedName: path.basename(req.file.filename),
      originalName: req.file.originalname,
      size: req.file.size,
      mimetype: req.file.mimetype
    }
  };

  const db = readDb();
  db.push(entry);
  writeDb(db);

  const acceptsHtml = (req.headers.accept || '').includes('text/html');
  if (acceptsHtml) {
    return res.redirect('/thanks.html');
  }
  return res.json({ ok: true, id: entry.id });
});

// API endpoint to get current user info
app.get('/api/admin/user', sessionAuth, (req, res) => {
  res.json({
    username: req.session.username,
    role: req.session.user,
    displayName: req.session.displayName
  });
});

// API endpoint to update user profile
app.put('/api/admin/profile', sessionAuth, (req, res) => {
  const { currentPassword, newUsername, newPassword } = req.body;
  const currentUsername = req.session.username;

  if (!currentPassword) {
    return res.status(400).json({ ok: false, message: 'Nuvarande lösenord krävs' });
  }

  // Read users and find current user
  const users = readUsers();
  const userIndex = users.findIndex(u => u.username === currentUsername);
  
  if (userIndex === -1) {
    return res.status(404).json({ ok: false, message: 'Användare hittades inte' });
  }

  const user = users[userIndex];

  // Verify current password
  if (user.password !== currentPassword) {
    return res.status(401).json({ ok: false, message: 'Felaktigt nuvarande lösenord' });
  }

  // Check if new username already exists (if changing username)
  if (newUsername && newUsername !== currentUsername) {
    const usernameExists = users.some(u => u.username === newUsername);
    if (usernameExists) {
      return res.status(400).json({ ok: false, message: 'Användarnamnet används redan' });
    }
    user.username = newUsername;
  }

  // Update password if provided
  if (newPassword) {
    user.password = newPassword;
  }

  // Save updated users
  users[userIndex] = user;
  writeUsers(users);

  // Update session with new credentials
  req.session.username = user.username;
  req.session.save((err) => {
    if (err) {
      console.error('Session save error:', err);
      return res.status(500).json({ ok: false, message: 'Kunde inte uppdatera session' });
    }
    res.json({ ok: true, message: 'Profil uppdaterad' });
  });
});

// Admin routes - serve the new dashboard pages
app.get('/admin', sessionAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html'));
});

app.get('/admin/my-prints', sessionAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-my-prints.html'));
});

app.get('/admin/other-prints', sessionAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-other-prints.html'));
});

app.get('/admin/completed', sessionAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-completed.html'));
});

// User management page (master only)
app.get('/admin/users', sessionAuth, (req, res) => {
  if (req.session.user !== 'master') {
    return res.redirect('/admin');
  }
  res.sendFile(path.join(__dirname, 'public', 'admin-users.html'));
});

// API: Get all users (master only)
app.get('/api/admin/users', sessionAuth, (req, res) => {
  if (req.session.user !== 'master') {
    return res.status(403).json({ ok: false, message: 'Only master can access user management' });
  }
  const users = readUsers();
  // Don't send passwords to frontend
  const safeUsers = users.map(u => ({ username: u.username, displayName: u.displayName, role: u.role }));
  res.json(safeUsers);
});

// API: Create new user (master only)
app.post('/api/admin/users', sessionAuth, (req, res) => {
  if (req.session.user !== 'master') {
    return res.status(403).json({ ok: false, message: 'Only master can create users' });
  }

  const { username, password, displayName } = req.body;

  if (!username || !password || !displayName) {
    return res.status(400).json({ ok: false, message: 'Användarnamn, lösenord och visningsnamn krävs' });
  }

  const users = readUsers();
  
  // Check if username already exists
  if (users.some(u => u.username === username)) {
    return res.status(400).json({ ok: false, message: 'Användarnamnet finns redan' });
  }

  // Auto-generate role from username (lowercase)
  const role = username.trim().toLowerCase();

  // Don't allow creating another master
  if (role === 'master') {
    return res.status(400).json({ ok: false, message: 'Kan inte skapa fler Master-konton' });
  }

  const newUser = {
    username: username.trim(),
    password: password,
    displayName: displayName.trim(),
    role: role
  };

  users.push(newUser);
  writeUsers(users);

  res.json({ ok: true, message: 'Användare skapad' });
});

// API: Update user (master only)
app.put('/api/admin/users/:username', sessionAuth, (req, res) => {
  if (req.session.user !== 'master') {
    return res.status(403).json({ ok: false, message: 'Only master can update users' });
  }

  const oldUsername = req.params.username;
  const { username, password, displayName } = req.body;

  if (!username || !displayName) {
    return res.status(400).json({ ok: false, message: 'Användarnamn och visningsnamn krävs' });
  }

  const users = readUsers();
  const userIndex = users.findIndex(u => u.username === oldUsername);

  if (userIndex === -1) {
    return res.status(404).json({ ok: false, message: 'Användare hittades inte' });
  }

  // Don't allow editing master
  if (users[userIndex].role === 'master') {
    return res.status(403).json({ ok: false, message: 'Master-kontot kan inte redigeras' });
  }

  // Auto-generate new role from username (lowercase)
  const newRole = username.trim().toLowerCase();

  // Don't allow changing to master role
  if (newRole === 'master') {
    return res.status(400).json({ ok: false, message: 'Kan inte ändra användarnamn till "master"' });
  }

  // Check if new username already exists (if changing username)
  if (username !== oldUsername && users.some(u => u.username === username)) {
    return res.status(400).json({ ok: false, message: 'Användarnamnet finns redan' });
  }

  // Update user
  users[userIndex].username = username.trim();
  users[userIndex].displayName = displayName.trim();
  users[userIndex].role = newRole;
  
  if (password) {
    users[userIndex].password = password;
  }

  writeUsers(users);

  res.json({ ok: true, message: 'Användare uppdaterad' });
});

// API: Delete user (master only)
app.delete('/api/admin/users/:username', sessionAuth, (req, res) => {
  if (req.session.user !== 'master') {
    return res.status(403).json({ ok: false, message: 'Only master can delete users' });
  }

  const username = req.params.username;
  const users = readUsers();
  const userIndex = users.findIndex(u => u.username === username);

  if (userIndex === -1) {
    return res.status(404).json({ ok: false, message: 'Användare hittades inte' });
  }

  // Don't allow deleting master
  if (users[userIndex].role === 'master') {
    return res.status(403).json({ ok: false, message: 'Master-kontot kan inte tas bort' });
  }

  users.splice(userIndex, 1);
  writeUsers(users);

  res.json({ ok: true, message: 'Användare borttagen' });
});

app.patch('/api/admin/submissions/:id/claim', sessionAuth, (req, res) => {
  const id = req.params.id;
  const userRole = req.session.user;
  const username = req.session.username;
  
  // Master can always claim, others can claim if not admin role
  if (userRole === 'master' || userRole !== 'admin') {
    // Allow claim
  } else {
    return res.status(403).json({ ok: false, error: 'Du kan inte ta över prints' });
  }
  
  const db = readDb();
  const idx = db.findIndex(s => s.id === id);
  if (idx === -1) return res.status(404).json({ ok: false, error: 'not found' });
  if (db[idx].preferens !== 'Vem som') {
    return res.status(400).json({ ok: false, error: 'Kan bara ta över "Vem som" prints' });
  }
  if (!db[idx].originalPreferens) db[idx].originalPreferens = 'Vem som';
  
  // Set preferens to username (capitalized)
  db[idx].preferens = username.charAt(0).toUpperCase() + username.slice(1);
  
  writeDb(db);
  res.json({ ok: true });
});

app.patch('/api/admin/submissions/:id/unclaim', sessionAuth, (req, res) => {
  const id = req.params.id;
  const userRole = req.session.user;
  const username = req.session.username;
  
  // Master can always unclaim, others can unclaim if not admin role
  if (userRole === 'master' || userRole !== 'admin') {
    // Allow unclaim
  } else {
    return res.status(403).json({ ok: false, error: 'Du kan inte ångra' });
  }
  
  const db = readDb();
  const idx = db.findIndex(s => s.id === id);
  if (idx === -1) return res.status(404).json({ ok: false, error: 'not found' });
  
  // Check if this user's print and was originally "Vem som"
  const capitalizedUsername = username.charAt(0).toUpperCase() + username.slice(1);
  if (db[idx].preferens !== capitalizedUsername || db[idx].originalPreferens !== 'Vem som') {
    return res.status(400).json({ ok: false, error: 'Kan bara ångra dina egna "Vem som"-claimade prints' });
  }
  
  db[idx].preferens = 'Vem som';
  writeDb(db);
  res.json({ ok: true });
});

app.get('/admin/download/:id', sessionAuth, (req, res) => {
  const id = req.params.id;
  const db = readDb();
  const found = db.find(s => s.id === id);
  if (!found) return res.status(404).send('Ej hittad');
  const filePath = path.join(UPLOAD_DIR, found.file.storedName);
  if (!fs.existsSync(filePath)) return res.status(404).send('Fil saknas på servern');
  res.download(filePath, found.file.originalName);
});

// Raw file route for in-browser preview
app.get('/admin/file/:id/raw', sessionAuth, (req, res) => {
  const id = req.params.id;
  const db = readDb();
  const found = db.find(s => s.id === id);
  if (!found) return res.status(404).send('Ej hittad');
  const filePath = path.join(UPLOAD_DIR, found.file.storedName);
  if (!fs.existsSync(filePath)) return res.status(404).send('Fil saknas på servern');
  const ext = path.extname(found.file.originalName).toLowerCase();
  const type = ext === '.stl' ? 'model/stl' : (ext === '.3mf' ? 'model/3mf' : 'application/octet-stream');
  res.setHeader('Content-Type', type);
  res.setHeader('Cache-Control', 'no-cache');
  res.sendFile(filePath);
});

app.get('/api/admin/submissions', sessionAuth, (req, res) => {
  const db = readDb();
  res.json(db);
});

app.patch('/api/admin/submissions/:id/done', sessionAuth, (req, res) => {
  const id = req.params.id;
  const { done } = req.body || {};
  if (typeof done !== 'boolean') {
    return res.status(400).json({ ok: false, error: 'done must be boolean' });
  }
  const db = readDb();
  const idx = db.findIndex(s => s.id === id);
  if (idx === -1) return res.status(404).json({ ok: false, error: 'not found' });
  db[idx].done = done;
  writeDb(db);
  res.json({ ok: true });
});

app.delete('/api/admin/submissions/:id', sessionAuth, (req, res) => {
  const id = req.params.id;
  const db = readDb();
  const idx = db.findIndex(s => s.id === id);
  if (idx === -1) return res.status(404).json({ ok: false, error: 'not found' });
  const [removed] = db.splice(idx, 1);
  writeDb(db);
  try {
    const filePath = path.join(UPLOAD_DIR, removed.file?.storedName || '');
    if (filePath && fs.existsSync(filePath)) fs.unlinkSync(filePath);
  } catch {}
  res.json({ ok: true });
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use((err, req, res, next) => {
  console.error(err);
  if (err instanceof multer.MulterError || err.message) {
    return res.status(400).json({ ok: false, error: err.message || 'Uppladdningsfel' });
  }
  res.status(500).json({ ok: false, error: 'Internt serverfel' });
});

app.listen(PORT, () => {
  console.log(`Server kör på http://localhost:${PORT}`);
});

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
