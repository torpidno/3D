const express = require('express');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const basicAuth = require('express-basic-auth'); // kept for backward compatibility (not used after session auth switch)
const session = require('express-session');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 80;
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const NOAH_USER = process.env.NOAH_USER || 'noah';
const NOAH_PASSWORD = process.env.NOAH_PASSWORD || 'noah123';
const ALEX_USER = process.env.ALEX_USER || 'alex';
const ALEX_PASSWORD = process.env.ALEX_PASSWORD || 'alex123';
const SESSION_SECRET = process.env.SESSION_SECRET || 'change_me_session_secret';
const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const DB_FILE = path.join(DATA_DIR, 'submissions.json');

// Ensure folders and DB file exist
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, '[]', 'utf8');

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

const USER_CREDENTIALS = [
  { username: ADMIN_USER, password: ADMIN_PASSWORD, role: 'admin', displayName: 'Admin' },
  { username: NOAH_USER, password: NOAH_PASSWORD, role: 'noah', displayName: 'Noah' },
  { username: ALEX_USER, password: ALEX_PASSWORD, role: 'alex', displayName: 'Alex' }
];

function authenticate(username, password) {
  if (!username || !password) return null;
  const match = USER_CREDENTIALS.find(u => u.username === username);
  if (!match) return null;
  if (match.password !== password) return null;
  return match;
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
    id: uuidv4(),
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

// Admin HTML page
app.get('/admin', sessionAuth, (req, res) => {
  const db = readDb();
  const list = db.map(s => ({ ...s, done: !!s.done }));
  const actives = list.filter(s => !s.done).slice().reverse();
  const finished = list.filter(s => s.done).slice().reverse();


  // Format date as 'HH:mm, DD/MM'
  function formatShortDate(dateStr) {
    const d = new Date(dateStr);
    const pad = n => n.toString().padStart(2, '0');
    return pad(d.getHours()) + ':' + pad(d.getMinutes()) + ', ' + pad(d.getDate()) + '/' + pad(d.getMonth() + 1);
  }

  const renderDescriptionCell = text => {
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
  };

  const renderRows = (arr, isDone, allowClaim = false, user = '') => arr
    .map((s, idx) => {
      // Show (vem som) if this was claimed (i.e., preferens is Noah/Alex but originally Vem som)
      let claimed = '';
      if ((s.preferens === 'Noah' || s.preferens === 'Alex') && s.originalPreferens === 'Vem som') {
        claimed = ' <span class="claimed">(vem som)</span>';
      }
      const descriptionCell = renderDescriptionCell(s.beskrivning);
      return `
      <tr data-id="${s.id}">
        <td class="idx">${idx + 1}</td>
        <td><input type="checkbox" class="toggle-done" data-id="${s.id}" aria-label="Markera klar" ${isDone ? 'checked' : ''} /></td>
        <td>${escapeHtml(s.namn)}</td>
        <td><a href="mailto:${escapeHtml(s.mejl)}">${escapeHtml(s.mejl)}</a></td>
        ${descriptionCell}
        <td>${escapeHtml(s.preferens)}${claimed}</td>
        <td>${escapeHtml(s.brattom)}</td>
        <td data-sort="${new Date(s.submittedAt).getTime()}">${formatShortDate(s.submittedAt)}</td>
        <td>
          <a href="/admin/download/${s.id}">Ladda ner</a>
          <button type="button" class="btn-del" data-id="${s.id}">Ta bort</button>
          ${allowClaim && (user === 'noah' || user === 'alex') && s.preferens === 'Vem som' ? `<button type="button" class="btn-claim" data-id="${s.id}">Ta över</button>` : ''}
          ${(user === 'noah' || user === 'alex') && (s.preferens === 'Noah' || s.preferens === 'Alex') && s.originalPreferens === 'Vem som' ? `<button type="button" class="btn-unclaim" data-id="${s.id}">Ångra</button>` : ''}
        </td>
      </tr>
      `;
    })
    .join('');

  // Active groups
  const user = req.session.user;
  // Add originalPreferens to each item for claim tracking
  function withOriginalPreferens(arr) {
    return arr.map(s => {
      if (!s.originalPreferens) {
        // If not present, set it to the initial preferens
        s.originalPreferens = s.preferens;
      }
      return s;
    });
  }
  withOriginalPreferens(list);
  const activeRowsAll = renderRows(actives.filter(s => s.preferens === 'Vem som'), false, true, user);
  const activeRowsNoah = renderRows(actives.filter(s => s.preferens === 'Noah'), false);
  const activeRowsAlex = renderRows(actives.filter(s => s.preferens === 'Alex'), false);
  const activeRowsOther = renderRows(actives.filter(s => s.preferens !== 'Noah' && s.preferens !== 'Alex'), false);
  // Done groups
  const doneRowsAll = renderRows(finished.filter(s => s.preferens === 'Vem som'), true, false, user);
  const doneRowsNoah = renderRows(finished.filter(s => s.preferens === 'Noah'), true);
  const doneRowsAlex = renderRows(finished.filter(s => s.preferens === 'Alex'), true);
  const doneRowsOther = renderRows(finished.filter(s => s.preferens !== 'Noah' && s.preferens !== 'Alex'), true);

  const activeCount = actives.length;
  const doneCount = finished.length;
  const preferensLabels = ['Noah', 'Alex', 'Vem som'];
  const preferensCounts = preferensLabels.map(() => 0);
  list.forEach(item => {
    let pref = item.preferens || 'Vem som';
    if (!preferensLabels.includes(pref)) pref = 'Vem som';
    const idx = preferensLabels.indexOf(pref);
    if (idx >= 0) preferensCounts[idx] += 1;
  });

  const normalizePreferens = pref => {
    if (pref === 'Noah' || pref === 'Alex' || pref === 'Vem som') return pref;
    return 'Vem som';
  };

  const urgencyLabels = ['Inte bråttom', 'Snart', 'Mycket bråttom'];
  const urgencyCounts = urgencyLabels.map(() => 0);
  const allowedUrgencyPrefs = (() => {
    if (user === 'noah') return new Set(['Noah', 'Vem som']);
    if (user === 'alex') return new Set(['Alex', 'Vem som']);
    return null; // admin sees all
  })();
  const urgencySource = list.filter(item => {
    const pref = normalizePreferens(item.preferens || 'Vem som');
    if (!allowedUrgencyPrefs) return true;
    return allowedUrgencyPrefs.has(pref);
  });
  urgencySource.forEach(item => {
    const idx = urgencyLabels.indexOf(item.brattom || '');
    if (idx >= 0) urgencyCounts[idx] += 1;
  });
  const urgencyTotal = urgencySource.length;

  const statusLabels = ['Aktiva', 'Klara'];
  const statusCounts = [activeCount, doneCount];

  const totalSubmissions = list.length;
  const safePercent = (value, total) => {
    if (!total) return 0;
    return Math.round((value / total) * 100);
  };

  const statusColors = ['#38bdf8', '#22c55e'];
  const statusBarsHtml = statusLabels.map((label, idx) => {
    const value = statusCounts[idx];
    const percent = safePercent(value, totalSubmissions);
    const width = value > 0 ? Math.max(percent, 12) : 0;
    return `<div class="bar-row" role="listitem"><span class="bar-label">${label}</span><div class="bar-track"><div class="bar-fill" data-target="${width}" style="width:0;background:${statusColors[idx] || '#475569'}"></div></div><span class="bar-value">${value}</span></div>`;
  }).join('');

  const preferensColors = ['#60a5fa', '#7c3aed', '#38bdf8'];
  const preferensBarsHtml = preferensLabels.map((label, idx) => {
    const value = preferensCounts[idx];
    const percent = safePercent(value, totalSubmissions);
    const width = value > 0 ? Math.max(percent, 10) : 0;
    return `<div class="bar-row" role="listitem"><span class="bar-label">${label}</span><div class="bar-track"><div class="bar-fill" data-target="${width}" style="width:0;background:${preferensColors[idx] || '#475569'}"></div></div><span class="bar-value">${value}</span></div>`;
  }).join('');

  const urgencyColors = ['#16a34a', '#facc15', '#f97316'];
  const urgencyBarsHtml = urgencyLabels.map((label, idx) => {
  const value = urgencyCounts[idx];
  const percent = safePercent(value, urgencyTotal);
    const width = value > 0 ? Math.max(percent, 12) : 0;
    return `<div class="bar-row" role="listitem"><span class="bar-label">${label}</span><div class="bar-track"><div class="bar-fill" data-target="${width}" style="width:0;background:${urgencyColors[idx] || '#475569'}"></div></div><span class="bar-value">${value}</span></div>`;
  }).join('');

  const html = `<!doctype html>
<html lang="sv">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Admin – Inskickade modeller</title>
  <style>
    :root{--bg:#0f172a;--text:#e5e7eb;--muted:#9ca3af;--brand:#0b1220;--card:#111827;--border:rgba(255,255,255,0.1);--accent:#60a5fa;--hover:rgba(255,255,255,0.06)}
    *{box-sizing:border-box}
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;line-height:1.45;margin:0;background:var(--bg);color:var(--text)}
    header{background:var(--brand);color:#fff;padding:16px 20px}
    main{padding:20px}
    .container{max-width:1100px;margin:0 auto}
    .card{background:var(--card);border:1px solid var(--border);border-radius:14px;box-shadow:0 6px 20px rgba(0,0,0,0.45)}
    .card-header{padding:14px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
    .card-body{padding:0}
    table{width:100%;border-collapse:separate;border-spacing:0;color:var(--text)}
    th,td{padding:10px 12px;vertical-align:top}
    thead th{position:sticky;top:0;background:#0f172a;border-bottom:1px solid var(--border);text-align:left;color:var(--text)}
    tbody tr{border-bottom:1px solid var(--border)}
    tbody tr:nth-child(even){background:rgba(255,255,255,0.02)}
    tbody tr:hover{background:var(--hover)}
    a{color:#93c5fd}
    .small{color:var(--muted);font-size:12px}
    .wrap{word-break:break-word;white-space:pre-wrap}
    .topbar{display:flex;justify-content:space-between;align-items:center;gap:12px}
    .left{display:flex;align-items:center;gap:12px}
    a.home{color:#93c5fd;text-decoration:none;border:1px solid #93c5fd;border-radius:8px;padding:6px 10px;background:transparent}
    a.home:hover{background:#93c5fd;color:#0b1020}
    th.sortable{cursor:pointer;user-select:none}
    th.sortable::after{content:'↕';font-size:12px;opacity:.6;margin-left:6px}
    th.sortable[aria-sort="ascending"]::after{content:'▲';opacity:.95}
    th.sortable[aria-sort="descending"]::after{content:'▼';opacity:.95}
    .table-wrap{overflow:auto;border-radius:14px}
    .btn-del{display:inline-block;margin-top:6px;background:#ef4444;color:#fff;padding:4px 8px;border-radius:6px;text-decoration:none;font-size:12px}
    .btn-del:hover{filter:brightness(1.05)}
    .claimed{color:#60a5fa;font-size:0.95em;margin-left:2px}
    .charts-section{margin-bottom:26px}
    .charts-header{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;margin-bottom:16px;flex-wrap:wrap}
    .charts-header h2{margin:0;font-size:22px}
    .chart-grid{display:grid;gap:16px;grid-template-columns:repeat(auto-fit,minmax(240px,1fr))}
    .chart-card{background:rgba(17,24,39,0.75);border:1px solid rgba(148,163,184,0.12);border-radius:16px;padding:16px;backdrop-filter:blur(12px);box-shadow:0 12px 32px rgba(0,0,0,0.4);position:relative;overflow:hidden}
    .chart-card h3{margin:0 0 12px 0;font-size:16px;color:var(--text)}
    .bar-chart{display:flex;flex-direction:column;gap:10px;margin-top:10px}
    .bar-row{display:grid;grid-template-columns:auto 1fr auto;gap:10px;align-items:center}
    .bar-label{font-size:13px;color:var(--muted)}
    .bar-track{background:rgba(148,163,184,0.12);border-radius:999px;height:12px;position:relative;overflow:hidden}
    .bar-fill{height:100%;border-radius:999px;width:0;transition:width .55s cubic-bezier(0.16,1,0.3,1)}
    .bar-value{font-weight:600;color:#f8fafc;font-size:13px}
    .stat-pills{display:flex;gap:12px;flex-wrap:wrap;margin-top:6px}
    .stat-pill{background:rgba(96,165,250,0.12);border:1px solid rgba(148,163,184,0.18);border-radius:999px;padding:10px 16px;display:flex;flex-direction:column;min-width:130px}
    .stat-pill strong{font-size:20px;color:#f8fafc;margin-bottom:2px}
    .stat-pill span{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:0.06em}
    .user-pill{padding:6px 10px;border-radius:999px;border:1px solid rgba(148,163,184,0.24);background:rgba(148,163,184,0.12);color:var(--muted);font-size:13px}
    .show-more{color:#93c5fd;font-size:12px;margin-left:4px}
    .desc-modal-bg{position:fixed;top:0;left:0;width:100vw;height:100vh;background:rgba(0,0,0,0.45);z-index:1000;display:flex;align-items:center;justify-content:center}
    .desc-modal{background:#111827;color:#e5e7eb;padding:28px 32px;border-radius:14px;max-width:480px;box-shadow:0 8px 32px #000a;font-size:1.05em;position:relative}
    .desc-close{position:absolute;top:10px;right:14px;background:#ef4444;color:#fff;border:none;border-radius:6px;padding:4px 10px;cursor:pointer}
    @media (max-width:768px){header{padding:16px}main{padding:16px}}
  </style>
</head>
<body data-user="${escapeHtml(req.session.user || '')}">
<header>
  <div class="topbar">
    <div class="left">
      <a class="home" href="/">← Till startsidan</a>
      <h1>Admin – Inskickade modeller</h1>
    </div>
    <div class="actions" style="display:flex;align-items:center;gap:10px">
      <span class="user-pill" aria-live="polite">Inloggad som ${escapeHtml(req.session.displayName || req.session.user || '')}</span>
      <a class="btn-logout" href="/logout" style="text-decoration:none;background:#ef4444;color:#fff;padding:6px 10px;border-radius:8px">Logga ut</a>
    </div>
  </div>
</header>
<main>
  <div class="container">
    <section class="charts-section">
      <div class="charts-header">
        <div>
          <h2>Översikt</h2>
          <p class="small" style="margin-top:4px">Totalt ${totalSubmissions} inkomna modeller senaste tiden.</p>
          <div class="stat-pills">
            <div class="stat-pill" aria-label="Aktiva ärenden">
              <strong>${activeCount}</strong>
              <span>Aktiva ärenden</span>
            </div>
            <div class="stat-pill" aria-label="Avslutade ärenden">
              <strong>${doneCount}</strong>
              <span>Avslutade</span>
            </div>
            <div class="stat-pill" aria-label="Totala ärenden">
              <strong>${totalSubmissions}</strong>
              <span>Totalt registrerade</span>
            </div>
          </div>
        </div>
      </div>
      <div class="chart-grid">
        <div class="chart-card">
          <h3>Status</h3>
          <div class="bar-chart" role="list" aria-live="polite">
            ${statusBarsHtml}
          </div>
        </div>
        <div class="chart-card">
          <h3>Preferens</h3>
          <div class="bar-chart" role="list" aria-live="polite">
            ${preferensBarsHtml}
          </div>
        </div>
        <div class="chart-card">
          <h3>Hur bråttom</h3>
          <div class="bar-chart" role="list" aria-live="polite">
            ${urgencyBarsHtml}
          </div>
        </div>
      </div>
    </section>

    <div class="card" style="margin-bottom:16px">
      <div class="card-header">
        <div>
          <strong>Aktiva</strong> – Pågående 3D‑utskrifter
        </div>
      </div>
      <div id="activeBody" class="card-body table-wrap">
        <section id="activeAllSec">
          <h3 style="margin:12px 16px">Alla</h3>
          <table id="activeAllTable" style="margin-bottom:12px">
            <thead>
              <tr>
                <th>#</th>
                <th>Klar</th>
                <th class="sortable" data-index="2">Namn</th>
                <th class="sortable" data-index="3">Mejl</th>
                <th class="sortable" data-index="4">Kort beskrivning</th>
                <th class="sortable" data-index="5">Preferens</th>
                <th class="sortable" data-index="6">Hur bråttom</th>
                <th class="sortable" data-index="7" data-type="date">Inskickad</th>
                <th class="sortable" data-index="8">Fil</th>
              </tr>
            </thead>
            <tbody>
              ${activeRowsAll || '<tr><td colspan="9">Inga aktiva ärenden.</td></tr>'}
            </tbody>
          </table>
        </section>

        <section id="activeNoahSec">
          <details id="activeNoahDetails" style="margin:12px 16px">
            <summary style="cursor:pointer;user-select:none;color:#93c5fd">Noah</summary>
            <div style="margin-top:8px">
              <table id="activeNoahTable" style="margin-bottom:12px">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Klar</th>
                    <th class="sortable" data-index="2">Namn</th>
                    <th class="sortable" data-index="3">Mejl</th>
                    <th class="sortable" data-index="4">Kort beskrivning</th>
                    <th class="sortable" data-index="5">Preferens</th>
                    <th class="sortable" data-index="6">Hur bråttom</th>
                    <th class="sortable" data-index="7" data-type="date">Inskickad</th>
                    <th class="sortable" data-index="8">Fil</th>
                  </tr>
                </thead>
                <tbody>
                  ${activeRowsNoah || '<tr><td colspan="9">Inga aktiva ärenden.</td></tr>'}
                </tbody>
              </table>
            </div>
          </details>
        </section>

        <section id="activeAlexSec">
          <details id="activeAlexDetails" style="margin:12px 16px">
            <summary style="cursor:pointer;user-select:none;color:#93c5fd">Alex</summary>
            <div style="margin-top:8px">
              <table id="activeAlexTable">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Klar</th>
                    <th class="sortable" data-index="2">Namn</th>
                    <th class="sortable" data-index="3">Mejl</th>
                    <th class="sortable" data-index="4">Kort beskrivning</th>
                    <th class="sortable" data-index="5">Preferens</th>
                    <th class="sortable" data-index="6">Hur bråttom</th>
                    <th class="sortable" data-index="7" data-type="date">Inskickad</th>
                    <th class="sortable" data-index="8">Fil</th>
                  </tr>
                </thead>
                <tbody>
                  ${activeRowsAlex || '<tr><td colspan="9">Inga aktiva ärenden.</td></tr>'}
                </tbody>
              </table>
            </div>
          </details>
        </section>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <div>
          <strong>Färdiga</strong> – Slutförda 3D‑utskrifter
        </div>
      </div>
      <div id="doneBody" class="card-body table-wrap">
        <section id="doneAllSec">
          <h3 style="margin:12px 16px">Alla färdiga</h3>
          <table id="doneAllTable" style="margin-bottom:12px">
            <thead>
              <tr>
                <th>#</th>
                <th>Klar</th>
                <th class="sortable" data-index="2">Namn</th>
                <th class="sortable" data-index="3">Mejl</th>
                <th class="sortable" data-index="4">Kort beskrivning</th>
                <th class="sortable" data-index="5">Preferens</th>
                <th class="sortable" data-index="6">Hur bråttom</th>
                <th class="sortable" data-index="7" data-type="date">Inskickad</th>
                <th class="sortable" data-index="8">Fil</th>
              </tr>
            </thead>
            <tbody>
              ${doneRowsAll || '<tr><td colspan="9">Inga färdiga än.</td></tr>'}
            </tbody>
          </table>
        </section>
      </div>
    </div>
  </div>
</main>

<script>
  document.addEventListener('click', function(e) {
    const closeBtn = e.target.closest('.desc-close');
    if (closeBtn) {
      closeBtn.closest('.desc-modal-bg')?.remove();
      return;
    }
    const cell = e.target.closest('.beskrivning-cell.long-desc');
    if (!cell) return;
    const full = cell.getAttribute('data-full') || '';
    const bg = document.createElement('div');
    bg.className = 'desc-modal-bg';
    const modal = document.createElement('div');
    modal.className = 'desc-modal';
    modal.innerHTML = full + '<button type="button" class="desc-close">Stäng</button>';
    bg.appendChild(modal);
    document.body.appendChild(bg);
  });
</script>

<script>
  (function(){
    function animateCharts(){
      const prefersReduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const fills = document.querySelectorAll('.bar-fill');
      const applyTargets = () => {
        fills.forEach(el => {
          const target = el.getAttribute('data-target');
          if (!target) return;
          el.style.width = target + '%';
        });
      };
      if (prefersReduced) { applyTargets(); return; }
      requestAnimationFrame(() => requestAnimationFrame(applyTargets));
    }
    if (document.readyState !== 'loading') animateCharts();
    else document.addEventListener('DOMContentLoaded', animateCharts);
  })();
</script>

<script>
  (function(){
    function initSortable(table){
      if (!table) return;
      const tbody = table.tBodies[0];
      const headers = table.querySelectorAll('thead th.sortable');
      let current = { index: null, dir: 'asc' };

      function getCellValue(row, idx, type) {
        const cell = row.children[idx];
        if (!cell) return '';
        const ds = cell.getAttribute('data-sort');
        if (type === 'date') {
          const n = ds ? parseFloat(ds) : Date.parse(cell.textContent.trim());
          return Number.isNaN(n) ? 0 : n;
        }
        return (ds || cell.textContent || '').trim().toLowerCase();
      }

      function renumber(){
        const rows = Array.from(tbody.querySelectorAll('tr'));
        rows.forEach((r, i) => {
          const first = r.children[0];
          if (first) first.textContent = i + 1;
        });
      }

      function sortBy(index, type) {
        const rows = Array.from(tbody.querySelectorAll('tr'));
        const dir = current.index === index && current.dir === 'asc' ? 'desc' : 'asc';

        rows.sort((a, b) => {
          const va = getCellValue(a, index, type);
          const vb = getCellValue(b, index, type);
          if (type === 'date') {
            return dir === 'asc' ? va - vb : vb - va;
          }
          const res = String(va).localeCompare(String(vb), 'sv', { sensitivity: 'base' });
          return dir === 'asc' ? res : -res;
        });

        rows.forEach(r => tbody.appendChild(r));
        headers.forEach(h => h.removeAttribute('aria-sort'));
        const active = Array.from(headers).find(h => parseInt(h.dataset.index, 10) === index);
        if (active) active.setAttribute('aria-sort', dir === 'asc' ? 'ascending' : 'descending');
        current = { index, dir };
        renumber();
      }

      headers.forEach(h => {
        h.addEventListener('click', () => {
          const index = parseInt(h.dataset.index, 10);
          const type = h.dataset.type || 'text';
          sortBy(index, type);
        });
      });

      return { renumber };
    }

    const tables = {
      activeAll: document.getElementById('activeAllTable'),
      activeNoah: document.getElementById('activeNoahTable'),
      activeAlex: document.getElementById('activeAlexTable'),
      doneAll: document.getElementById('doneAllTable')
    };
    const sorters = Object.fromEntries(Object.entries(tables).map(([k, el]) => [k, initSortable(el)]));

    const userRole = document.body.getAttribute('data-user');
    function reorderSections(group){
      const container = document.getElementById(group + 'Body');
      if (!container) return;
      const all = document.getElementById(group + 'AllSec');
      const noah = document.getElementById(group + 'NoahSec');
      const alex = document.getElementById(group + 'AlexSec');
      const frag = document.createDocumentFragment();
      if (group === 'done') {
        if (all) frag.appendChild(all);
        if (noah) frag.appendChild(noah);
        if (alex) frag.appendChild(alex);
      } else {
        if (userRole === 'noah') {
          if (noah) frag.appendChild(noah);
          if (all) frag.appendChild(all);
          if (alex) frag.appendChild(alex);
        } else if (userRole === 'alex') {
          if (alex) frag.appendChild(alex);
          if (all) frag.appendChild(all);
          if (noah) frag.appendChild(noah);
        } else {
          if (all) frag.appendChild(all);
          if (noah) frag.appendChild(noah);
          if (alex) frag.appendChild(alex);
        }
      }
      container.innerHTML = '';
      container.appendChild(frag);
    }
    reorderSections('active');
    reorderSections('done');

    document.addEventListener('change', async (e) => {
      const cb = e.target;
      if (!(cb instanceof HTMLInputElement)) return;
      if (!cb.classList.contains('toggle-done')) return;
      const id = cb.getAttribute('data-id');
      const done = cb.checked;
      try {
        const res = await fetch('/api/admin/submissions/' + id + '/done', {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ done })
        });
        if (!res.ok) throw new Error('Update failed');
        const row = cb.closest('tr');
        if (!row) return;
        const srcTbody = row.parentElement;
        const pref = (row.querySelector('td:nth-child(6)')?.textContent || '').trim();
        const dstTbody = (function(){
          if (done) return tables.doneAll?.tBodies?.[0];
          if (pref === 'Noah') return tables.activeNoah?.tBodies?.[0];
          if (pref === 'Alex') return tables.activeAlex?.tBodies?.[0];
          return tables.activeAll?.tBodies?.[0];
        })();
        if (dstTbody && dstTbody.querySelector('td[colspan]')) dstTbody.innerHTML = '';
        if (dstTbody) dstTbody.appendChild(row);
        Object.values(sorters).forEach(s => s && s.renumber && s.renumber());
        if (srcTbody && !srcTbody.querySelector('tr[data-id]')) {
          srcTbody.innerHTML = '';
          const tr = document.createElement('tr');
          const td = document.createElement('td');
          td.colSpan = 9;
          td.textContent = done ? 'Inga aktiva ärenden.' : 'Inga färdiga än.';
          tr.appendChild(td);
          srcTbody.appendChild(tr);
        }
      } catch (err) {
        cb.checked = !done;
        alert('Kunde inte uppdatera status. Försök igen.');
      }
    });

    document.addEventListener('click', async (e) => {
      const target = e.target;
      if (!(target instanceof HTMLElement)) return;
      if (target.classList.contains('btn-del')) {
        const id = target.getAttribute('data-id');
        if (!id) return;
        if (!confirm('Är du säker på att du vill ta bort denna rad och dess fil?')) return;
        try {
          const res = await fetch('/api/admin/submissions/' + id, { method: 'DELETE' });
          if (!res.ok) throw new Error('Delete failed');
          const row = target.closest('tr');
          if (!row) return;
          const tbody = row.parentElement;
          row.remove();
          Object.values(sorters).forEach(s => s && s.renumber && s.renumber());
          if (tbody && !tbody.querySelector('tr[data-id]')) {
            tbody.innerHTML = '';
            const tr = document.createElement('tr');
            const td = document.createElement('td');
            td.colSpan = 9;
            td.textContent = (tbody.parentElement?.parentElement?.id === 'doneTable') ? 'Inga färdiga än.' : 'Inga aktiva ärenden.';
            tr.appendChild(td);
            tbody.appendChild(tr);
          }
        } catch (err) {
          alert('Kunde inte ta bort posten. Försök igen.');
        }
      } else if (target.classList.contains('btn-claim')) {
        const id = target.getAttribute('data-id');
        if (!id) return;
        if (!confirm('Vill du ta över denna 3D-print?')) return;
        try {
          const res = await fetch('/api/admin/submissions/' + id + '/claim', { method: 'PATCH' });
          if (!res.ok) throw new Error('Claim failed');
          location.reload();
        } catch (err) {
          alert('Kunde inte ta över posten. Försök igen.');
        }
      } else if (target.classList.contains('btn-unclaim')) {
        const id = target.getAttribute('data-id');
        if (!id) return;
        if (!confirm('Vill du ångra och flytta tillbaka till Vem som?')) return;
        try {
          const res = await fetch('/api/admin/submissions/' + id + '/unclaim', { method: 'PATCH' });
          if (!res.ok) throw new Error('Unclaim failed');
          location.reload();
        } catch (err) {
          alert('Kunde inte ångra posten. Försök igen.');
        }
      }
    });
  })();
</script>
</body>
</html>`;

  res.send(html);
});

app.patch('/api/admin/submissions/:id/claim', sessionAuth, (req, res) => {
  const id = req.params.id;
  const userRole = req.session.user;
  if (userRole !== 'noah' && userRole !== 'alex') {
    return res.status(403).json({ ok: false, error: 'Endast Noah eller Alex kan ta över' });
  }
  const db = readDb();
  const idx = db.findIndex(s => s.id === id);
  if (idx === -1) return res.status(404).json({ ok: false, error: 'not found' });
  if (db[idx].preferens !== 'Vem som') {
    return res.status(400).json({ ok: false, error: 'Kan bara ta över "Vem som" prints' });
  }
  if (!db[idx].originalPreferens) db[idx].originalPreferens = 'Vem som';
  db[idx].preferens = userRole === 'noah' ? 'Noah' : 'Alex';
  writeDb(db);
  res.json({ ok: true });
});

app.patch('/api/admin/submissions/:id/unclaim', sessionAuth, (req, res) => {
  const id = req.params.id;
  const userRole = req.session.user;
  if (userRole !== 'noah' && userRole !== 'alex') {
    return res.status(403).json({ ok: false, error: 'Endast Noah eller Alex kan ångra' });
  }
  const db = readDb();
  const idx = db.findIndex(s => s.id === id);
  if (idx === -1) return res.status(404).json({ ok: false, error: 'not found' });
  if ((db[idx].preferens !== 'Noah' && db[idx].preferens !== 'Alex') || db[idx].originalPreferens !== 'Vem som') {
    return res.status(400).json({ ok: false, error: 'Kan bara ångra "Vem som"-claimade prints' });
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
