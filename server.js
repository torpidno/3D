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
    return JSON.parse(raw);
  } catch (e) {
    console.error('Failed to read DB, resetting to []', e);
    fs.writeFileSync(DB_FILE, '[]', 'utf8');
    return [];
  }
}

function writeDb(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), 'utf8');
}

// Multer setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const id = uuidv4();
    cb(null, `${Date.now()}_${id}${ext}`);
  }
});

const allowedExt = new Set(['.stl', '.3mf']);
const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!allowedExt.has(ext)) {
      return cb(new Error('Endast .stl eller .3mf filer accepteras'));
    }
    cb(null, true);
  }
});

// Body parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// Sessions
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 30 // 30 days
  }
}));
// Static files
app.use(express.static(path.join(__dirname, 'public')));

// Session auth middleware
function sessionAuth(req, res, next) {
  if (req.session && req.session.authenticated) return next();
  return res.redirect('/login');
}

// Legacy: keep basic auth config (not used) to avoid breaking require lines
const adminAuth = (req, res, next) => next();

// Login routes
app.get('/login', (req, res) => {
  if (req.session && req.session.authenticated) return res.redirect('/admin');
  const hasError = String(req.query.error || '') === '1';
  const html = `<!doctype html>
<html lang="sv">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Logga in</title>
  <style>
    :root{--bg:#0f172a;--card:#111827;--text:#e5e7eb;--muted:#9ca3af;--accent:#60a5fa}
    *{box-sizing:border-box}
    body{margin:0;background:linear-gradient(135deg,#0f172a,#1f2937);color:var(--text);font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
    .card{width:100%;max-width:420px;background:rgba(17,24,39,0.6);backdrop-filter:blur(10px);border:1px solid rgba(255,255,255,0.08);border-radius:16px;padding:28px;box-shadow:0 10px 30px rgba(0,0,0,0.45)}
    h1{margin:0 0 10px 0;font-size:24px}
    label{display:block;margin:12px 0 6px}
    input{width:100%;padding:12px 14px;border:1px solid rgba(255,255,255,0.12);border-radius:10px;background:rgba(255,255,255,0.06);color:var(--text);outline:none}
    .btn{margin-top:16px;background:var(--accent);color:#0b1020;border:none;padding:12px 16px;border-radius:10px;font-weight:600;cursor:pointer;width:100%}
    .err{color:#ef4444;margin-top:10px}
    .muted{color:var(--muted);font-size:12px;margin-top:8px}
    a{color:#93c5fd;text-decoration:none}
  </style>
  </head>
  <body>
    <div class="card">
      <h1>Admin – Logga in</h1>
      ${hasError ? '<div class="err">Fel användarnamn eller lösenord</div>' : ''}
      <form method="POST" action="/login">
        <label for="username">Användarnamn</label>
        <input id="username" name="username" type="text" required />
        <label for="password">Lösenord</label>
        <input id="password" name="password" type="password" required />
        <button class="btn" type="submit">Logga in</button>
      </form>
      <div class="muted" style="margin-top:12px"><a href="/">← Till startsidan</a></div>
    </div>
  </body>
  </html>`;
  res.send(html);
});

app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (username === ADMIN_USER && password === ADMIN_PASSWORD) {
    req.session.authenticated = true;
    req.session.user = 'admin';
    return res.redirect('/admin');
  }
  if (username === NOAH_USER && password === NOAH_PASSWORD) {
    req.session.authenticated = true;
    req.session.user = 'noah';
    return res.redirect('/admin');
  }
  if (username === ALEX_USER && password === ALEX_PASSWORD) {
    req.session.authenticated = true;
    req.session.user = 'alex';
    return res.redirect('/admin');
  }
  return res.redirect('/login?error=1');
});

app.get('/logout', (req, res) => {
  req.session?.destroy(() => {
    res.clearCookie('connect.sid');
    res.redirect('/login');
  });
});

// Submit endpoint
app.post('/api/submit', upload.single('modelFile'), (req, res) => {
  const { namn, mejl, beskrivning, preferens, brattom } = req.body || {};

  if (!namn || !mejl || !beskrivning || !preferens || !brattom) {
    if (req.file) {
      // cleanup uploaded file if validation fails
      try { fs.unlinkSync(req.file.path); } catch {}
    }
    return res.status(400).json({ ok: false, error: 'Alla fält är obligatoriska' });
  }

  if (!req.file) {
    return res.status(400).json({ ok: false, error: 'Fil (.stl eller .3mf) krävs' });
  }

  const id = uuidv4();
  const now = new Date().toISOString();
  const entry = {
    id,
    submittedAt: now,
    namn,
    mejl,
    beskrivning,
    preferens,
    brattom,
    done: false,
    file: {
      storedName: path.basename(req.file.filename),
      originalName: req.file.originalname,
      size: req.file.size
    }
  };

  const db = readDb();
  db.push(entry);
  writeDb(db);

  // If client expects HTML, redirect to thank-you page, else JSON
  const acceptsHtml = (req.headers.accept || '').includes('text/html');
  if (acceptsHtml) {
    return res.redirect('/thanks.html');
  }
  res.json({ ok: true, id });
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

  const renderRows = (arr, isDone, allowClaim = false, user = '') => arr
    .map((s, idx) => {
      // Show (vem som) if this was claimed (i.e., preferens is Noah/Alex but originally Vem som)
      let claimed = '';
      if ((s.preferens === 'Noah' || s.preferens === 'Alex') && s.originalPreferens === 'Vem som') {
        claimed = ' <span class="claimed">(vem som)</span>';
      }
      // Truncate description if too long, add click handler
      const desc = escapeHtml(s.beskrivning);
      // Always render the full description, but clamp to 2 lines with CSS
      // '[visa mer]' will be shown by JS if the text is actually truncated
  // Always show '[visa mer]' if description is long (over 60 chars)
      return `
      <tr data-id="${s.id}">
        <td class="idx">${idx + 1}</td>
        <td><input type="checkbox" class="toggle-done" data-id="${s.id}" aria-label="Markera klar" ${isDone ? 'checked' : ''} /></td>
        <td>${escapeHtml(s.namn)}</td>
        <td><a href="mailto:${escapeHtml(s.mejl)}">${escapeHtml(s.mejl)}</a></td>
        <td class="wrap beskrivning-cell">${desc}</td>
        <td>${escapeHtml(s.preferens)}${claimed}</td>
        <td>${escapeHtml(s.brattom)}</td>
        <td data-sort="${new Date(s.submittedAt).getTime()}">${formatShortDate(s.submittedAt)}</td>
        <td>
          <a href="/admin/download/${s.id}">Ladda ner</a>
          <button type="button" class="btn-del" data-id="${s.id}">Ta bort</button>
          ${allowClaim && (user === 'noah' || user === 'alex') && s.preferens === 'Vem som' ? `<button type=\"button\" class=\"btn-claim\" data-id=\"${s.id}\">Ta över</button>` : ''}
          ${(user === 'noah' || user === 'alex') && (s.preferens === 'Noah' || s.preferens === 'Alex') && s.originalPreferens === 'Vem som' ? `<button type=\"button\" class=\"btn-unclaim\" data-id=\"${s.id}\">Ångra</button>` : ''}
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
// Unclaim a claimed print (move back to 'Vem som')
app.patch('/api/admin/submissions/:id/unclaim', sessionAuth, (req, res) => {
  const id = req.params.id;
  const user = req.session.user;
  if (user !== 'noah' && user !== 'alex') return res.status(403).json({ ok:false, error: 'Endast Noah eller Alex kan ångra' });
  const db = readDb();
  const idx = db.findIndex(s => s.id === id);
  if (idx === -1) return res.status(404).json({ ok:false, error: 'not found' });
  if ((db[idx].preferens !== 'Noah' && db[idx].preferens !== 'Alex') || db[idx].originalPreferens !== 'Vem som') {
    return res.status(400).json({ ok:false, error: 'Kan bara ångra "Vem som"-claimade prints' });
  }
  db[idx].preferens = 'Vem som';
  writeDb(db);
  res.json({ ok:true });
});
// Claim a 'Vem som' print
app.patch('/api/admin/submissions/:id/claim', sessionAuth, (req, res) => {
  const id = req.params.id;
  const user = req.session.user;
  if (user !== 'noah' && user !== 'alex') return res.status(403).json({ ok:false, error: 'Endast Noah eller Alex kan ta över' });
  const db = readDb();
  const idx = db.findIndex(s => s.id === id);
  if (idx === -1) return res.status(404).json({ ok:false, error: 'not found' });
  if (db[idx].preferens !== 'Vem som') return res.status(400).json({ ok:false, error: 'Kan bara ta över "Vem som" prints' });
  if (!db[idx].originalPreferens) db[idx].originalPreferens = 'Vem som';
  db[idx].preferens = user.charAt(0).toUpperCase() + user.slice(1); // Noah or Alex
  writeDb(db);
  res.json({ ok:true });
});
  const doneRowsNoah = renderRows(finished.filter(s => s.preferens === 'Noah'), true);
  const doneRowsAlex = renderRows(finished.filter(s => s.preferens === 'Alex'), true);
  const doneRowsOther = renderRows(finished.filter(s => s.preferens !== 'Noah' && s.preferens !== 'Alex'), true);

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
    code{background:#1f2937;padding:2px 4px;border-radius:4px;color:#e5e7eb}
    /* Sortable table styles */
    th.sortable{cursor:pointer;user-select:none}
    th.sortable::after{content:'↕'; font-size:12px;opacity:.6;margin-left:6px}
    th.sortable[aria-sort="ascending"]::after{content:'▲'; opacity:.95}
    th.sortable[aria-sort="descending"]::after{content:'▼'; opacity:.95}
    .table-wrap{overflow:auto;border-radius:14px}
    .btn-del{display:inline-block;margin-top:6px;background:#ef4444;color:#fff;padding:4px 8px;border-radius:6px;text-decoration:none;font-size:12px}
    .btn-del:hover{filter:brightness(1.05)}
    .claimed { color: #60a5fa; font-size: 0.95em; margin-left: 2px; }
  </style>
  <style>
    .desc-modal-bg {
      position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
      background: rgba(0,0,0,0.45); z-index: 1000; display: flex; align-items: center; justify-content: center;
    }
    .desc-modal {
      background: #111827; color: #e5e7eb; padding: 28px 32px; border-radius: 14px; max-width: 480px; box-shadow: 0 8px 32px #000a; font-size: 1.1em;
      position: relative;
    }
    .desc-modal button { position: absolute; top: 10px; right: 14px; background: #ef4444; color: #fff; border: none; border-radius: 6px; padding: 4px 10px; cursor: pointer; }
  </style>
<script>
// Popup for long description
// No need for JS clamp detection, always show '[visa mer]' for long descriptions
// Popup for long description
document.addEventListener('click', function(e) {
  const cell = e.target.closest('.beskrivning-cell.long-desc');
  if (cell) {
    const full = cell.getAttribute('data-full');
    const modalBg = document.createElement('div');
    modalBg.className = 'desc-modal-bg';
    modalBg.innerHTML = '<div class="desc-modal">' +
      full.replace(/\n/g, '<br>') +
      '<button type="button" style="position:absolute;top:10px;right:14px;background:#ef4444;color:#fff;border:none;border-radius:6px;padding:4px 10px;cursor:pointer;" onclick="this.closest(\'.desc-modal-bg\').remove()">Stäng</button>' +
      '</div>';
    document.body.appendChild(modalBg);
    return;
  }
});
</script>
</head>
<body data-user="${escapeHtml(req.session.user || '')}">
<header>
  <div class="topbar">
    <div class="left">
      <a class="home" href="/">← Till startsidan</a>
      <h1>Admin – Inskickade modeller</h1>
    </div>
    <div class="actions" style="display:flex;align-items:center;gap:10px">
  <a class="btn-logout" href="/logout" style="text-decoration:none;background:#ef4444;color:#fff;padding:6px 10px;border-radius:8px">Logga ut</a>
    </div>
  </div>
</header>
<main>
  <div class="container">
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

        <!-- Övriga section removed -->
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

        <!-- Övriga section removed -->
      </div>
    </div>
  </div>
</main>

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
          return isNaN(n) ? 0 : n;
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

    // Reorder sections for Noah/Alex so their personal table appears first, then All, then the other person
    const user = document.body.getAttribute('data-user');
    function reorderSections(group){
      const container = document.getElementById(group + 'Body');
      if (!container) return;
      const all = document.getElementById(group + 'AllSec');
      const noah = document.getElementById(group + 'NoahSec');
      const alex = document.getElementById(group + 'AlexSec');
      const frag = document.createDocumentFragment();
      if (group === 'done') {
        frag.appendChild(all);
      } else {
        if (user === 'noah') { frag.appendChild(noah); frag.appendChild(all); frag.appendChild(alex); }
        else if (user === 'alex') { frag.appendChild(alex); frag.appendChild(all); frag.appendChild(noah); }
        else { frag.appendChild(all); frag.appendChild(noah); frag.appendChild(alex); }
      }
      container.innerHTML = '';
      container.appendChild(frag);
    }
    reorderSections('active');
    reorderSections('done');

    // Open own section, collapse the other person's section (not affecting "Övriga")
    (function controlDetailsByUser(){
      const user = document.body.getAttribute('data-user');
      const d = {
        activeNoah: document.getElementById('activeNoahDetails'),
        activeAlex: document.getElementById('activeAlexDetails'),
        doneNoah: document.getElementById('doneNoahDetails'),
        doneAlex: document.getElementById('doneAlexDetails')
      };
      if (user === 'noah') {
        if (d.activeNoah) d.activeNoah.open = true;
        if (d.doneNoah) d.doneNoah.open = true;
        if (d.activeAlex) d.activeAlex.open = false;
        if (d.doneAlex) d.doneAlex.open = false;
      } else if (user === 'alex') {
        if (d.activeAlex) d.activeAlex.open = true;
        if (d.doneAlex) d.doneAlex.open = true;
        if (d.activeNoah) d.activeNoah.open = false;
        if (d.doneNoah) d.doneNoah.open = false;
      } else {
        // admin: show both open
        if (d.activeNoah) d.activeNoah.open = true;
        if (d.doneNoah) d.doneNoah.open = true;
        if (d.activeAlex) d.activeAlex.open = true;
        if (d.doneAlex) d.doneAlex.open = true;
      }
    })();

    function ensurePlaceholder(tbody){
      const hasRows = tbody.querySelector('tr[data-id]');
      const rowCount = tbody.querySelectorAll('tr').length;
      if (!hasRows && rowCount === 0) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 9; td.textContent = 'Inga poster.'; tr.appendChild(td);
        tbody.appendChild(tr);
      }
    }

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
          body: JSON.stringify({ done: done })
        });
        if (!res.ok) throw new Error('Update failed');
        // Move row
        const row = cb.closest('tr');
        if (!row) return;
        const srcTbody = row.parentElement;
        const pref = (row.querySelector('td:nth-child(6)')?.textContent || '').trim();
        const dstTbody = (function(){
          if (done) {
            return tables.doneAll.tBodies[0];
          } else {
            if (pref === 'Noah') return tables.activeNoah.tBodies[0];
            if (pref === 'Alex') return tables.activeAlex.tBodies[0];
            return tables.activeAll.tBodies[0];
          }
        })();
        // Remove placeholder if present
        if (dstTbody.querySelector('td[colspan]')) dstTbody.innerHTML = '';
        dstTbody.appendChild(row);
        // Renumber both tables
  Object.values(sorters).forEach(s => s && s.renumber && s.renumber());
        // If source became empty, show placeholder
        if (srcTbody && !srcTbody.querySelector('tr[data-id]')) {
          srcTbody.innerHTML = '';
          const tr = document.createElement('tr');
          const td = document.createElement('td');
          td.colSpan = 9; td.textContent = done ? 'Inga aktiva ärenden.' : 'Inga färdiga än.';
          tr.appendChild(td);
          srcTbody.appendChild(tr);
        }
      } catch (err) {
        // Revert checkbox if failed
        cb.checked = !done;
        alert('Kunde inte uppdatera status. Försök igen.');
      }
    });

    document.addEventListener('click', async (e) => {
      const btn = e.target;
      if (!(btn instanceof HTMLElement)) return;
      if (!btn.classList.contains('btn-del')) return;
      const id = btn.getAttribute('data-id');
      if (!id) return;
      if (!confirm('Är du säker på att du vill ta bort denna rad och dess fil?')) return;
      try {
        const res = await fetch('/api/admin/submissions/' + id, { method: 'DELETE' });
        if (!res.ok) throw new Error('Delete failed');
        const row = btn.closest('tr');
        if (!row) return;
        const tbody = row.parentElement;
        row.remove();
  // Renumber all tables
  Object.values(sorters).forEach(s => s && s.renumber && s.renumber());
        // If table got empty, show placeholder
        if (tbody && !tbody.querySelector('tr[data-id]')) {
          tbody.innerHTML = '';
          const tr = document.createElement('tr');
          const td = document.createElement('td');
          td.colSpan = 9; td.textContent = (tbody.parentElement?.parentElement?.id === 'doneTable') ? 'Inga färdiga än.' : 'Inga aktiva ärenden.';
          tr.appendChild(td);
          tbody.appendChild(tr);
        }
      } catch (err) {
        alert('Kunde inte ta bort posten. Försök igen.');
      }
    });
    // Claim/Unclaim button handler
    document.addEventListener('click', async (e) => {
      const btn = e.target;
      if (!(btn instanceof HTMLElement)) return;
      if (btn.classList.contains('btn-claim')) {
        const id = btn.getAttribute('data-id');
        if (!id) return;
        if (!confirm('Vill du ta över denna 3D-print?')) return;
        try {
          const res = await fetch('/api/admin/submissions/' + id + '/claim', { method: 'PATCH' });
          if (!res.ok) throw new Error('Claim failed');
          location.reload();
        } catch (err) {
          alert('Kunde inte ta över posten. Försök igen.');
        }
      } else if (btn.classList.contains('btn-unclaim')) {
        const id = btn.getAttribute('data-id');
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
  // Add style for claimed
  // Removed the JS style injection for claimed
  
  // The style is now included in the <style> block above
  })();
</script>
</body>
</html>`;

  res.send(html);
});

// Protected download
app.get('/admin/download/:id', sessionAuth, (req, res) => {
  const id = req.params.id;
  const db = readDb();
  const found = db.find(s => s.id === id);
  if (!found) return res.status(404).send('Ej hittad');
  const filePath = path.join(UPLOAD_DIR, found.file.storedName);
  if (!fs.existsSync(filePath)) return res.status(404).send('Fil saknas på servern');
  res.download(filePath, found.file.originalName);
});

// Basic health
app.get('/api/admin/submissions', sessionAuth, (req,res)=>{
  const db = readDb();
  res.json(db);
});

// Toggle done
app.patch('/api/admin/submissions/:id/done', sessionAuth, (req, res) => {
  const id = req.params.id;
  const { done } = req.body || {};
  if (typeof done !== 'boolean') return res.status(400).json({ ok:false, error: 'done must be boolean' });
  const db = readDb();
  const idx = db.findIndex(s => s.id === id);
  if (idx === -1) return res.status(404).json({ ok:false, error: 'not found' });
  db[idx].done = done;
  writeDb(db);
  res.json({ ok:true });
});

// Delete submission and file
app.delete('/api/admin/submissions/:id', sessionAuth, (req, res) => {
  const id = req.params.id;
  const db = readDb();
  const idx = db.findIndex(s => s.id === id);
  if (idx === -1) return res.status(404).json({ ok:false, error: 'not found' });
  const [removed] = db.splice(idx, 1);
  writeDb(db);
  // delete file best-effort
  try {
    const filePath = path.join(UPLOAD_DIR, removed.file?.storedName || '');
    if (filePath && fs.existsSync(filePath)) fs.unlinkSync(filePath);
  } catch {}
  res.json({ ok:true });
});

// Root route explicitly serves index.html for convenience
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handler for multer/file errors
// eslint-disable-next-line no-unused-vars
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

// Simple HTML escape to avoid accidental HTML injection in admin table
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
