// server.js — sesión única, reemplaza sesión anterior automáticamente, con claim atómico
// Listo para Railway: incluye /health y raíz '/'
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');
const util = require('util');

const app = express();

// ====== Utilidades de respuesta JSON seguras ======
function sendJson(res, status, payload) {
  res.set('Content-Type', 'application/json; charset=utf-8');
  if (payload === undefined || payload === null) {
    return res.status(status || 204).end();
  }
  return res.status(status || 200).json(payload);
}

async function fetchAsText(url, options = {}) {
  const r = await fetch(url, { ...options, headers: { Accept: 'application/json', ...(options.headers||{}) } });
  const text = await r.text();
  const ct = (r.headers.get('content-type') || '').toLowerCase();
  const isJson = ct.includes('application/json') || ct.includes('application/problem+json');
  return { ok: r.ok, status: r.status, text, isJson };
}

app.set('trust proxy', 1);

// ====== Carpetas ======
const DB_DIR = path.join(__dirname, 'db');
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
const PUBLIC_DIR = path.join(__dirname, 'public');

// ====== Sesiones (SQLite) ======
const store = new SQLiteStore({
  db: 'sessions.sqlite',
  dir: DB_DIR
});

app.use(session({
  store,
  secret: process.env.SESSION_SECRET || 'cambia-esta-clave',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: process.env.SAMESITE || 'lax', // 'none' si front/back en dominios distintos (+ secure:true)
    secure: process.env.COOKIE_SECURE === 'true' || process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 8
  }
}));

// Promesas para store.get/destroy
const storeGet = util.promisify(store.get).bind(store);
const storeDestroy = util.promisify(store.destroy).bind(store);

// Body y estáticos
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(PUBLIC_DIR));

// ====== DB usuarios ======
const db = new Database(path.join(DB_DIR, 'usuarios.db'));
db.pragma('journal_mode = wal');
db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT,
    session_id TEXT
  )
`).run();

const DEBUG = process.env.DEBUG_SINGLE_SESSION === '1';
const log = (...a) => DEBUG && console.log('[single-session]', ...a);

// ====== Healthcheck (PUBLICO) ======
app.get('/health', (req, res) => res.status(200).send('OK'));

// ====== Raíz (PUBLICO) ======
app.get('/', (req, res) => {
  const loginFile = path.join(PUBLIC_DIR, 'login.html');
  if (fs.existsSync(loginFile)) return res.sendFile(loginFile);
  res.type('html').send(`<!doctype html><html><head><meta charset="utf-8"><title>Login</title></head>
  <body>
    <h1>Login</h1>
    <form method="POST" action="/login">
      <input name="usuario" placeholder="usuario" required>
      <input type="password" name="password" placeholder="password" required>
      <button>Entrar</button>
    </form>
  </body></html>`);
});

// ====== Helper: autenticar (ajusta a tu lógica real) ======
function autenticar(username, password) {
  const row = db.prepare('SELECT username, password, session_id FROM users WHERE username = ?').get(username);
  if (!row) return null;
  if (row.password && password && row.password !== password) return null;
  return row;
}

// ====== LOGIN: reemplaza SIEMPRE la sesión anterior + claim atómico ======
app.post('/login', async (req, res) => {
  try {
    const { usuario, username, password } = req.body;
    const userField = usuario || username;
    if (!userField) return res.redirect('/login.html?error=credenciales');

    const user = autenticar(userField, password);
    if (!user) return res.redirect('/login.html?error=credenciales');

    // 1) Si había una sesión previa, EXPULSARLA SIEMPRE (reemplazo automático)
    if (user.session_id) {
      await storeDestroy(user.session_id).catch(() => {}); // ignora error si ya expiró
      db.prepare('UPDATE users SET session_id = NULL WHERE username = ?').run(user.username);
    }

    // 2) Regenerar sesión para nuevo SID (evita fijación y choques)
    await new Promise((resolve, reject) => {
      req.session.regenerate(err => (err ? reject(err) : resolve()));
    });

    // 3) Claim ATÓMICO: tomar la sesión solo si sigue NULL
    const claim = db.prepare(
      'UPDATE users SET session_id = ? WHERE username = ? AND session_id IS NULL'
    ).run(req.sessionID, user.username);

    if (claim.changes === 0) {
      // Alguna carrera extrema: otro proceso tomó la sesión en microsegundos
      return res.redirect('/login.html?error=sesion_activa');
    }

    // 4) Completar sesión de app
    req.session.usuario = user.username;
    log('login OK (reemplazo + claim) para', user.username, 'sid:', req.sessionID);
    return res.redirect('/inicio.html');
  } catch (e) {
    console.error(e);
    return res.redirect('/login.html?error=interno');
  }
});

// ====== Middleware: sesión única ======
async function requiereSesionUnica(req, res, next) {
  try {
    if (!req.session?.usuario) return res.redirect('/login.html');

    const row = db.prepare('SELECT session_id FROM users WHERE username = ?').get(req.session.usuario);
    if (!row) return res.redirect('/login.html');

    if (!row.session_id) {
      req.session.destroy(() => res.redirect('/login.html?error=sesion_invalida'));
      return;
    }

    if (row.session_id !== req.sessionID) {
      req.session.destroy(() => res.redirect('/login.html?error=conectado_en_otra_maquina'));
      return;
    }

    const sess = await storeGet(row.session_id);
    if (!sess) {
      db.prepare('UPDATE users SET session_id = NULL WHERE username = ?').run(req.session.usuario);
      req.session.destroy(() => res.redirect('/login.html?error=sesion_expirada'));
      return;
    }

    next();
  } catch (e) {
    console.error(e);
    res.redirect('/login.html?error=interno');
  }
}

// ====== Rutas protegidas ======
app.get('/inicio', requiereSesionUnica, (req, res) => {
  const inicioFile = path.join(PUBLIC_DIR, 'inicio.html');
  if (fs.existsSync(inicioFile)) return res.sendFile(inicioFile);
  res.type('html').send(`<!doctype html><html><head><meta charset="utf-8"><title>Inicio</title></head>
  <body><h1>Inicio</h1><p>Usuario: ${req.session.usuario}</p>
  <form method="POST" action="/logout"><button>Salir</button></form>
  </body></html>`);
});

app.get('/api/datos', requiereSesionUnica, (req, res) => {
  res.json({ ok: true, usuario: req.session.usuario, sid: req.sessionID });
});

app.get('/verificar-sesion', (req, res) => {
  res.json({ activo: !!req.session?.usuario });
});

// ====== Logout ======
app.post('/logout', (req, res) => {
  const usuario = req.session?.usuario;
  const sid = req.sessionID;

  req.session.destroy(async () => {
    if (usuario) {
      const row = db.prepare('SELECT session_id FROM users WHERE username = ?').get(usuario);
      if (row?.session_id === sid) {
        db.prepare('UPDATE users SET session_id = NULL WHERE username = ?').run(usuario);
      }
    }
    res.redirect('/login.html?msg=logout');
  });
});

// ====== Admin: forzar logout (opcional) ======
app.post('/admin/forzar-logout', async (req, res) => {
  const { username } = req.body;
  const row = db.prepare('SELECT session_id FROM users WHERE username = ?').get(username);
  if (row?.session_id) {
    await storeDestroy(row.session_id).catch(() => {});
    db.prepare('UPDATE users SET session_id = NULL WHERE username = ?').run(username);
  }
  res.json({ ok: true });
});

// ====== Arranque ======
const PORT = process.env.PORT || 8080;

// ====== API: Forecast (PROXY) ======
app.get('/api/forecast', async (req, res) => {
  try {
    const lat = req.query.lat || process.env.DEFAULT_LAT || "40.4168";
    const lon = req.query.lon || process.env.DEFAULT_LON || "-3.7038";
    const apiKey = process.env.WEATHER_API_KEY;
    if (!apiKey) {
      return sendJson(res, 500, { error: "Falta WEATHER_API_KEY" });
    }

    const url = new URL("https://api.weather.com/v3/wx/forecast/daily/5day");
    url.searchParams.set("geocode", `${lat},${lon}`);
    url.searchParams.set("format", "json");
    url.searchParams.set("language", "es-ES");
    url.searchParams.set("units", "m");
    url.searchParams.set("apiKey", apiKey);

    const { ok, status, text, isJson } = await fetchAsText(url.toString(), { method: "GET" });

    if (!ok) {
      let body = text;
      try { if (isJson) body = JSON.parse(text); } catch {}
      return sendJson(res, status, { error: "Weather API error", status, body });
    }

    if (!text) return sendJson(res, 204, null);

    let data = text;
    if (isJson) {
      try { data = JSON.parse(text); } catch (e) {
        return sendJson(res, 502, { error: "Respuesta JSON inválida del proveedor", detail: String(e), fragment: text.slice(0, 200) });
      }
    }
    return sendJson(res, 200, data);
  } catch (err) {
    console.error(err);
    return sendJson(res, 500, { error: "Fallo interno", detail: String(err) });
  }
});


app.listen(PORT, () => console.log(`🚀 http://0.0.0.0:${PORT} — reemplazo automático de sesión activado`));









