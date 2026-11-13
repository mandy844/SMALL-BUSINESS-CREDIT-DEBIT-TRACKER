// ============================================================
// Duka Ledger — Multi-Tenant Production API
// Node.js 20+ · Express · @libsql/client (WASM SQLite) · Sessions
// No native compilation required — works on any platform.
// ============================================================
// Setup:
//   npm install
//   # .env is auto-generated on first run if missing,
//   # or copy .env.example to .env and set SESSION_SECRET
//   node server.js
// ============================================================

require('dotenv').config();
require('express-async-errors'); // async error forwarding to Express handler

const express    = require('express');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const session    = require('express-session');
const bcrypt     = require('bcryptjs');
const { z }      = require('zod');
const morgan     = require('morgan');
const path       = require('path');
const fs         = require('fs');
const crypto     = require('crypto');
const { createClient } = require('@libsql/client');

/* ============================================================
   CONFIG
   ============================================================ */
const PORT           = parseInt(process.env.PORT || '3000', 10);
const NODE_ENV       = process.env.NODE_ENV || 'development';
const IS_PROD        = NODE_ENV === 'production';
const DB_PATH        = process.env.DB_PATH || path.join(__dirname, 'data', 'duka.db');
let   SESSION_SECRET = process.env.SESSION_SECRET;
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7; // 7 days
const BCRYPT_ROUNDS  = parseInt(process.env.BCRYPT_ROUNDS || '12', 10);

// Auto-generate SESSION_SECRET if missing (dev convenience)
if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  if (IS_PROD) {
    console.error('FATAL: SESSION_SECRET must be set in .env (at least 32 chars).');
    console.error('Generate: node -e "console.log(require(\'crypto\').randomBytes(48).toString(\'hex\'))"');
    process.exit(1);
  }
  SESSION_SECRET = crypto.randomBytes(48).toString('hex');
  console.warn('[warn] SESSION_SECRET not set — using a random one (sessions will reset on restart).');
}

// ensure data directory exists
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

/* ============================================================
   DATABASE  — @libsql/client (local SQLite, no compilation)
   ============================================================ */
const db = createClient({ url: 'file:' + DB_PATH });

async function dbExec(sql) {
  await db.executeMultiple(sql);
}

async function dbAll(sql, args = []) {
  const r = await db.execute({ sql, args });
  return r.rows;
}

async function dbGet(sql, args = []) {
  const r = await db.execute({ sql, args });
  return r.rows[0] || null;
}

async function dbRun(sql, args = []) {
  return db.execute({ sql, args });
}

// Wrap multiple operations in a batch (atomic where supported)
async function dbBatch(stmts) {
  return db.batch(stmts, 'write');
}

async function initDb() {
  // Run each statement separately for compatibility
  const stmts = [
    `CREATE TABLE IF NOT EXISTS users (
      id            TEXT PRIMARY KEY,
      username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
      shop_name     TEXT NOT NULL DEFAULT '',
      password_hash TEXT NOT NULL,
      created_at    TEXT NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS customers (
      id                 TEXT PRIMARY KEY,
      owner_id           TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name               TEXT NOT NULL,
      phone              TEXT NOT NULL DEFAULT '',
      email              TEXT NOT NULL DEFAULT '',
      credit_limit_cents INTEGER NOT NULL DEFAULT 0,
      created_at         TEXT NOT NULL,
      deleted_at         TEXT
    )`,
    `CREATE INDEX IF NOT EXISTS idx_customers_owner  ON customers(owner_id)`,
    `CREATE INDEX IF NOT EXISTS idx_customers_name   ON customers(owner_id, name)`,
    `CREATE TABLE IF NOT EXISTS credits (
      id           TEXT PRIMARY KEY,
      owner_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      customer_id  TEXT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
      item         TEXT NOT NULL,
      amount_cents INTEGER NOT NULL,
      date         TEXT NOT NULL,
      created_at   TEXT NOT NULL,
      deleted_at   TEXT
    )`,
    `CREATE INDEX IF NOT EXISTS idx_credits_owner    ON credits(owner_id)`,
    `CREATE INDEX IF NOT EXISTS idx_credits_customer ON credits(owner_id, customer_id)`,
    `CREATE INDEX IF NOT EXISTS idx_credits_date     ON credits(owner_id, date)`,
    `CREATE TABLE IF NOT EXISTS payments (
      id           TEXT PRIMARY KEY,
      owner_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      customer_id  TEXT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
      amount_cents INTEGER NOT NULL,
      date         TEXT NOT NULL,
      note         TEXT NOT NULL DEFAULT '',
      created_at   TEXT NOT NULL,
      deleted_at   TEXT
    )`,
    `CREATE INDEX IF NOT EXISTS idx_payments_owner    ON payments(owner_id)`,
    `CREATE INDEX IF NOT EXISTS idx_payments_customer ON payments(owner_id, customer_id)`,
    `CREATE INDEX IF NOT EXISTS idx_payments_date     ON payments(owner_id, date)`,
    `CREATE TABLE IF NOT EXISTS audit_log (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      owner_id   TEXT,
      action     TEXT NOT NULL,
      entity     TEXT NOT NULL,
      entity_id  TEXT,
      detail     TEXT,
      created_at TEXT NOT NULL
    )`,
    `PRAGMA journal_mode=WAL`,
    `PRAGMA foreign_keys=ON`
  ];

  for (const sql of stmts) {
    await db.execute(sql).catch(e => {
      // ignore "already exists" errors for indexes
      if (!e.message.includes('already exists')) throw e;
    });
  }
}

/* ============================================================
   HELPERS
   ============================================================ */
const uid      = (prefix) => prefix + Date.now().toString(36) + crypto.randomBytes(4).toString('hex');
const todayISO = () => {
  const tz    = process.env.SHOP_TZ || 'Africa/Nairobi';
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit'
  }).formatToParts(new Date());
  const y = parts.find(p => p.type === 'year').value;
  const m = parts.find(p => p.type === 'month').value;
  const d = parts.find(p => p.type === 'day').value;
  return `${y}-${m}-${d}`;
};

const toCents = (kes)   => Math.round(Number(kes) * 100);
const toKes   = (cents) => Math.round(Number(cents)) / 100;

async function audit(ownerId, action, entity, entityId, detail) {
  try {
    await dbRun(
      `INSERT INTO audit_log (owner_id, action, entity, entity_id, detail, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [ownerId || null, action, entity, entityId || null,
       detail ? JSON.stringify(detail) : null, new Date().toISOString()]
    );
  } catch (e) { console.error('audit failed', e.message); }
}

const fail = (res, status, message, extra) =>
  res.status(status).json({ error: message, ...(extra || {}) });

/* ============================================================
   CORE BUSINESS LOGIC  (async, tenant-scoped)
   ============================================================ */
async function computeForCustomer(ownerId, customerId) {
  const credits  = await dbAll(
    `SELECT id, date, item, amount_cents FROM credits
     WHERE owner_id = ? AND customer_id = ? AND deleted_at IS NULL
     ORDER BY date ASC, created_at ASC`,
    [ownerId, customerId]
  );
  const payments = await dbAll(
    `SELECT id, date, amount_cents, note FROM payments
     WHERE owner_id = ? AND customer_id = ? AND deleted_at IS NULL
     ORDER BY date ASC, created_at ASC`,
    [ownerId, customerId]
  );

  const rows = credits.map(c => ({
    id: c.id, date: c.date, item: c.item,
    amountCents: Number(c.amount_cents), paidCents: 0
  }));

  let totalPaidCents = 0, unappliedCents = 0;
  for (const p of payments) {
    totalPaidCents += Number(p.amount_cents);
    let remaining   = Number(p.amount_cents);
    for (const r of rows) {
      if (remaining <= 0) break;
      const due = r.amountCents - r.paidCents;
      if (due <= 0) continue;
      const use = Math.min(due, remaining);
      r.paidCents += use; remaining -= use;
    }
    if (remaining > 0) unappliedCents += remaining;
  }

  const totalCreditCents    = rows.reduce((s, r) => s + r.amountCents, 0);
  const totalAllocatedCents = rows.reduce((s, r) => s + r.paidCents,   0);
  const outstandingCents    = totalCreditCents - totalAllocatedCents;

  return {
    credits: rows.map(r => ({
      id: r.id, date: r.date, item: r.item,
      amount:  toKes(r.amountCents),
      paid:    toKes(r.paidCents),
      balance: toKes(r.amountCents - r.paidCents)
    })),
    payments: payments.map(p => ({
      id: p.id, date: p.date, amount: toKes(Number(p.amount_cents)), note: p.note
    })),
    totalCredit: toKes(totalCreditCents),
    totalPaid:   toKes(totalPaidCents),
    unapplied:   toKes(unappliedCents),
    outstanding: toKes(outstandingCents)
  };
}

function customerStatus(computed) {
  if (computed.totalCredit === 0)      return { key: 'none',    label: 'no credit' };
  if (computed.outstanding <= 0.005)   return { key: 'full',    label: 'settled' };
  if (computed.totalPaid > 0)          return { key: 'partial', label: 'partial' };
  return { key: 'unpaid', label: 'unpaid' };
}

/* ============================================================
   VALIDATION (zod)
   ============================================================ */
const dateStr     = z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'Date must be YYYY-MM-DD');
const usernameStr = z.string().trim().min(3).max(32).regex(/^[a-zA-Z0-9_.\-]+$/);
const passwordStr = z.string().min(8).max(200);

const schemas = {
  register: z.object({
    username: usernameStr,
    shopName: z.string().trim().min(1).max(100),
    password: passwordStr
  }),
  login: z.object({
    username: z.string().trim().min(1),
    password: z.string().min(1)
  }),
  customerCreate: z.object({
    name:        z.string().trim().min(1).max(100),
    phone:       z.string().trim().max(30).optional().default(''),
    email:       z.string().trim().max(120).email().or(z.literal('')).optional().default(''),
    creditLimit: z.coerce.number().min(0).max(10_000_000).optional().default(0)
  }),
  customerPatch: z.object({
    name:        z.string().trim().min(1).max(100).optional(),
    phone:       z.string().trim().max(30).optional(),
    email:       z.string().trim().max(120).email().or(z.literal('')).optional(),
    creditLimit: z.coerce.number().min(0).max(10_000_000).optional()
  }),
  creditCreate: z.object({
    customerId: z.string().min(1),
    item:       z.string().trim().min(1).max(200),
    amount:     z.coerce.number().positive().max(10_000_000),
    date:       dateStr.optional()
  }),
  paymentCreate: z.object({
    customerId:   z.string().min(1),
    amount:       z.coerce.number().positive().max(10_000_000),
    date:         dateStr.optional(),
    note:         z.string().trim().max(200).optional().default(''),
    allowOverpay: z.boolean().optional().default(false)
  })
};

function validate(schema) {
  return (req, res, next) => {
    const r = schema.safeParse(req.body);
    if (!r.success) {
      return fail(res, 400, 'Invalid input', {
        issues: r.error.issues.map(i => ({ path: i.path.join('.'), message: i.message }))
      });
    }
    req.body = r.data;
    next();
  };
}

/* ============================================================
   AUTH MIDDLEWARE
   ============================================================ */
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  return fail(res, 401, 'Not authenticated');
}
const oid = (req) => req.session.userId;

/* ============================================================
   EXPRESS APP
   ============================================================ */
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      'default-src': ["'self'"],
      'img-src':     ["'self'", 'data:'],
      'style-src':   ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      'script-src':  ["'self'", "'unsafe-inline'"],
      'font-src':    ["'self'", 'https://fonts.gstatic.com'],
      'connect-src': ["'self'"],
      'frame-ancestors': ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: false
}));

app.use(express.json({ limit: '100kb' }));
app.use(morgan(IS_PROD ? 'combined' : 'dev'));

// In-memory session store (suitable for single-process; replace with
// connect-redis or similar for multi-process production deployments)
app.use(session({
  name:              'duka.sid',
  secret:            SESSION_SECRET,
  resave:            false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure:   IS_PROD,
    maxAge:   SESSION_TTL_MS
  }
}));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 20,
  standardHeaders: 'draft-7', legacyHeaders: false,
  message: { error: 'Too many attempts, please try again later.' }
});
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 600,
  standardHeaders: 'draft-7', legacyHeaders: false,
  message: { error: 'Too many requests, please slow down.' }
});
app.use('/api', apiLimiter);
app.use('/api/auth', authLimiter);

/* ============================================================
   HEALTH
   ============================================================ */
app.get('/api/health', async (req, res) => {
  try {
    await dbGet('SELECT 1 AS ok');
    res.json({ ok: true, time: new Date().toISOString() });
  } catch (e) {
    res.status(503).json({ ok: false });
  }
});

/* ============================================================
   AUTH ROUTES
   ============================================================ */
app.post('/api/auth/register', validate(schemas.register), async (req, res) => {
  const { username, shopName, password } = req.body;
  const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  const id   = uid('u');
  try {
    await dbRun(
      `INSERT INTO users (id, username, shop_name, password_hash, created_at) VALUES (?,?,?,?,?)`,
      [id, username, shopName, hash, new Date().toISOString()]
    );
  } catch (e) {
    if (e.message && e.message.includes('UNIQUE')) return fail(res, 409, 'Username already taken');
    throw e;
  }
  await new Promise((resolve, reject) =>
    req.session.regenerate(err => err ? reject(err) : resolve())
  );
  req.session.userId   = id;
  req.session.username = username;
  req.session.shopName = shopName;
  audit(id, 'register', 'user', id, { username, shopName });
  res.status(201).json({ ok: true, username, shopName });
});

app.post('/api/auth/login', validate(schemas.login), async (req, res) => {
  const { username, password } = req.body;
  const user = await dbGet(
    'SELECT id, username, shop_name, password_hash FROM users WHERE lower(username) = lower(?)',
    [username]
  );
  const hash = user ? user.password_hash : '$2a$12$' + 'x'.repeat(53);
  const ok   = await bcrypt.compare(password, hash);
  if (!user || !ok) return fail(res, 401, 'Invalid credentials');

  await new Promise((resolve, reject) =>
    req.session.regenerate(err => err ? reject(err) : resolve())
  );
  req.session.userId   = user.id;
  req.session.username = user.username;
  req.session.shopName = user.shop_name;
  audit(user.id, 'login', 'user', user.id, null);
  res.json({ ok: true, username: user.username, shopName: user.shop_name });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('duka.sid');
    res.json({ ok: true });
  });
});

app.get('/api/auth/me', (req, res) => {
  if (!req.session || !req.session.userId) return fail(res, 401, 'Not authenticated');
  res.json({ id: req.session.userId, username: req.session.username, shopName: req.session.shopName });
});

// ---- all routes below require auth ----
app.use('/api', (req, res, next) => {
  if (req.path === '/health' || req.path.startsWith('/auth')) return next();
  return requireAuth(req, res, next);
});

/* ============================================================
   SUMMARY
   ============================================================ */
app.get('/api/summary', async (req, res) => {
  const o = oid(req);
  const customers = await dbAll(
    'SELECT id FROM customers WHERE owner_id = ? AND deleted_at IS NULL', [o]
  );
  let totalOutstandingCents = 0;
  for (const c of customers) {
    const comp = await computeForCustomer(o, c.id);
    totalOutstandingCents += Math.max(0, toCents(comp.outstanding));
  }
  const today = todayISO();
  const collectedRow = await dbGet(
    'SELECT COALESCE(SUM(amount_cents),0) AS t FROM payments WHERE owner_id = ? AND date = ? AND deleted_at IS NULL',
    [o, today]
  );
  const creditRow = await dbGet(
    'SELECT COALESCE(SUM(amount_cents),0) AS t FROM credits WHERE owner_id = ? AND date = ? AND deleted_at IS NULL',
    [o, today]
  );
  res.json({
    shopName:         req.session.shopName,
    customerCount:    customers.length,
    totalOutstanding: toKes(totalOutstandingCents),
    collectedToday:   toKes(Number(collectedRow.t)),
    creditToday:      toKes(Number(creditRow.t)),
    today
  });
});

/* ============================================================
   CUSTOMERS
   ============================================================ */
app.get('/api/customers', async (req, res) => {
  const o = oid(req);
  const q = String(req.query.q || '').trim();
  let rows;
  if (q) {
    rows = await dbAll(
      `SELECT * FROM customers WHERE owner_id = ? AND deleted_at IS NULL
       AND (lower(name) LIKE ? OR lower(phone) LIKE ?) ORDER BY name`,
      [o, '%' + q.toLowerCase() + '%', '%' + q.toLowerCase() + '%']
    );
  } else {
    rows = await dbAll(
      'SELECT * FROM customers WHERE owner_id = ? AND deleted_at IS NULL ORDER BY name', [o]
    );
  }
  const customers = await Promise.all(rows.map(async c => {
    const comp = await computeForCustomer(o, c.id);
    return {
      id: c.id, name: c.name, phone: c.phone, email: c.email,
      creditLimit: toKes(Number(c.credit_limit_cents)), createdAt: c.created_at,
      totalCredit: comp.totalCredit, totalPaid: comp.totalPaid,
      outstanding: comp.outstanding, status: customerStatus(comp),
      overLimit: toCents(comp.outstanding) > Number(c.credit_limit_cents) + 1
    };
  }));
  res.json({ customers });
});

app.get('/api/customers/:id', async (req, res) => {
  const o = oid(req);
  const c = await dbGet(
    'SELECT * FROM customers WHERE owner_id = ? AND id = ? AND deleted_at IS NULL',
    [o, req.params.id]
  );
  if (!c) return fail(res, 404, 'Customer not found');
  const comp = await computeForCustomer(o, c.id);
  res.json({
    id: c.id, name: c.name, phone: c.phone, email: c.email,
    creditLimit: toKes(Number(c.credit_limit_cents)), createdAt: c.created_at,
    totalCredit: comp.totalCredit, totalPaid: comp.totalPaid,
    outstanding: comp.outstanding, status: customerStatus(comp),
    overLimit: toCents(comp.outstanding) > Number(c.credit_limit_cents) + 1,
    credits: comp.credits, payments: comp.payments
  });
});

app.post('/api/customers', validate(schemas.customerCreate), async (req, res) => {
  const o = oid(req);
  const { name, phone, email, creditLimit } = req.body;
  const dup = await dbGet(
    'SELECT id FROM customers WHERE owner_id = ? AND deleted_at IS NULL AND lower(name) = lower(?) AND phone = ?',
    [o, name, phone]
  );
  if (dup) return fail(res, 409, 'A customer with that name and phone already exists');
  const id  = uid('c');
  const now = new Date().toISOString();
  await dbRun(
    `INSERT INTO customers (id, owner_id, name, phone, email, credit_limit_cents, created_at)
     VALUES (?,?,?,?,?,?,?)`,
    [id, o, name, phone, email, toCents(creditLimit), now]
  );
  audit(o, 'create', 'customer', id, { name });
  res.status(201).json({
    id, name, phone, email, creditLimit, createdAt: now,
    totalCredit: 0, totalPaid: 0, outstanding: 0,
    status: { key: 'none', label: 'no credit' }, overLimit: false
  });
});

app.patch('/api/customers/:id', validate(schemas.customerPatch), async (req, res) => {
  const o = oid(req);
  const c = await dbGet(
    'SELECT * FROM customers WHERE owner_id = ? AND id = ? AND deleted_at IS NULL',
    [o, req.params.id]
  );
  if (!c) return fail(res, 404, 'Customer not found');
  const name       = req.body.name        !== undefined ? req.body.name        : c.name;
  const phone      = req.body.phone       !== undefined ? req.body.phone       : c.phone;
  const email      = req.body.email       !== undefined ? req.body.email       : c.email;
  const limitCents = req.body.creditLimit !== undefined ? toCents(req.body.creditLimit) : Number(c.credit_limit_cents);
  const dup = await dbGet(
    `SELECT id FROM customers WHERE owner_id = ? AND deleted_at IS NULL AND id <> ? AND lower(name) = lower(?) AND phone = ?`,
    [o, c.id, name, phone]
  );
  if (dup) return fail(res, 409, 'Another customer already has that name and phone');
  await dbRun(
    `UPDATE customers SET name=?, phone=?, email=?, credit_limit_cents=? WHERE id=?`,
    [name, phone, email, limitCents, c.id]
  );
  audit(o, 'update', 'customer', c.id, req.body);
  res.json({ ok: true });
});

app.delete('/api/customers/:id', async (req, res) => {
  const o = oid(req);
  const c = await dbGet(
    'SELECT id FROM customers WHERE owner_id = ? AND id = ? AND deleted_at IS NULL',
    [o, req.params.id]
  );
  if (!c) return fail(res, 404, 'Customer not found');
  await dbRun('UPDATE customers SET deleted_at=? WHERE id=?', [new Date().toISOString(), c.id]);
  audit(o, 'delete', 'customer', c.id, null);
  res.json({ ok: true });
});

/* ============================================================
   CREDITS
   ============================================================ */
app.get('/api/credits', async (req, res) => {
  const o = oid(req);
  const { customerId, month } = req.query;
  let sql    = `SELECT cr.*, c.name AS customer_name FROM credits cr
                JOIN customers c ON c.id = cr.customer_id
                WHERE cr.owner_id = ? AND cr.deleted_at IS NULL AND c.deleted_at IS NULL`;
  const args = [o];
  if (customerId) { sql += ' AND cr.customer_id = ?'; args.push(customerId); }
  if (month)      { sql += " AND substr(cr.date,1,7) = ?"; args.push(month); }
  sql += ' ORDER BY cr.date DESC, cr.created_at DESC LIMIT 500';

  const rows  = await dbAll(sql, args);
  const cache = {};
  const credits = await Promise.all(rows.map(async cr => {
    if (!cache[cr.customer_id]) cache[cr.customer_id] = await computeForCustomer(o, cr.customer_id);
    const info = cache[cr.customer_id].credits.find(x => x.id === cr.id)
      || { paid: 0, balance: toKes(Number(cr.amount_cents)) };
    return {
      id: cr.id, customerId: cr.customer_id, customerName: cr.customer_name,
      item: cr.item, amount: toKes(Number(cr.amount_cents)),
      date: cr.date, paid: info.paid, balance: info.balance
    };
  }));
  res.json({ credits });
});

app.post('/api/credits', validate(schemas.creditCreate), async (req, res) => {
  const o = oid(req);
  const { customerId, item, amount, date } = req.body;
  const customer = await dbGet(
    'SELECT id FROM customers WHERE owner_id = ? AND id = ? AND deleted_at IS NULL',
    [o, customerId]
  );
  if (!customer) return fail(res, 404, 'Customer not found');
  const id   = uid('cr');
  const when = date || todayISO();
  await dbRun(
    `INSERT INTO credits (id, owner_id, customer_id, item, amount_cents, date, created_at)
     VALUES (?,?,?,?,?,?,?)`,
    [id, o, customerId, item, toCents(amount), when, new Date().toISOString()]
  );
  audit(o, 'create', 'credit', id, { customerId, amount, item });
  res.status(201).json({ id, customerId, item, amount, date: when, paid: 0, balance: amount });
});

app.delete('/api/credits/:id', async (req, res) => {
  const o = oid(req);
  const row = await dbGet(
    'SELECT id FROM credits WHERE owner_id = ? AND id = ? AND deleted_at IS NULL',
    [o, req.params.id]
  );
  if (!row) return fail(res, 404, 'Credit not found');
  await dbRun('UPDATE credits SET deleted_at=? WHERE id=?', [new Date().toISOString(), row.id]);
  audit(o, 'delete', 'credit', row.id, null);
  res.json({ ok: true });
});

/* ============================================================
   PAYMENTS
   ============================================================ */
app.get('/api/payments', async (req, res) => {
  const o = oid(req);
  const { customerId, month } = req.query;
  let sql    = `SELECT p.*, c.name AS customer_name FROM payments p
                JOIN customers c ON c.id = p.customer_id
                WHERE p.owner_id = ? AND p.deleted_at IS NULL AND c.deleted_at IS NULL`;
  const args = [o];
  if (customerId) { sql += ' AND p.customer_id = ?'; args.push(customerId); }
  if (month)      { sql += " AND substr(p.date,1,7) = ?"; args.push(month); }
  sql += ' ORDER BY p.date DESC, p.created_at DESC LIMIT 500';
  const rows = await dbAll(sql, args);
  res.json({
    payments: rows.map(p => ({
      id: p.id, customerId: p.customer_id, customerName: p.customer_name,
      amount: toKes(Number(p.amount_cents)), date: p.date, note: p.note
    }))
  });
});

app.post('/api/payments', validate(schemas.paymentCreate), async (req, res) => {
  const o = oid(req);
  const { customerId, amount, date, note, allowOverpay } = req.body;
  const customer = await dbGet(
    'SELECT id FROM customers WHERE owner_id = ? AND id = ? AND deleted_at IS NULL',
    [o, customerId]
  );
  if (!customer) return fail(res, 404, 'Customer not found');

  const id          = uid('p');
  const when        = date || todayISO();
  const amountCents = toCents(amount);

  const before = await computeForCustomer(o, customerId);
  const outstandingBeforeCents = toCents(before.outstanding);

  if (amountCents > outstandingBeforeCents + 1) {
    if (!allowOverpay) {
      return res.status(409).json({
        error: 'Payment exceeds outstanding balance',
        outstanding: before.outstanding,
        requiresConfirmation: true
      });
    }
  }

  await dbRun(
    `INSERT INTO payments (id, owner_id, customer_id, amount_cents, date, note, created_at)
     VALUES (?,?,?,?,?,?,?)`,
    [id, o, customerId, amountCents, when, note || '', new Date().toISOString()]
  );
  const overpaid = amountCents > outstandingBeforeCents + 1;
  audit(o, 'create', 'payment', id, { customerId, amount, overpaid });
  const after = await computeForCustomer(o, customerId);
  res.status(201).json({
    id, customerId, amount, date: when, note: note || '',
    outstandingAfter: after.outstanding, overpaid
  });
});

app.delete('/api/payments/:id', async (req, res) => {
  const o   = oid(req);
  const row = await dbGet(
    'SELECT id FROM payments WHERE owner_id = ? AND id = ? AND deleted_at IS NULL',
    [o, req.params.id]
  );
  if (!row) return fail(res, 404, 'Payment not found');
  await dbRun('UPDATE payments SET deleted_at=? WHERE id=?', [new Date().toISOString(), row.id]);
  audit(o, 'delete', 'payment', row.id, null);
  res.json({ ok: true });
});

/* ============================================================
   STATEMENTS
   ============================================================ */
app.get('/api/customers/:id/statement', async (req, res) => {
  const o = oid(req);
  const c = await dbGet(
    'SELECT * FROM customers WHERE owner_id = ? AND id = ? AND deleted_at IS NULL',
    [o, req.params.id]
  );
  if (!c) return fail(res, 404, 'Customer not found');
  const { from, to } = req.query;
  if (from && !/^\d{4}-\d{2}-\d{2}$/.test(from)) return fail(res, 400, 'Invalid from date');
  if (to   && !/^\d{4}-\d{2}-\d{2}$/.test(to))   return fail(res, 400, 'Invalid to date');

  const events = [];
  (await dbAll(
    `SELECT id,date,item,amount_cents FROM credits WHERE owner_id=? AND customer_id=? AND deleted_at IS NULL ORDER BY date,created_at`,
    [o, c.id]
  )).forEach(cr => events.push({ type:'credit', date:cr.date, description:cr.item, amount:Number(cr.amount_cents) }));
  (await dbAll(
    `SELECT id,date,amount_cents,note FROM payments WHERE owner_id=? AND customer_id=? AND deleted_at IS NULL ORDER BY date,created_at`,
    [o, c.id]
  )).forEach(p => events.push({ type:'payment', date:p.date, description:p.note||'Payment received', amount:-Number(p.amount_cents) }));

  let openingCents = 0;
  if (from) events.forEach(e => { if (e.date < from) openingCents += e.amount; });

  const filtered = events.filter(e => {
    if (from && e.date < from) return false;
    if (to   && e.date > to)   return false;
    return true;
  }).sort((a,b) => a.date.localeCompare(b.date));

  let running = openingCents;
  const lines = filtered.map(e => {
    running += e.amount;
    return { date:e.date, description:e.description, type:e.type,
      credit: e.type==='credit'  ? toKes(e.amount)  : 0,
      paid:   e.type==='payment' ? toKes(-e.amount) : 0,
      balance: toKes(running) };
  });

  const periodCreditCents = filtered.filter(e => e.type==='credit').reduce((s,e) => s+e.amount, 0);
  const periodPaidCents   = filtered.filter(e => e.type==='payment').reduce((s,e) => s+(-e.amount), 0);

  res.json({
    customer: { id:c.id, name:c.name, phone:c.phone, email:c.email, creditLimit:toKes(Number(c.credit_limit_cents)) },
    range: { from:from||null, to:to||null },
    openingBalance: toKes(openingCents), periodCredit: toKes(periodCreditCents),
    periodPaid: toKes(periodPaidCents),  closingBalance: toKes(running), lines
  });
});

/* ============================================================
   REPORTS
   ============================================================ */
app.get('/api/reports/daily', async (req, res) => {
  const o    = oid(req);
  const date = req.query.date || todayISO();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return fail(res, 400, 'Invalid date');

  const credits  = await dbAll(
    `SELECT cr.id,cr.item,cr.amount_cents,cr.customer_id,c.name AS customer_name
     FROM credits cr JOIN customers c ON c.id=cr.customer_id
     WHERE cr.owner_id=? AND cr.date=? AND cr.deleted_at IS NULL AND c.deleted_at IS NULL
     ORDER BY cr.created_at`,
    [o, date]
  );
  const payments = await dbAll(
    `SELECT p.id,p.amount_cents,p.note,p.customer_id,c.name AS customer_name
     FROM payments p JOIN customers c ON c.id=p.customer_id
     WHERE p.owner_id=? AND p.date=? AND p.deleted_at IS NULL AND c.deleted_at IS NULL
     ORDER BY p.created_at`,
    [o, date]
  );
  const creditTotalCents  = credits.reduce((s,x) => s+Number(x.amount_cents), 0);
  const paymentTotalCents = payments.reduce((s,x) => s+Number(x.amount_cents), 0);
  res.json({
    date,
    creditTotal:  toKes(creditTotalCents),
    paymentTotal: toKes(paymentTotalCents),
    netMovement:  toKes(paymentTotalCents - creditTotalCents),
    credits:  credits.map(c  => ({ id:c.id, customerId:c.customer_id, customerName:c.customer_name, item:c.item, amount:toKes(Number(c.amount_cents)) })),
    payments: payments.map(p => ({ id:p.id, customerId:p.customer_id, customerName:p.customer_name, amount:toKes(Number(p.amount_cents)), note:p.note }))
  });
});

app.get('/api/reports/monthly', async (req, res) => {
  const o     = oid(req);
  const month = req.query.month || todayISO().slice(0, 7);
  if (!/^\d{4}-\d{2}$/.test(month)) return fail(res, 400, 'Invalid month');

  const credits  = await dbAll(
    `SELECT customer_id, amount_cents FROM credits WHERE owner_id=? AND substr(date,1,7)=? AND deleted_at IS NULL`,
    [o, month]
  );
  const payments = await dbAll(
    `SELECT customer_id, amount_cents FROM payments WHERE owner_id=? AND substr(date,1,7)=? AND deleted_at IS NULL`,
    [o, month]
  );
  const creditTotalCents  = credits.reduce((s,x) => s+Number(x.amount_cents), 0);
  const paymentTotalCents = payments.reduce((s,x) => s+Number(x.amount_cents), 0);

  const map = {};
  credits.forEach(x  => { map[x.customer_id] = map[x.customer_id] || {credit:0,paid:0}; map[x.customer_id].credit += Number(x.amount_cents); });
  payments.forEach(x => { map[x.customer_id] = map[x.customer_id] || {credit:0,paid:0}; map[x.customer_id].paid   += Number(x.amount_cents); });

  const perCustomer = await Promise.all(Object.keys(map).map(async cid => {
    const c    = await dbGet('SELECT name FROM customers WHERE id=?', [cid]);
    const comp = await computeForCustomer(o, cid);
    return { customerId:cid, customerName: c?c.name:'(deleted)',
      creditIssued:toKes(map[cid].credit), paid:toKes(map[cid].paid),
      net:toKes(map[cid].paid-map[cid].credit), currentOutstanding:comp.outstanding };
  }));
  perCustomer.sort((a,b) => a.customerName.localeCompare(b.customerName));

  const allCustomers = await dbAll('SELECT id FROM customers WHERE owner_id=? AND deleted_at IS NULL', [o]);
  let totalOutstanding = 0;
  for (const c of allCustomers) {
    const comp = await computeForCustomer(o, c.id);
    totalOutstanding += Math.max(0, toCents(comp.outstanding));
  }
  res.json({
    month, creditTotal:toKes(creditTotalCents), paymentTotal:toKes(paymentTotalCents),
    netMovement:toKes(paymentTotalCents-creditTotalCents), totalOutstanding:toKes(totalOutstanding), perCustomer
  });
});

/* ============================================================
   CSV EXPORTS
   ============================================================ */
const csvEscape = v => { const s = String(v??''); return /[",\n]/.test(s) ? '"'+s.replace(/"/g,'""')+'"' : s; };
const toCSV = (hdr, rows) => [hdr.map(csvEscape).join(',')].concat(rows.map(r=>r.map(csvEscape).join(','))).join('\n');

app.get('/api/export/customers.csv', async (req, res) => {
  const o = oid(req);
  const rows = await dbAll('SELECT * FROM customers WHERE owner_id=? AND deleted_at IS NULL ORDER BY name', [o]);
  const data = await Promise.all(rows.map(async c => {
    const comp = await computeForCustomer(o, c.id);
    return [c.id, c.name, c.phone, c.email, toKes(Number(c.credit_limit_cents)),
      comp.totalCredit, comp.totalPaid, comp.outstanding, c.created_at];
  }));
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="customers.csv"');
  res.send(toCSV(['id','name','phone','email','credit_limit','total_credit','total_paid','outstanding','created_at'], data));
});

app.get('/api/export/credits.csv', async (req, res) => {
  const o = oid(req);
  const rows = await dbAll(
    `SELECT cr.id,cr.date,c.name,cr.item,cr.amount_cents FROM credits cr
     JOIN customers c ON c.id=cr.customer_id
     WHERE cr.owner_id=? AND cr.deleted_at IS NULL AND c.deleted_at IS NULL ORDER BY cr.date`,
    [o]
  );
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="credits.csv"');
  res.send(toCSV(['id','date','customer','item','amount'], rows.map(r=>[r.id,r.date,r.name,r.item,toKes(Number(r.amount_cents))])));
});

app.get('/api/export/payments.csv', async (req, res) => {
  const o = oid(req);
  const rows = await dbAll(
    `SELECT p.id,p.date,c.name,p.amount_cents,p.note FROM payments p
     JOIN customers c ON c.id=p.customer_id
     WHERE p.owner_id=? AND p.deleted_at IS NULL AND c.deleted_at IS NULL ORDER BY p.date`,
    [o]
  );
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="payments.csv"');
  res.send(toCSV(['id','date','customer','amount','note'], rows.map(r=>[r.id,r.date,r.name,toKes(Number(r.amount_cents)),r.note])));
});

/* ============================================================
   FRONTEND
   ============================================================ */
const publicDir = path.join(__dirname, 'public');
if (fs.existsSync(publicDir)) {
  app.use(express.static(publicDir, { index: 'index.html' }));
  app.get(/^(?!\/api).*/, (req, res) =>
    res.sendFile(path.join(publicDir, 'index.html'))
  );
}

/* ============================================================
   ERROR HANDLING
   ============================================================ */
app.use((req, res) => fail(res, 404, 'Not found'));
app.use((err, req, res, next) => {
  console.error('[error]', err.message);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'Something went wrong' });
});

process.on('SIGTERM', () => { console.log('SIGTERM — shutting down'); process.exit(0); });
process.on('SIGINT',  () => process.exit(0));
process.on('uncaughtException',  e => { console.error('[uncaught]', e); process.exit(1); });
process.on('unhandledRejection', e => console.error('[unhandledRejection]', e));

/* ============================================================
   START
   ============================================================ */
initDb().then(() => {
  app.listen(PORT, () => {
    console.log(`\n✅  Duka Ledger  →  http://localhost:${PORT}  (${NODE_ENV})`);
    console.log(`    DB: ${DB_PATH}\n`);
  });
}).catch(e => {
  console.error('Failed to initialise database:', e);
  process.exit(1);
});

module.exports = app;