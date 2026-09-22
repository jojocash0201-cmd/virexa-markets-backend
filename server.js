const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || "CHANGE_THIS_BEFORE_DEPLOYMENT";
const DATA_DIR = path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "demo-db.json");

fs.mkdirSync(DATA_DIR, { recursive: true });

function loadDb() {
  if (!fs.existsSync(DB_FILE)) return { users: [], transactions: [], audit: [] };
  try { return JSON.parse(fs.readFileSync(DB_FILE, "utf8")); }
  catch { return { users: [], transactions: [], audit: [] }; }
}
function saveDb(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}
const db = loadDb();

function addAudit(action, actor, detail) {
  db.audit.unshift({ id: Date.now(), action, actor, detail, at: new Date().toISOString() });
  db.audit = db.audit.slice(0, 500);
  saveDb(db);
}

async function seedAdmin() {
  const email = (process.env.ADMIN_EMAIL || "admin@virexa.local").toLowerCase();
  if (!db.users.find(u => u.email === email)) {
    const password = process.env.ADMIN_PASSWORD || "ChangeMe-Admin-123!";
    db.users.push({
      id: "ADM-" + Date.now(),
      name: "Virexa Administrator",
      email,
      passwordHash: await bcrypt.hash(password, 12),
      role: "admin",
      kyc: "approved",
      balance: 0,
      equity: 0,
      createdAt: new Date().toISOString()
    });
    saveDb(db);
  }
}
seedAdmin();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: false }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: true, legacyHeaders: false }));
app.use(express.static(path.join(__dirname, "public")));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, message: { error: "Too many authentication attempts. Please try again later." } });

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "Authentication required." });
  next();
}
function currentUser(req) {
  return db.users.find(u => u.id === req.session.userId);
}
function requireAdmin(req, res, next) {
  const user = currentUser(req);
  if (!user || user.role !== "admin") return res.status(403).json({ error: "Administrator access required." });
  next();
}

app.post("/api/register", authLimiter, async (req, res) => {
  const name = String(req.body.name || "").trim();
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  if (name.length < 2 || !email.includes("@") || password.length < 10) {
    return res.status(400).json({ error: "Use a valid name, email and password of at least 10 characters." });
  }
  if (db.users.some(u => u.email === email)) return res.status(409).json({ error: "An account with that email already exists." });
  const user = {
    id: "USR-" + Date.now(),
    name, email,
    passwordHash: await bcrypt.hash(password, 12),
    role: "client",
    kyc: "pending",
    balance: 0,
    equity: 0,
    createdAt: new Date().toISOString()
  };
  db.users.push(user);
  saveDb(db);
  addAudit("client_registered", email, "New client account created.");
  req.session.userId = user.id;
  res.json({ ok: true, user: { id: user.id, name: user.name, email: user.email, role: user.role, kyc: user.kyc } });
});

app.post("/api/login", authLimiter, async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const user = db.users.find(u => u.email === email);
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ error: "Invalid email or password." });
  }
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "Could not create session." });
    req.session.userId = user.id;
    addAudit("login", email, user.role === "admin" ? "Administrator login." : "Client login.");
    res.json({ ok: true, user: { id: user.id, name: user.name, email: user.email, role: user.role, kyc: user.kyc } });
  });
});

app.post("/api/logout", (req, res) => {
  const email = currentUser(req)?.email || "unknown";
  req.session.destroy(() => {
    addAudit("logout", email, "Session ended.");
    res.json({ ok: true });
  });
});

app.get("/api/me", requireAuth, (req, res) => {
  const u = currentUser(req);
  res.json({ id: u.id, name: u.name, email: u.email, role: u.role, kyc: u.kyc, balance: u.balance, equity: u.equity });
});

app.get("/api/transactions", requireAuth, (req, res) => {
  const u = currentUser(req);
  res.json(db.transactions.filter(t => t.userId === u.id));
});

app.get("/api/admin/stats", requireAdmin, (req, res) => {
  const clients = db.users.filter(u => u.role === "client");
  res.json({
    clients: clients.length,
    pendingKyc: clients.filter(u => u.kyc === "pending").length,
    approvedKyc: clients.filter(u => u.kyc === "approved").length,
    auditEvents: db.audit.length,
    liveTrading: false,
    deposits: false,
    withdrawals: false,
    custody: false
  });
});

app.get("/api/admin/users", requireAdmin, (req, res) => {
  res.json(db.users.filter(u => u.role === "client").map(u => ({
    id: u.id, name: u.name, email: u.email, kyc: u.kyc,
    balance: u.balance, equity: u.equity, createdAt: u.createdAt
  })));
});

app.patch("/api/admin/users/:id/kyc", requireAdmin, (req, res) => {
  const status = String(req.body.status || "");
  if (!["pending", "approved", "rejected"].includes(status)) return res.status(400).json({ error: "Invalid KYC status." });
  const u = db.users.find(x => x.id === req.params.id && x.role === "client");
  if (!u) return res.status(404).json({ error: "Client not found." });
  u.kyc = status;
  saveDb(db);
  addAudit("kyc_status_changed", currentUser(req).email, `${u.email} => ${status}`);
  res.json({ ok: true });
});

app.get("/api/admin/audit", requireAdmin, (req, res) => res.json(db.audit));

app.post("/api/deposit", requireAuth, (req, res) => res.status(403).json({ error: "Deposits are disabled in this development environment." }));
app.post("/api/withdraw", requireAuth, (req, res) => res.status(403).json({ error: "Withdrawals are disabled in this development environment." }));
app.post("/api/order", requireAuth, (req, res) => res.status(403).json({ error: "Live trading is disabled in this development environment." }));

app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

app.listen(PORT, () => console.log(`Virexa Markets V6 listening on ${PORT}`));
