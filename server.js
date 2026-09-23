const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const fs = require("fs");
const path = require("path");

const app = express();

/* =========================================================
   BASIC CONFIGURATION
========================================================= */

const PORT = process.env.PORT || 3000;

const SESSION_SECRET =
  process.env.SESSION_SECRET || "CHANGE_THIS_BEFORE_DEPLOYMENT";

const DATA_DIR = path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "demo-db.json");

fs.mkdirSync(DATA_DIR, { recursive: true });

/* =========================================================
   DATABASE
========================================================= */

function loadDb() {
  if (!fs.existsSync(DB_FILE)) {
    return {
      users: [],
      transactions: [],
      audit: []
    };
  }

  try {
    return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
  } catch {
    return {
      users: [],
      transactions: [],
      audit: []
    };
  }
}

function saveDb(db) {
  fs.writeFileSync(
    DB_FILE,
    JSON.stringify(db, null, 2)
  );
}

const db = loadDb();

/* =========================================================
   AUDIT LOG
========================================================= */

function addAudit(action, actor, detail) {
  db.audit.unshift({
    id: Date.now(),
    action,
    actor,
    detail,
    at: new Date().toISOString()
  });

  db.audit = db.audit.slice(0, 500);

  saveDb(db);
}

/* =========================================================
   ADMIN SEED
========================================================= */

async function seedAdmin() {
  const email = (
    process.env.ADMIN_EMAIL ||
    "admin@virexa.local"
  ).toLowerCase();

  if (!db.users.find((u) => u.email === email)) {
    const password =
      process.env.ADMIN_PASSWORD ||
      "ChangeMe-Admin-123!";

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

/* =========================================================
   RENDER / PROXY CONFIGURATION
========================================================= */

app.set("trust proxy", 1);

/* =========================================================
   SECURITY + BODY PARSING
========================================================= */

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(express.json({ limit: "100kb" }));

app.use(
  express.urlencoded({
    extended: false
  })
);

/* =========================================================
   CORS
========================================================= */

app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (origin) {
    res.header(
      "Access-Control-Allow-Origin",
      origin
    );

    res.header(
      "Access-Control-Allow-Credentials",
      "true"
    );

    res.header(
      "Vary",
      "Origin"
    );
  }

  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept"
  );

  res.header(
    "Access-Control-Allow-Methods",
    "GET,POST,PATCH,PUT,DELETE,OPTIONS"
  );

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

/* =========================================================
   SESSION
========================================================= */

app.use(
  session({
    secret: SESSION_SECRET,

    resave: false,

    saveUninitialized: false,

    cookie: {
      httpOnly: true,

      secure: process.env.NODE_ENV === "production",

      sameSite:
        process.env.NODE_ENV === "production"
          ? "none"
          : "lax",

      maxAge: 24 * 60 * 60 * 1000
    }
  })
);

/* =========================================================
   GENERAL RATE LIMIT
========================================================= */

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 300,
    standardHeaders: true,
    legacyHeaders: false
  })
);

/* =========================================================
   HEALTH CHECK
   IMPORTANT: KEEP THIS BEFORE STATIC / SPA FALLBACK
========================================================= */

app.get("/api/health", (req, res) => {
  res.status(200).json({
    ok: true,
    service: "Virexa Markets Backend",
    environment:
      process.env.NODE_ENV || "development",
    timestamp: new Date().toISOString()
  });
});

/* =========================================================
   AUTH HELPERS
========================================================= */

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  message: {
    error:
      "Too many authentication attempts. Please try again later."
  }
});

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      error: "Authentication required."
    });
  }

  next();
}

function currentUser(req) {
  return db.users.find(
    (u) => u.id === req.session.userId
  );
}

function requireAdmin(req, res, next) {
  const user = currentUser(req);

  if (!user || user.role !== "admin") {
    return