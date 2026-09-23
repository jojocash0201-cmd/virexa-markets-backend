const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const fs = require("fs");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;
const SESSION_SECRET =
  process.env.SESSION_SECRET || "CHANGE_THIS_BEFORE_DEPLOYMENT";

const DATA_DIR = path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "demo-db.json");

fs.mkdirSync(DATA_DIR, { recursive: true });

/* =========================
   DATABASE
========================= */

function loadDb() {
  if (!fs.existsSync(DB_FILE)) {
    return {
      users: [],
      transactions: [],
      audit: []
    };
  }

  try {
    return JSON.parse(
      fs.readFileSync(DB_FILE, "utf8")
    );
  } catch (error) {
    return {
      users: [],
      transactions: [],
      audit: []
    };
  }
}

function saveDb(database) {
  fs.writeFileSync(
    DB_FILE,
    JSON.stringify(database, null, 2)
  );
}

const db = loadDb();

/* =========================
   AUDIT
========================= */

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

/* =========================
   ADMIN
========================= */

async function seedAdmin() {
  const email = (
    process.env.ADMIN_EMAIL ||
    "admin@virexa.local"
  ).toLowerCase();

  if (!db.users.find((user) => user.email === email)) {
    const password =
      process.env.ADMIN_PASSWORD ||
      "ChangeMe-Admin-123!";

    db.users.push({
      id: "ADM-" + Date.now(),
      name: "Virexa Administrator",
      email: email,
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

/* =========================
   RENDER
========================= */

app.set("trust proxy", 1);

/* =========================
   MIDDLEWARE
========================= */

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(
  express.json({
    limit: "100kb"
  })
);

app.use(
  express.urlencoded({
    extended: false
  })
);

/* =========================
   CORS
========================= */

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

    res.header("Vary", "Origin");
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

/* =========================
   SESSION
========================= */

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,

    cookie: {
      httpOnly: true,
      secure:
        process.env.NODE_ENV === "production",
      sameSite:
        process.env.NODE_ENV === "production"
          ? "none"
          : "lax",
      maxAge: 24 * 60 * 60 * 1000
    }
  })
);

/* =========================
   RATE LIMIT
========================= */

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 300,
    standardHeaders: true,
    legacyHeaders: false
  })
);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  message: {
    error:
      "Too many authentication attempts. Please try again later."
  }
});

/* =========================
   HEALTH CHECK
========================= */

app.get("/api/health", (req, res) => {
  res.status(200).json({
    ok: true,
    service: "Virexa Markets Backend",
    environment:
      process.env.NODE_ENV || "development",
    timestamp: new Date().toISOString()
  });
});

/* =========================
   AUTH HELPERS
========================= */

function currentUser(req) {
  return db.users.find(
    (user) => user.id === req.session.userId
  );
}

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      error: "Authentication required."
    });
  }

  next();
}

function requireAdmin(req, res, next) {
  const user = currentUser(req);

  if (!user || user.role !== "admin") {
    return res.status(403).json({
      error: "Administrator access required."
    });
  }

  next();
}

/* =========================
   REGISTER
========================= */

app.post(
  "/api/register",
  authLimiter,
  async (req, res) => {
    const name = String(
      req.body.name || ""
    ).trim();

    const email = String(
      req.body.email || ""
    )
      .trim()
      .toLowerCase();

    const password = String(
      req.body.password || ""
    );

    if (
      name.length < 2 ||
      !email.includes("@") ||
      password.length < 10
    ) {
      return res.status(400).json({
        error:
          "Use a valid name, email and password of at least 10 characters."
      });
    }

    if (
      db.users.some(
        (user) => user.email === email
      )
    ) {
      return res.status(409).json({
        error:
          "An account with that email already exists."
      });
    }

    const user = {
      id: "USR-" + Date.now(),
      name: name,
      email: email,
      passwordHash:
        await bcrypt.hash(password, 12),
      role: "client",
      kyc: "pending",
      balance: 0,
      equity: 0,
      createdAt: new Date().toISOString()
    };

    db.users.push(user);
    saveDb(db);

    addAudit(
      "client_registered",
      email,
      "New client account created."
    );

    req.session.userId = user.id;

    req.session.save((error) => {
      if (error) {
        return res.status(500).json({
          error:
            "Account created, but the session could not be saved."
        });
      }

      res.json({
        ok: true,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
          kyc: user.kyc
        }
      });
    });
  }
);

/* =========================
   LOGIN
========================= */

app.post(
  "/api/login",
  authLimiter,
  async (req, res) => {
    const email = String(
      req.body.email || ""
    )
      .trim()
      .toLowerCase();

    const password = String(
      req.body.password || ""
    );

    const user = db.users.find(
      (item) => item.email === email
    );

    if (
      !user ||
      !(await bcrypt.compare(
        password,
        user.passwordHash
      ))
    ) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    req.session.regenerate((error) => {
      if (error) {
        return res.status(500).json({
          error: "Could not create session."
        });
      }

      req.session.userId = user.id;

      addAudit(
        "login",
        email,
        user.role === "admin"
          ? "Administrator login."
          : "Client login."
      );

      req.session.save((saveError) => {
        if (saveError) {
          return res.status(500).json({
            error:
              "Login succeeded, but the session could not be saved."
          });
        }

        res.json({
          ok: true,
          user: {
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role,
            kyc: user.kyc
          }
        });
      });
    });
  }
);

/* =========================
   LOGOUT
========================= */

app.post(
  "/api/logout",
  (req, res) => {
    const email =
      currentUser(req)?.email || "unknown";

    req.session.destroy(() => {
      addAudit(
        "logout",
        email,
        "Session ended."
      );

      res.json({
        ok: true
      });
    });
  }
);

/* =========================
   CURRENT USER
========================= */

app.get(
  "/api/me",
  requireAuth,
  (req, res) => {
    const user = currentUser(req);

    if (!user) {
      return res.status(401).json({
        error:
          "User session is no longer valid."
      });
    }

    res.json({
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      kyc: user.kyc,
      balance: user.balance,
      equity: user.equity
    });
  }
);

/* =========================
   TRANSACTIONS
========================= */

app.get(
  "/api/transactions",
  requireAuth,
  (req, res) => {
    const user = currentUser(req);

    if (!user) {
      return res.status(401).json({
        error:
          "User session is no longer valid."
      });
    }

    res.json(
      db.transactions.filter(
        (transaction) =>
          transaction.userId === user.id
      )
    );
  }
);

/* =========================
   ADMIN STATS
========================= */

app.get(
  "/api/admin/stats",
  requireAdmin,
  (req, res) => {
    const clients = db.users.filter(
      (user) => user.role === "client"
    );

    res.json({
      clients: clients.length,
      pendingKyc: clients.filter(
        (user) => user.kyc === "pending"
      ).length,
      approvedKyc: clients.filter(
        (user) => user.kyc === "approved"
      ).length,
      auditEvents: db.audit.length,
      liveTrading: false,
      deposits: false,
      withdrawals: false,
      custody: false
    });
  }
);

/* =========================
   ADMIN USERS
========================= */

app.get(
  "/api/admin/users",
  requireAdmin,
  (req, res) => {
    const clients = db.users
      .filter(
        (user) => user.role === "client"
      )
      .map((user) => ({
        id: user.id,
        name: user.name,
        email: user.email,
        kyc: user.kyc,
        balance: user.balance,
        equity: user.equity,
        createdAt: user.createdAt
      }));

    res.json(clients);
  }
);

/* =========================
   ADMIN KYC
========================= */

app.patch(
  "/api/admin/users/:id/kyc",
  requireAdmin,
  (req, res) => {
    const status = String(
      req.body.status || ""
    );

    if (
      ![
        "pending",
        "approved",
        "rejected"
      ].includes(status)
    ) {
      return res.status(400).json({
        error: "Invalid KYC status."
      });
    }

    const user = db.users.find(
      (item) =>
        item.id === req.params.id &&
        item.role === "client"
    );

    if (!user) {
      return res.status(404).json({
        error: "Client not found."
      });
    }

    user.kyc = status;

    saveDb(db);

    addAudit(
      "kyc_status_changed",
      currentUser(req).email,
      `${user.email} => ${status}`
    );

    res.json({
      ok: true
    });
  }
);

/* =========================
   ADMIN AUDIT
========================= */

app.get(
  "/api/admin/audit",
  requireAdmin,
  (req, res) => {
    res.json(db.audit);
  }
);

/* =========================
   DISABLED FINANCIAL ROUTES
========================= */

app.post(
  "/api/deposit",
  requireAuth,
  (req, res) => {
    res.status(403).json({
      error:
        "Deposits are disabled in this development environment."
    });
  }
);

app.post(
  "/api/withdraw",
  requireAuth,
  (req, res) => {
    res.status(403).json({
      error:
        "Withdrawals are disabled in this development environment."
    });
  }
);

app.post(
  "/api/order",
  requireAuth,
  (req, res) => {
    res.status(403).json({
      error:
        "Live trading is disabled in this development environment."
    });
  }
);

/* =========================
   STATIC FRONTEND
========================= */

app.use(
  express.static(
    path.join(__dirname, "public")
  )
);

/* =========================
   UNKNOWN API ROUTES
========================= */

app.use(
  "/api",
  (req, res) => {
    res.status(404).json({
      error: "API endpoint not found."
    });
  }
);

/* =========================
   FRONTEND FALLBACK
========================= */

app.get(
  "/{*splat}",
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        "public",
        "index.html"
      )
    );
  }
);

/* =========================
   START SERVER
========================= */

app.listen(
  PORT,
  () => {
    console.log(
      `Virexa Markets V6 listening on ${PORT}`
    );
  }
);