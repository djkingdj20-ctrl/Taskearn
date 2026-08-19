const express = require("express");
const session = require("express-session");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const { promisify } = require("util");

const scryptAsync = promisify(crypto.scrypt);
const app = express();

/* =====================================================
   BASIC CONFIG
===================================================== */

const IS_PRODUCTION = process.env.NODE_ENV === "production";
app.set("trust proxy", 1);

/* =====================================================
   SECURITY CONFIG
===================================================== */

const SESSION_SECRET = process.env.SESSION_SECRET;

if (IS_PRODUCTION && !SESSION_SECRET) {
  console.error("CRITICAL ERROR: SESSION_SECRET environment variable is required in production.");
  process.exit(1);
}

const FINAL_SESSION_SECRET = SESSION_SECRET || crypto.randomBytes(48).toString("hex");

/* =====================================================
   BODY LIMITS
===================================================== */

app.use(express.json({ limit: "50kb" }));
app.use(express.urlencoded({ extended: false, limit: "50kb" }));

/* =====================================================
   SECURITY HEADERS
===================================================== */

app.disable("x-powered-by");

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  
  // Content Security Policy
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
  );

  if (IS_PRODUCTION) {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
  }

  next();
});

/* =====================================================
   DATABASE DIRECTORY & FILE
===================================================== */

const DATA_DIR = path.join(__dirname, "data");
const DATA_FILE = path.join(DATA_DIR, "database.json");

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

/* =====================================================
   ASYNC PASSWORD HASHING (SCRYPT)
===================================================== */

const PASSWORD_KEY_LENGTH = 64;
const SCRYPT_OPTIONS = {
  N: 16384,
  r: 8,
  p: 1,
  maxmem: 32 * 1024 * 1024
};

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const derivedKey = await scryptAsync(password, salt, PASSWORD_KEY_LENGTH, SCRYPT_OPTIONS);
  return `scrypt:${salt}:${derivedKey.toString("hex")}`;
}

function isHashedPassword(password) {
  return typeof password === "string" && password.startsWith("scrypt:");
}

async function verifyPassword(password, storedPassword) {
  try {
    if (!isHashedPassword(storedPassword)) return false;

    const parts = storedPassword.split(":");
    if (parts.length !== 3) return false;

    const salt = parts[1];
    const storedHash = parts[2];

    if (!/^[a-f0-9]{32}$/i.test(salt) || !/^[a-f0-9]{128}$/i.test(storedHash)) {
      return false;
    }

    const calculatedHash = await scryptAsync(password, salt, PASSWORD_KEY_LENGTH, SCRYPT_OPTIONS);
    const storedBuffer = Buffer.from(storedHash, "hex");

    if (calculatedHash.length !== storedBuffer.length) {
      return false;
    }

    return crypto.timingSafeEqual(calculatedHash, storedBuffer);
  } catch (error) {
    console.error("Password verification error:", error.message);
    return false;
  }
}

/* =====================================================
   DEFAULT DATABASE & LOAD
===================================================== */

const defaultDatabase = {
  users: [],
  tasks: [
    {
      id: 1,
      title: "Welcome Task",
      description: "Complete the basic TaskEarn welcome activity and submit it for review.",
      type: "Welcome",
      reward: 5,
      active: true,
      createdAt: new Date().toISOString()
    },
    {
      id: 2,
      title: "Website Feedback",
      description: "Review the website and provide useful feedback about your experience.",
      type: "Feedback",
      reward: 10,
      active: true,
      createdAt: new Date().toISOString()
    }
  ],
  submissions: [],
  withdrawals: []
};

function loadDatabase() {
  try {
    if (!fs.existsSync(DATA_FILE)) {
      const initial = JSON.parse(JSON.stringify(defaultDatabase));
      fs.writeFileSync(DATA_FILE, JSON.stringify(initial, null, 2), { encoding: "utf8", flag: "wx" });
      return initial;
    }

    const raw = fs.readFileSync(DATA_FILE, "utf8");
    const data = JSON.parse(raw);

    return {
      users: Array.isArray(data.users) ? data.users : [],
      tasks: Array.isArray(data.tasks) ? data.tasks : [],
      submissions: Array.isArray(data.submissions) ? data.submissions : [],
      withdrawals: Array.isArray(data.withdrawals) ? data.withdrawals : []
    };
  } catch (error) {
    console.error("Database load error:", error);
    process.exit(1);
  }
}

let db = loadDatabase();

/* =====================================================
   DATABASE SAVE (SAFE QUEUE)
===================================================== */

let databaseWriteQueue = Promise.resolve();

function saveDatabase() {
  databaseWriteQueue = databaseWriteQueue.then(async () => {
    const tempFile = `${DATA_FILE}.${process.pid}.${Date.now()}.tmp`;
    await fs.promises.writeFile(tempFile, JSON.stringify(db, null, 2), "utf8");
    await fs.promises.rename(tempFile, DATA_FILE);
  });

  return databaseWriteQueue;
}

function nextId(array) {
  if (!array.length) return 1;
  return Math.max(...array.map(item => Number(item.id) || 0)) + 1;
}

/* =====================================================
   ADMIN INITIALIZATION
===================================================== */

async function ensureAdminAccount() {
  const adminEmail = process.env.ADMIN_EMAIL;
  const adminPassword = process.env.ADMIN_PASSWORD;

  if (!adminEmail || !adminPassword) {
    if (IS_PRODUCTION) {
      console.warn("WARNING: ADMIN_EMAIL and ADMIN_PASSWORD are not configured.");
    }
    return;
  }

  const normalizedEmail = String(adminEmail).trim().toLowerCase();
  let admin = db.users.find(user => user.role === "admin");

  if (!admin) {
    admin = {
      id: nextId(db.users),
      name: "TaskEarn Admin",
      email: normalizedEmail,
      password: await hashPassword(String(adminPassword)),
      role: "admin",
      balance: 0,
      createdAt: new Date().toISOString()
    };

    db.users.push(admin);
    await saveDatabase();
    console.log("Admin account created.");
    return;
  }

  if (admin.email !== normalizedEmail) {
    admin.email = normalizedEmail;
    await saveDatabase();
  }
}

ensureAdminAccount().catch(err => console.error("Admin init error:", err));

/* =====================================================
   SESSION MANAGEMENT
===================================================== */

app.use(
  session({
    name: "taskearn.sid",
    secret: FINAL_SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      httpOnly: true,
      secure: IS_PRODUCTION,
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24 * 7
    }
  })
);

/* =====================================================
   STATIC FILES
===================================================== */

app.use(
  express.static(path.join(__dirname, "public"), {
    index: "index.html",
    dotfiles: "deny",
    maxAge: IS_PRODUCTION ? "1d" : 0
  })
);

/* =====================================================
   HELPERS & VALIDATORS
===================================================== */

function getCurrentUser(req) {
  if (!req.session || !req.session.userId) return null;
  return db.users.find(user => user.id === req.session.userId) || null;
}

function safeUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    balance: Number(user.balance || 0),
    createdAt: user.createdAt
  };
}

function cleanText(value, maxLength = 500) {
  if (typeof value !== "string") return "";
  return value.normalize("NFKC").trim().slice(0, maxLength);
}

function validEmail(email) {
  if (typeof email !== "string" || email.length < 5 || email.length > 150) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validPassword(password) {
  return typeof password === "string" && password.length >= 8 && password.length <= 200;
}

/* =====================================================
   ORIGIN CHECK (CSRF MITIGATION)
===================================================== */

function checkOrigin(req, res, next) {
  const method = req.method.toUpperCase();
  const isProtected = ["POST", "PUT", "PATCH", "DELETE"].includes(method);

  if (!isProtected || !req.path.startsWith("/api/")) {
    return next();
  }

  const origin = req.get("origin");
  const host = req.get("host");

  if (!origin) return next();

  try {
    const originUrl = new URL(origin);
    if (originUrl.host !== host) {
      return res.status(403).json({ error: "Request origin is not allowed." });
    }
  } catch {
    return res.status(403).json({ error: "Invalid request origin." });
  }

  next();
}

app.use(checkOrigin);

/* =====================================================
   AUTH MIDDLEWARE
===================================================== */

function requireLogin(req, res, next) {
  const user = getCurrentUser(req);
  if (!user) return res.status(401).json({ error: "Please login first." });
  req.user = user;
  next();
}

function requireUser(req, res, next) {
  const user = getCurrentUser(req);
  if (!user) return res.status(401).json({ error: "Please login first." });
  if (user.role !== "user") return res.status(403).json({ error: "User account required." });
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  const user = getCurrentUser(req);
  if (!user) return res.status(401).json({ error: "Please login first." });
  if (user.role !== "admin") return res.status(403).json({ error: "Admin access required." });
  req.user = user;
  next();
}

/* =====================================================
   RATE LIMITERS WITH AUTO-CLEANUP
===================================================== */

const loginAttempts = new Map();
const apiRateMap = new Map();

const MAX_LOGIN_ATTEMPTS = 8;
const LOGIN_WINDOW = 15 * 60 * 1000;

// Memory leak prevention
setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of loginAttempts.entries()) {
    if (now - record.firstAttempt > LOGIN_WINDOW) loginAttempts.delete(ip);
  }
  for (const [ip, record] of apiRateMap.entries()) {
    if (now - record.start > 60 * 1000) apiRateMap.delete(ip);
  }
}, 5 * 60 * 1000);

function getClientIp(req) {
  return req.ip || "unknown";
}

function checkLoginRateLimit(req) {
  const ip = getClientIp(req);
  const now = Date.now();
  const record = loginAttempts.get(ip);

  if (!record) return true;
  if (now - record.firstAttempt > LOGIN_WINDOW) {
    loginAttempts.delete(ip);
    return true;
  }

  return record.count < MAX_LOGIN_ATTEMPTS;
}

function recordFailedLogin(req) {
  const ip = getClientIp(req);
  const now = Date.now();
  let record = loginAttempts.get(ip);

  if (!record || now - record.firstAttempt > LOGIN_WINDOW) {
    record = { count: 0, firstAttempt: now };
  }

  record.count++;
  loginAttempts.set(ip, record);
}

function clearLoginAttempts(req) {
  loginAttempts.delete(getClientIp(req));
}

function generalApiRateLimit(req, res, next) {
  if (!req.path.startsWith("/api/")) return next();

  const ip = getClientIp(req);
  const now = Date.now();
  let record = apiRateMap.get(ip);

  if (!record || now - record.start > 60 * 1000) {
    record = { start: now, count: 0 };
  }

  record.count++;
  apiRateMap.set(ip, record);

  if (record.count > 120) {
    return res.status(429).json({ error: "Too many requests. Please try again later." });
  }

  next();
}

app.use(generalApiRateLimit);

/* =====================================================
   ROUTES
===================================================== */

app.get("/health", (req, res) => {
  res.json({ success: true, message: "TaskEarn server is running.", time: new Date().toISOString() });
});

app.get("/api/me", (req, res) => {
  res.json(safeUser(getCurrentUser(req)));
});

// REGISTER
app.post("/api/register", async (req, res) => {
  try {
    const name = cleanText(req.body.name, 80);
    const email = cleanText(req.body.email, 150).toLowerCase();
    const password = String(req.body.password || "");

    if (!name || !email || !password) {
      return res.status(400).json({ error: "Please complete all fields." });
    }
    if (name.length < 2) {
      return res.status(400).json({ error: "Please enter a valid name." });
    }
    if (!validEmail(email)) {
      return res.status(400).json({ error: "Please enter a valid email address." });
    }
    if (!validPassword(password)) {
      return res.status(400).json({ error: "Password must contain 8 to 200 characters." });
    }

    if (db.users.some(user => user.email === email)) {
      return res.status(400).json({ error: "An account with this email already exists." });
    }

    const hashedPassword = await hashPassword(password);
    const user = {
      id: nextId(db.users),
      name,
      email,
      password: hashedPassword,
      role: "user",
      balance: 0,
      createdAt: new Date().toISOString()
    };

    db.users.push(user);
    await saveDatabase();

    req.session.regenerate(err => {
      if (err) return res.status(500).json({ error: "Session creation failed." });
      req.session.userId = user.id;
      req.session.save(() => res.json({ success: true, user: safeUser(user) }));
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ error: "Registration failed." });
  }
});

// LOGIN
app.post("/api/login", async (req, res) => {
  try {
    if (!checkLoginRateLimit(req)) {
      return res.status(429).json({ error: "Too many login attempts. Please try again later." });
    }

    const email = cleanText(req.body.email, 150).toLowerCase();
    const password = String(req.body.password || "");

    if (!email || !password) {
      recordFailedLogin(req);
      return res.status(400).json({ error: "Please enter email and password." });
    }

    const user = db.users.find(item => item.email === email);
    if (!user) {
      recordFailedLogin(req);
      return res.status(401).json({ error: "Invalid email or password." });
    }

    let correct = false;

    if (isHashedPassword(user.password)) {
      correct = await verifyPassword(password, user.password);
    } else if (typeof user.password === "string" && user.password === password) {
      correct = true;
      user.password = await hashPassword(password);
      await saveDatabase();
    }

    if (!correct) {
      recordFailedLogin(req);
      return res.status(401).json({ error: "Invalid email or password." });
    }

    clearLoginAttempts(req);

    req.session.regenerate(err => {
      if (err) return res.status(500).json({ error: "Login session creation failed." });
      req.session.userId = user.id;
      req.session.save(() => res.json({ success: true, user: safeUser(user) }));
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Login failed." });
  }
});

// LOGOUT
app.post("/api/logout", (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: "Logout failed." });
    res.clearCookie("taskearn.sid");
    res.json({ success: true, message: "Logged out successfully." });
  });
});

// TASKS & SUBMISSIONS
app.get("/api/tasks", requireUser, (req, res) => {
  const tasks = db.tasks.filter(task => task.active).map(t => ({ ...t, reward: Number(t.reward) }));
  res.json(tasks);
});

app.post("/api/tasks/:id/submit", requireUser, async (req, res) => {
  try {
    const taskId = Number(req.params.id);
    if (!Number.isSafeInteger(taskId)) return res.status(400).json({ error: "Invalid task ID." });

    const task = db.tasks.find(item => item.id === taskId && item.active);
    if (!task) return res.status(404).json({ error: "Task is not available." });

    const existing = db.submissions.find(s => s.userId === req.user.id && s.taskId === task.id && ["pending", "approved"].includes(s.status));
    if (existing) {
      return res.status(400).json({ error: "Task already submitted or completed." });
    }

    const submission = {
      id: nextId(db.submissions),
      userId: req.user.id,
      taskId: task.id,
      taskTitle: task.title,
      reward: Number(task.reward),
      status: "pending",
      submittedAt: new Date().toISOString()
    };

    db.submissions.push(submission);
    await saveDatabase();

    res.json({ success: true, message: "Task submitted for review." });
  } catch (error) {
    res.status(500).json({ error: "Task submission failed." });
  }
});

// WALLET & WITHDRAWAL
app.post("/api/withdraw", requireUser, async (req, res) => {
  try {
    const amount = Number(req.body.amount);
    const method = cleanText(req.body.method, 100);

    if (!Number.isSafeInteger(amount) || amount < 100 || amount > 100000 || !method) {
      return res.status(400).json({ error: "Invalid withdrawal parameters." });
    }

    const user = db.users.find(item => item.id === req.user.id);
    if (!user || user.balance < amount) {
      return res.status(400).json({ error: "Insufficient balance." });
    }

    if (db.withdrawals.some(w => w.userId === user.id && w.status === "pending")) {
      return res.status(400).json({ error: "Pending withdrawal request already exists." });
    }

    user.balance -= amount;

    db.withdrawals.push({
      id: nextId(db.withdrawals),
      userId: user.id,
      name: user.name,
      amount,
      method,
      status: "pending",
      createdAt: new Date().toISOString()
    });

    await saveDatabase();
    res.json({ success: true, message: "Withdrawal request submitted." });
  } catch (error) {
    res.status(500).json({ error: "Withdrawal failed." });
  }
});

/* =====================================================
   ADMIN HANDLERS & ERROR HANDLING
===================================================== */

app.use("/api", (req, res) => res.status(404).json({ error: "API endpoint not found." }));

app.use((req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.use((err, req, res, next) => {
  console.error("Server error:", err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: "Internal server error." });
});

/* =====================================================
   SERVER START
===================================================== */

const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, "0.0.0.0", () => {
  console.log(`TaskEarn server running on port ${PORT}`);
});
