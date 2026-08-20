const express = require("express");
const session = require("express-session");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");

const app = express();

app.set("trust proxy", 1);

app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true, limit: "100kb" }));

/* =====================================================
   CONFIGURATION (Environment Variables)
===================================================== */

const PORT = Number(process.env.PORT) || 10000;
const DATA_DIR = path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "database.json");

const SESSION_SECRET = process.env.SESSION_SECRET || "CHANGE_THIS_TASKEARN_SECRET_2026";
const GMAIL_USER = process.env.GMAIL_USER || "taskearn.otp@gmail.com";
const GMAIL_APP_PASSWORD = process.env.GMAIL_APP_PASSWORD || "";
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";

/* =====================================================
   DATABASE MANAGEMENT
===================================================== */

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

function defaultDatabase() {
  return {
    users: [],
    tasks: [
      { id: 1, title: "Complete a simple online task", description: "Complete instructions carefully.", type: "General", reward: 10, active: true },
      { id: 2, title: "Social Media Engagement", description: "Complete social media activity.", type: "Social", reward: 15, active: true },
      { id: 3, title: "Website Visit Task", description: "Visit required website.", type: "Website", reward: 20, active: true }
    ],
    submissions: [],
    withdrawals: [],
    otpCodes: []
  };
}

function saveDB(database) {
  const tempFile = DB_FILE + ".tmp";
  fs.writeFileSync(tempFile, JSON.stringify(database, null, 2), "utf8");
  fs.renameSync(tempFile, DB_FILE);
}

function loadDB() {
  try {
    if (!fs.existsSync(DB_FILE)) {
      const database = defaultDatabase();
      saveDB(database);
      return database;
    }
    const raw = fs.readFileSync(DB_FILE, "utf8");
    if (!raw.trim()) {
      const database = defaultDatabase();
      saveDB(database);
      return database;
    }
    const database = JSON.parse(raw);
    database.users ||= [];
    database.tasks ||= [];
    database.submissions ||= [];
    database.withdrawals ||= [];
    database.otpCodes ||= [];
    return database;
  } catch (error) {
    console.error("Database load error:", error);
    const database = defaultDatabase();
    saveDB(database);
    return database;
  }
}

let db = loadDB();

/* =====================================================
   SESSION CONFIGURATION (RENDER / PRODUCTION FIX)
===================================================== */

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 24 * 30
    }
  })
);

/* =====================================================
   HELPERS & AUTHENTICATION
===================================================== */

function cleanText(value, maxLength = 200) { return String(value ?? "").trim().slice(0, maxLength); }
function normalizeEmail(value) { return cleanText(value, 160).toLowerCase(); }
function validEmail(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); }

function publicUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    name: user.name || "",
    email: user.email || "",
    role: user.role || "Member",
    mobile: user.mobile || "",
    city: user.city || "",
    profileImage: user.profileImage || "",
    emailVerified: Boolean(user.emailVerified),
    mobileVerified: Boolean(user.mobileVerified),
    authProvider: user.authProvider || "local",
    balance: user.balance || 0,
    createdAt: user.createdAt
  };
}

function currentUser(req) {
  if (!req.session.userId) return null;
  return db.users.find(u => String(u.id) === String(req.session.userId));
}

function requireLogin(req, res, next) {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Please login first." });
  req.user = user;
  next();
}

/* =====================================================
   GOOGLE AUTH VERIFICATION
===================================================== */

async function verifyGoogleIdToken(idToken) {
  if (!GOOGLE_CLIENT_ID) throw new Error("Google Sign-In is not configured.");
  if (!idToken) throw new Error("Google auth token missing.");

  const response = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(idToken)}`);
  if (!response.ok) throw new Error("Invalid Google token.");

  const data = await response.json();
  if (data.aud !== GOOGLE_CLIENT_ID) throw new Error("Google Client ID mismatch.");
  if (data.email_verified !== "true" && data.email_verified !== true) throw new Error("Google email not verified.");

  return {
    googleId: cleanText(data.sub, 200),
    email: normalizeEmail(data.email),
    name: cleanText(data.name || data.email.split("@")[0], 80),
    picture: cleanText(data.picture || "", 1000)
  };
}

/* =====================================================
   API ROUTES
===================================================== */

app.get("/api/google-config", (req, res) => {
  return res.json({ clientId: GOOGLE_CLIENT_ID });
});

app.post("/api/auth/google", async (req, res) => {
  try {
    const google = await verifyGoogleIdToken(req.body.credential);
    let user = db.users.find(u => u.googleId && String(u.googleId) === String(google.googleId));

    if (!user) {
      user = db.users.find(u => normalizeEmail(u.email) === google.email);
    }

    if (!user) {
      user = {
        id: crypto.randomUUID(),
        name: google.name,
        email: google.email,
        passwordHash: "",
        role: "Member",
        mobile: "",
        city: "",
        profileImage: google.picture,
        emailVerified: true,
        mobileVerified: false,
        googleId: google.googleId,
        authProvider: "google",
        balance: 0,
        createdAt: new Date().toISOString()
      };
      db.users.push(user);
    } else {
      user.googleId = google.googleId;
      user.emailVerified = true;
      user.authProvider = "google";
      if (!user.profileImage) user.profileImage = google.picture;
    }

    saveDB(db);
    req.session.userId = user.id;

    return res.json({ success: true, user: publicUser(user) });
  } catch (error) {
    return res.status(401).json({ error: error.message || "Google auth failed." });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");

    const user = db.users.find(u => normalizeEmail(u.email) === email);
    if (!user || !user.passwordHash) {
      return res.status(400).json({ error: "Invalid email or password." });
    }

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) {
      return res.status(400).json({ error: "Invalid email or password." });
    }

    req.session.userId = user.id;
    return res.json({ success: true, user: publicUser(user) });
  } catch (err) {
    return res.status(500).json({ error: "Login failed." });
  }
});

app.post("/api/register", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const name = cleanText(req.body.name, 100);
    const mobile = cleanText(req.body.mobile, 15);
    const city = cleanText(req.body.city, 50);
    const password = String(req.body.password || "");

    if (!validEmail(email)) return res.status(400).json({ error: "Invalid email address." });
    if (password.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters." });

    const existing = db.users.find(u => normalizeEmail(u.email) === email);
    if (existing) return res.status(400).json({ error: "Email already registered." });

    const passwordHash = await bcrypt.hash(password, 10);
    const user = {
      id: crypto.randomUUID(),
      name,
      email,
      mobile,
      city,
      passwordHash,
      role: "Member",
      balance: 0,
      emailVerified: false,
      mobileVerified: false,
      authProvider: "local",
      createdAt: new Date().toISOString()
    };

    db.users.push(user);
    saveDB(db);

    req.session.userId = user.id;
    return res.json({ success: true, user: publicUser(user) });
  } catch (err) {
    return res.status(500).json({ error: "Registration failed." });
  }
});

app.get("/api/me", (req, res) => {
  return res.json(publicUser(currentUser(req)));
});

app.get("/api/tasks", requireLogin, (req, res) => {
  return res.json(db.tasks.filter(t => t.active !== false));
});

app.post("/api/submissions", requireLogin, (req, res) => {
  const { taskId, proofText, proofImage } = req.body;
  const sub = {
    id: crypto.randomUUID(),
    userId: req.user.id,
    taskId: Number(taskId),
    proofText: cleanText(proofText, 500),
    proofImage: proofImage || "",
    status: "Pending",
    createdAt: new Date().toISOString()
  };
  db.submissions.push(sub);
  saveDB(db);
  return res.json({ success: true, submission: sub });
});

app.get("/api/submissions/me", requireLogin, (req, res) => {
  const userSubs = db.submissions.filter(s => String(s.userId) === String(req.user.id));
  return res.json(userSubs);
});

app.post("/api/withdrawals", requireLogin, (req, res) => {
  const { amount, paymentMethod, details } = req.body;
  const numAmount = Number(amount);

  if (numAmount > (req.user.balance || 0)) {
    return res.status(400).json({ error: "Insufficient balance." });
  }

  const withdrawal = {
    id: crypto.randomUUID(),
    userId: req.user.id,
    amount: numAmount,
    paymentMethod: cleanText(paymentMethod, 50),
    details: cleanText(details, 200),
    status: "Pending",
    createdAt: new Date().toISOString()
  };

  db.withdrawals.push(withdrawal);
  saveDB(db);
  return res.json({ success: true, withdrawal });
});

app.get("/api/withdrawals/me", requireLogin, (req, res) => {
  const userList = db.withdrawals.filter(w => String(w.userId) === String(req.user.id));
  return res.json(userList);
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    return res.json({ message: "Logged out successfully" });
  });
});

/* Static Files Serving */
app.use(express.static(path.join(__dirname, "public")));

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
