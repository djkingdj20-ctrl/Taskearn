require("dotenv").config();
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
   CONFIGURATION
===================================================== */

const PORT = Number(process.env.PORT) || 10000;
const DATA_DIR = path.join("/tmp", "data");
const DB_FILE = path.join(DATA_DIR, "database.json");

const SESSION_SECRET = process.env.SESSION_SECRET || "CHANGE_THIS_TASKEARN_SECRET_2026";
const GMAIL_USER = process.env.GMAIL_USER || "";
const GMAIL_APP_PASSWORD = process.env.GMAIL_APP_PASSWORD || "";

const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID || "";
const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN || "";
const TWILIO_PHONE_NUMBER = process.env.TWILIO_PHONE_NUMBER || "";

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";

/* =====================================================
   DATABASE (TMP DIRECTORY SAFE FOR RENDER)
===================================================== */

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

function defaultDatabase() {
  return {
    users: [],
    tasks: [
      { id: 1, title: "Complete a simple online task", description: "Complete the instructions carefully and submit the task for review.", type: "General", reward: 10, active: true },
      { id: 2, title: "Social Media Engagement", description: "Complete the specified social media activity and submit your task.", type: "Social", reward: 15, active: true },
      { id: 3, title: "Website Visit Task", description: "Visit the required website and complete the provided instructions.", type: "Website", reward: 20, active: true }
    ],
    submissions: [],
    withdrawals: [],
    otpCodes: []
  };
}

function saveDB(database) {
  try {
    const tempFile = DB_FILE + ".tmp";
    fs.writeFileSync(tempFile, JSON.stringify(database, null, 2), "utf8");
    fs.renameSync(tempFile, DB_FILE);
  } catch (err) {
    console.error("DB Save Error:", err.message);
  }
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
    return defaultDatabase();
  }
}

let db = loadDB();

/* =====================================================
   SESSION
===================================================== */

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 24 * 30
    }
  })
);

/* =====================================================
   HELPERS
===================================================== */

function cleanText(value, maxLength = 200) {
  return String(value ?? "").trim().slice(0, maxLength);
}

function normalizeEmail(value) {
  return cleanText(value, 160).toLowerCase();
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function normalizeMobile(value) {
  let clean = cleanText(value, 20).replace(/[\s()-]/g, "");
  if (/^[0-9]{10}$/.test(clean)) {
    clean = "+91" + clean;
  }
  return clean;
}

function validMobile(mobile) {
  return /^\+?[0-9]{10,15}$/.test(mobile);
}

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
    balance: Number(user.balance || 0),
    createdAt: user.createdAt
  };
}

function findUserById(id) {
  return db.users.find((user) => String(user.id) === String(id));
}

function currentUser(req) {
  if (!req.session.userId) return null;
  return findUserById(req.session.userId);
}

/* =====================================================
   OTP & MAIL LOGIC
===================================================== */

const OTP_EXPIRY_MS = 10 * 60 * 1000;

function randomOtp() {
  return String(crypto.randomInt(100000, 1000000));
}

function hashOtp(otp) {
  return crypto.createHash("sha256").update(String(otp)).digest("hex");
}

const mailTransporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: GMAIL_USER,
    pass: GMAIL_APP_PASSWORD
  }
});

async function sendEmailOtp(email, otp) {
  if (!GMAIL_USER || !GMAIL_APP_PASSWORD) {
    throw new Error("GMAIL_USER or GMAIL_APP_PASSWORD is not set in Render Environment Variables.");
  }

  await mailTransporter.sendMail({
    from: `"TaskEarn" <${GMAIL_USER}>`,
    to: email,
    subject: "TaskEarn Verification Code",
    html: `<h2>Your OTP: <b>${otp}</b></h2><p>Valid for 10 minutes.</p>`
  });
}

async function sendSmsOtp(mobile, otp) {
  if (!TWILIO_ACCOUNT_SID || !TWILIO_AUTH_TOKEN || !TWILIO_PHONE_NUMBER) {
    throw new Error("Twilio Variables are missing in Render Environment Variables.");
  }

  const auth = Buffer.from(`${TWILIO_ACCOUNT_SID}:${TWILIO_AUTH_TOKEN}`).toString("base64");
  const params = new URLSearchParams();
  params.append("To", mobile);
  params.append("From", TWILIO_PHONE_NUMBER);
  params.append("Body", `TaskEarn Verification Code: ${otp}`);

  const response = await fetch(
    `https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(TWILIO_ACCOUNT_SID)}/Messages.json`,
    {
      method: "POST",
      headers: {
        Authorization: "Basic " + auth,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: params.toString()
    }
  );

  if (!response.ok) {
    const errorData = await response.text();
    console.error("Twilio Error:", errorData);
    throw new Error("Failed to send Mobile OTP via Twilio.");
  }
}

async function sendOtpFor(user, type, purpose) {
  const otp = randomOtp();
  const now = Date.now();

  db.otpCodes = (db.otpCodes || []).filter(
    (item) => !(String(item.userId) === String(user.id) && item.type === type)
  );

  db.otpCodes.push({
    userId: user.id,
    type,
    purpose,
    otpHash: hashOtp(otp),
    expiresAt: new Date(now + OTP_EXPIRY_MS).toISOString()
  });

  saveDB(db);

  if (type === "email") {
    await sendEmailOtp(user.email, otp);
  } else {
    await sendSmsOtp(user.mobile, otp);
  }
}

/* =====================================================
   ENDPOINTS
===================================================== */

app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.post("/api/register", async (req, res) => {
  try {
    const name = cleanText(req.body.name);
    const email = normalizeEmail(req.body.email);
    const mobile = normalizeMobile(req.body.mobile);
    const password = String(req.body.password || "");

    if (!name || !email || !mobile || !password) {
      return res.status(400).json({ error: "All fields are required." });
    }

    let user = db.users.find((u) => normalizeEmail(u.email) === email);

    if (!user) {
      user = {
        id: crypto.randomUUID(),
        name,
        email,
        mobile,
        passwordHash: await bcrypt.hash(password, 10),
        emailVerified: false,
        mobileVerified: false,
        balance: 0,
        createdAt: new Date().toISOString()
      };
      db.users.push(user);
      saveDB(db);
    }

    req.session.verification = { userId: user.id, step: "email", purpose: "register" };
    await sendOtpFor(user, "email", "register");

    res.json({ success: true, verificationRequired: true, step: "email", email: user.email });
  } catch (error) {
    console.error("Register Error:", error);
    res.status(500).json({ error: error.message || "Registration failed." });
  }
});

app.post("/api/verify-otp", async (req, res) => {
  try {
    const verification = req.session.verification;
    if (!verification) return res.status(400).json({ error: "Session expired." });

    const user = findUserById(verification.userId);
    const otp = cleanText(req.body.otp);

    const record = (db.otpCodes || []).find(
      (o) => String(o.userId) === String(user.id) && o.type === verification.step
    );

    if (!record || hashOtp(otp) !== record.otpHash) {
      return res.status(400).json({ error: "Invalid OTP." });
    }

    if (verification.step === "email") {
      user.emailVerified = true;
      saveDB(db);

      if (user.mobile) {
        verification.step = "mobile";
        req.session.verification = verification;
        await sendOtpFor(user, "mobile", verification.purpose);
        return res.json({ success: true, step: "mobile", mobile: user.mobile });
      }
    } else {
      user.mobileVerified = true;
      saveDB(db);
    }

    req.session.userId = user.id;
    delete req.session.verification;

    res.json({ success: true, step: "complete", user: publicUser(user) });
  } catch (error) {
    console.error("Verify Error:", error);
    res.status(500).json({ error: error.message || "Verification failed." });
  }
});

app.get("/api/me", (req, res) => res.json(publicUser(currentUser(req))));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
