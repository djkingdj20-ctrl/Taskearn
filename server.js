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
const DATA_DIR = path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "database.json");

const SESSION_SECRET = process.env.SESSION_SECRET || "CHANGE_THIS_TASKEARN_SECRET_2026";
const GMAIL_USER = process.env.GMAIL_USER || "";
const GMAIL_APP_PASSWORD = process.env.GMAIL_APP_PASSWORD || "";

const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID || "";
const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN || "";
const TWILIO_PHONE_NUMBER = process.env.TWILIO_PHONE_NUMBER || "";

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";

/* =====================================================
   DATABASE
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

    database.users.forEach((user) => {
      user.mobile ??= "";
      user.city ??= "";
      user.profileImage ??= "";
      user.emailVerified ??= false;
      user.mobileVerified ??= false;
      user.googleId ??= "";
      user.authProvider ??= user.googleId ? "google" : "local";
      user.balance ??= 0;
      user.role ??= "Member";
      user.passwordHash ??= "";
    });

    return database;
  } catch (error) {
    console.error("Database load error:", error);
    const database = defaultDatabase();
    try { saveDB(database); } catch (e) {}
    return database;
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

function requireLogin(req, res, next) {
  const user = currentUser(req);
  if (!user) {
    return res.status(401).json({ error: "Please login first." });
  }
  req.user = user;
  next();
}

/* =====================================================
   DUPLICATE CHECKS
===================================================== */

function findVerifiedUserByEmail(email) {
  const normalized = normalizeEmail(email);
  return db.users.find((user) => Boolean(user.emailVerified) && normalizeEmail(user.email) === normalized);
}

function findVerifiedUserByMobile(mobile) {
  const normalized = normalizeMobile(mobile);
  return db.users.find((user) => Boolean(user.mobileVerified) && normalizeMobile(user.mobile) === normalized);
}

function findUnverifiedUser(email, mobile) {
  const normalizedEmail = normalizeEmail(email);
  const normalizedMobile = normalizeMobile(mobile);

  return db.users.find(
    (user) =>
      !user.emailVerified &&
      !user.mobileVerified &&
      (normalizeEmail(user.email) === normalizedEmail || normalizeMobile(user.mobile) === normalizedMobile)
  );
}

/* =====================================================
   OTP LOGIC
===================================================== */

const OTP_EXPIRY_MS = 10 * 60 * 1000;
const OTP_RESEND_MS = 60 * 1000;
const OTP_MAX_ATTEMPTS = 5;

function randomOtp() {
  return String(crypto.randomInt(100000, 1000000));
}

function hashOtp(otp) {
  return crypto.createHash("sha256").update(String(otp)).digest("hex");
}

function safeCompare(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (aa.length !== bb.length) return false;
  return crypto.timingSafeEqual(aa, bb);
}

/* =====================================================
   REAL EMAIL OTP (GMAIL FIXED SERVICE)
===================================================== */

const mailTransporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: GMAIL_USER,
    pass: GMAIL_APP_PASSWORD
  }
});

async function verifyMailConnection() {
  if (!GMAIL_USER || !GMAIL_APP_PASSWORD) {
    console.warn("WARNING: GMAIL_USER or GMAIL_APP_PASSWORD missing in env.");
    return;
  }
  try {
    await mailTransporter.verify();
    console.log(`Gmail SMTP Ready: ${GMAIL_USER}`);
  } catch (error) {
    console.error("Gmail Connection Error:", error.message);
  }
}

async function sendEmailOtp(email, otp, purpose) {
  if (!GMAIL_USER || !GMAIL_APP_PASSWORD) {
    throw new Error("Gmail environment variables (GMAIL_USER / GMAIL_APP_PASSWORD) are missing.");
  }

  let subject = "TaskEarn Email Verification Code";
  if (purpose === "login") subject = "TaskEarn Login Verification Code";
  if (purpose === "profile") subject = "TaskEarn Mobile Verification";

  const html = `
    <div style="max-width:500px;margin:20px auto;font-family:Arial,sans-serif;padding:20px;border:1px solid #eee;border-radius:10px;">
      <h2>TaskEarn Verification</h2>
      <p>Your verification code is:</p>
      <div style="font-size:32px;font-weight:bold;letter-spacing:5px;color:#007bff;margin:15px 0;">${otp}</div>
      <p>This code is valid for 10 minutes.</p>
    </div>`;

  await mailTransporter.sendMail({
    from: `"TaskEarn" <${GMAIL_USER}>`,
    to: email,
    subject,
    html
  });
}

/* =====================================================
   REAL SMS OTP (TWILIO FIXED)
===================================================== */

async function sendSmsOtp(mobile, otp) {
  if (!TWILIO_ACCOUNT_SID || !TWILIO_AUTH_TOKEN || !TWILIO_PHONE_NUMBER) {
    throw new Error("Twilio environment variables missing on server.");
  }

  const auth = Buffer.from(`${TWILIO_ACCOUNT_SID}:${TWILIO_AUTH_TOKEN}`).toString("base64");
  const params = new URLSearchParams();
  params.append("To", mobile);
  params.append("From", TWILIO_PHONE_NUMBER);
  params.append("Body", `TaskEarn code: ${otp}. Valid for 10 minutes.`);

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
    const errorText = await response.text();
    console.error("Twilio API Error Response:", errorText);
    throw new Error("Twilio SMS sending failed. Check phone number format (+91).");
  }
}

/* =====================================================
   OTP MANAGEMENT
===================================================== */

function createOtpRecord(user, type, purpose) {
  const otp = randomOtp();
  const now = Date.now();

  const record = {
    userId: user.id,
    type,
    purpose,
    otpHash: hashOtp(otp),
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + OTP_EXPIRY_MS).toISOString(),
    attempts: 0,
    lastSentAt: new Date(now).toISOString()
  };

  db.otpCodes = (db.otpCodes || []).filter(
    (item) => !(String(item.userId) === String(user.id) && item.type === type && item.purpose === purpose)
  );

  db.otpCodes.push(record);
  saveDB(db);

  return otp;
}

function getOtpRecord(userId, type, purpose) {
  db.otpCodes ||= [];
  return db.otpCodes
    .filter((item) => String(item.userId) === String(userId) && item.type === type && item.purpose === purpose)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))[0];
}

function deleteOtpRecord(userId, type, purpose) {
  db.otpCodes = (db.otpCodes || []).filter(
    (item) => !(String(item.userId) === String(userId) && item.type === type && item.purpose === purpose)
  );
  saveDB(db);
}

async function sendOtpFor(user, type, purpose, force = false) {
  const existing = getOtpRecord(user.id, type, purpose);

  if (existing && !force) {
    const lastSent = new Date(existing.lastSentAt).getTime();
    const elapsed = Date.now() - lastSent;
    if (elapsed < OTP_RESEND_MS) {
      const remaining = Math.ceil((OTP_RESEND_MS - elapsed) / 1000);
      throw new Error(`Please wait ${remaining} seconds before requesting another OTP.`);
    }
  }

  const otp = createOtpRecord(user, type, purpose);

  if (type === "email") {
    await sendEmailOtp(user.email, otp, purpose);
  } else {
    await sendSmsOtp(user.mobile, otp);
  }
}

/* =====================================================
   VERIFICATION FLOW
===================================================== */

async function startVerification(req, user, purpose) {
  req.session.verification = {
    userId: user.id,
    purpose,
    emailVerified: Boolean(user.emailVerified),
    mobileVerified: Boolean(user.mobileVerified),
    createdAt: Date.now()
  };

  if (!user.emailVerified) {
    await sendOtpFor(user, "email", purpose, true);
    req.session.verification.step = "email";
    return "email";
  }

  if (!user.mobileVerified && user.mobile) {
    await sendOtpFor(user, "mobile", purpose, true);
    req.session.verification.step = "mobile";
    return "mobile";
  }

  return "complete";
}

function completeLogin(req, user, remember) {
  req.session.userId = user.id;
  delete req.session.verification;
  delete req.session.remember;

  req.session.cookie.maxAge = remember ? 1000 * 60 * 60 * 24 * 30 : 1000 * 60 * 60 * 12;
}

/* =====================================================
   GOOGLE VERIFICATION
===================================================== */

async function verifyGoogleIdToken(idToken) {
  if (!GOOGLE_CLIENT_ID) throw new Error("Google Sign-In is not configured.");
  if (!idToken) throw new Error("Google authentication token is missing.");

  const response = await fetch("https://oauth2.googleapis.com/tokeninfo?id_token=" + encodeURIComponent(idToken));
  if (!response.ok) throw new Error("Invalid Google authentication token.");

  const data = await response.json();
  if (data.aud !== GOOGLE_CLIENT_ID) throw new Error("Google client ID does not match.");
  if (data.email_verified !== "true" && data.email_verified !== true) throw new Error("Google email is unverified.");

  return {
    googleId: cleanText(data.sub, 200),
    email: normalizeEmail(data.email),
    name: cleanText(data.name || data.email.split("@")[0], 80),
    picture: cleanText(data.picture || "", 1000)
  };
}

/* =====================================================
   ENDPOINTS
===================================================== */

app.get("/api/google-config", (req, res) => {
  res.json({ clientId: GOOGLE_CLIENT_ID });
});

app.post("/api/auth/google", async (req, res) => {
  try {
    const google = await verifyGoogleIdToken(req.body.credential);

    let user = db.users.find((u) => u.googleId && String(u.googleId) === String(google.googleId));
    if (!user) user = db.users.find((u) => normalizeEmail(u.email) === google.email);

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
    }

    saveDB(db);

    if (user.mobile && !user.mobileVerified) {
      req.session.remember = true;
      const step = await startVerification(req, user, "login");

      if (step !== "complete") {
        return res.json({ verificationRequired: true, step, email: user.email, mobile: user.mobile });
      }
    }

    completeLogin(req, user, true);
    res.json({ success: true, message: "Google login successful.", user: publicUser(user) });
  } catch (error) {
    console.error("Google Auth Error:", error);
    res.status(401).json({ error: error.message || "Google login failed." });
  }
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.use(express.static(path.join(__dirname, "public")));

app.post("/api/register", async (req, res) => {
  try {
    const name = cleanText(req.body.name, 80);
    const email = normalizeEmail(req.body.email);
    const mobile = normalizeMobile(req.body.mobile);
    const city = cleanText(req.body.city, 80);
    const password = String(req.body.password || "");

    if (!name || !email || !mobile || !city || !password) {
      return res.status(400).json({ error: "Please complete all fields." });
    }

    if (!validEmail(email)) return res.status(400).json({ error: "Invalid email format." });
    if (!validMobile(mobile)) return res.status(400).json({ error: "Invalid mobile number format." });
    if (password.length < 6) return res.status(400).json({ error: "Password min 6 characters required." });

    if (findVerifiedUserByEmail(email)) {
      return res.status(409).json({ error: "Email is already registered and verified." });
    }

    if (findVerifiedUserByMobile(mobile)) {
      return res.status(409).json({ error: "Mobile number is already registered and verified." });
    }

    let user = findUnverifiedUser(email, mobile);

    if (user) {
      user.name = name;
      user.email = email;
      user.mobile = mobile;
      user.city = city;
      user.passwordHash = await bcrypt.hash(password, 12);
      saveDB(db);
    } else {
      user = {
        id: crypto.randomUUID(),
        name,
        email,
        passwordHash: await bcrypt.hash(password, 12),
        role: "Member",
        mobile,
        city,
        profileImage: "",
        emailVerified: false,
        mobileVerified: false,
        googleId: "",
        authProvider: "local",
        balance: 0,
        createdAt: new Date().toISOString()
      };
      db.users.push(user);
      saveDB(db);
    }

    req.session.remember = Boolean(req.body.remember);
    const step = await startVerification(req, user, "register");

    return res.status(200).json({
      success: true,
      verificationRequired: true,
      step,
      email: user.email,
      mobile: user.mobile,
      message: "Registration successful. OTP sent."
    });
  } catch (error) {
    console.error("REGISTER ERROR:", error);
    return res.status(500).json({ error: error.message || "Failed to process registration." });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");
    const remember = Boolean(req.body.remember);

    const user = db.users.find((u) => normalizeEmail(u.email) === email);
    if (!user || !user.passwordHash) {
      return res.status(401).json({ error: "Invalid email or password." });
    }

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) return res.status(401).json({ error: "Invalid email or password." });

    req.session.remember = remember;

    if (user.emailVerified && user.mobileVerified) {
      completeLogin(req, user, remember);
      return res.json({ success: true, user: publicUser(user) });
    }

    const step = await startVerification(req, user, "login");

    if (step === "complete") {
      completeLogin(req, user, remember);
      return res.json({ success: true, user: publicUser(user) });
    }

    return res.json({ success: true, verificationRequired: true, step, email: user.email, mobile: user.mobile });
  } catch (error) {
    console.error("LOGIN ERROR:", error);
    res.status(500).json({ error: error.message || "Login failed." });
  }
});

app.post("/api/verify-otp", async (req, res) => {
  try {
    const verification = req.session.verification;
    if (!verification) return res.status(400).json({ error: "Session expired. Try logging in again." });

    const user = findUserById(verification.userId);
    if (!user) return res.status(404).json({ error: "User not found." });

    const otp = cleanText(req.body.otp, 6);
    if (!/^\d{6}$/.test(otp)) return res.status(400).json({ error: "Enter valid 6-digit OTP." });

    const step = verification.step;
    const record = getOtpRecord(user.id, step, verification.purpose);

    if (!record) return res.status(400).json({ error: "OTP expired or invalid." });

    if (Date.now() > new Date(record.expiresAt).getTime()) {
      deleteOtpRecord(user.id, step, verification.purpose);
      return res.status(400).json({ error: "OTP expired." });
    }

    const valid = safeCompare(record.otpHash, hashOtp(otp));
    if (!valid) {
      record.attempts++;
      saveDB(db);
      return res.status(401).json({ error: "Incorrect OTP." });
    }

    deleteOtpRecord(user.id, step, verification.purpose);

    if (step === "email") user.emailVerified = true;
    if (step === "mobile") user.mobileVerified = true;
    saveDB(db);

    if (step === "email" && !user.mobileVerified && user.mobile) {
      await sendOtpFor(user, "mobile", verification.purpose, true);
      verification.emailVerified = true;
      verification.step = "mobile";
      req.session.verification = verification;

      return res.json({ success: true, step: "mobile", email: user.email, mobile: user.mobile, message: "Email verified. Mobile OTP sent." });
    }

    completeLogin(req, user, Boolean(req.session.remember));
    return res.json({ success: true, step: "complete", user: publicUser(user) });
  } catch (error) {
    console.error("VERIFY OTP ERROR:", error);
    res.status(500).json({ error: error.message || "Verification failed." });
  }
});

app.post("/api/resend-otp", async (req, res) => {
  try {
    const verification = req.session.verification;
    if (!verification) return res.status(400).json({ error: "Session expired." });

    const user = findUserById(verification.userId);
    if (!user) return res.status(404).json({ error: "User not found." });

    await sendOtpFor(user, verification.step, verification.purpose, false);
    return res.json({ success: true, message: "New OTP sent." });
  } catch (error) {
    res.status(400).json({ error: error.message || "Failed to resend OTP." });
  }
});

app.get("/api/me", (req, res) => res.json(publicUser(currentUser(req))));

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ success: true });
  });
});

app.listen(PORT, "0.0.0.0", async () => {
  console.log(`Server listening on port ${PORT}`);
  await verifyMailConnection();
});
