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
   CONFIGURATION & ENV VARIABLES
===================================================== */

const PORT = Number(process.env.PORT) || 10000;
const DATA_DIR = path.join("/tmp", "data");
const DB_FILE = path.join(DATA_DIR, "database.json");

const SESSION_SECRET = process.env.SESSION_SECRET || "TASKEARN_SECRET_KEY_2026";
const GMAIL_USER = process.env.GMAIL_USER || "";
const GMAIL_APP_PASSWORD = process.env.GMAIL_APP_PASSWORD || "";

const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID || "";
const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN || "";
const TWILIO_PHONE_NUMBER = process.env.TWILIO_PHONE_NUMBER || "";

/* =====================================================
   DATABASE (TMP DIRECTORY FOR RENDER SAFETY)
===================================================== */

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

function defaultDatabase() {
  return {
    users: [],
    tasks: [
      { id: 1, title: "Complete a simple task", reward: 10, active: true },
      { id: 2, title: "Social Media Task", reward: 15, active: true }
    ],
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
      const dbData = defaultDatabase();
      saveDB(dbData);
      return dbData;
    }
    const raw = fs.readFileSync(DB_FILE, "utf8");
    if (!raw.trim()) return defaultDatabase();
    const parsed = JSON.parse(raw);
    parsed.users ||= [];
    parsed.otpCodes ||= [];
    return parsed;
  } catch (error) {
    console.error("Database load error:", error);
    return defaultDatabase();
  }
}

let db = loadDB();

/* =====================================================
   SESSION CONFIGURATION
===================================================== */

app.use(
  session({
    secret: SESSION_SECRET,
    resave: true,
    saveUninitialized: true,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: false, // Set to true if pure HTTPS domain
      maxAge: 1000 * 60 * 60 * 24
    }
  })
);

/* =====================================================
   HELPERS & VALIDATIONS
===================================================== */

function cleanText(val) {
  return String(val || "").trim();
}

function normalizeEmail(email) {
  return cleanText(email).toLowerCase();
}

function normalizeMobile(mobile) {
  let clean = cleanText(mobile).replace(/[\s()-]/g, "");
  if (/^[0-9]{10}$/.test(clean)) {
    clean = "+91" + clean;
  }
  return clean;
}

function publicUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    mobile: user.mobile,
    emailVerified: Boolean(user.emailVerified),
    mobileVerified: Boolean(user.mobileVerified),
    balance: user.balance || 0
  };
}

/* =====================================================
   OTP & MAILER SERVICES
===================================================== */

const mailTransporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: GMAIL_USER,
    pass: GMAIL_APP_PASSWORD
  }
});

function randomOtp() {
  return String(crypto.randomInt(100000, 1000000));
}

function hashOtp(otp) {
  return crypto.createHash("sha256").update(String(otp)).digest("hex");
}

async function sendEmailOtp(email, otp) {
  if (!GMAIL_USER || !GMAIL_APP_PASSWORD) {
    console.warn("Gmail Env variables missing! OTP email skipped.");
    return;
  }
  await mailTransporter.sendMail({
    from: `"TaskEarn" <${GMAIL_USER}>`,
    to: email,
    subject: "TaskEarn Verification Code",
    html: `<div style="padding:20px; border:1px solid #ddd;">
      <h2>TaskEarn Verification</h2>
      <p>Your OTP Code is: <b style="font-size: 24px; color: #007bff;">${otp}</b></p>
      <p>This code is valid for 10 minutes.</p>
    </div>`
  });
}

async function sendSmsOtp(mobile, otp) {
  if (!TWILIO_ACCOUNT_SID || !TWILIO_AUTH_TOKEN || !TWILIO_PHONE_NUMBER) {
    console.warn("Twilio Env variables missing! SMS skipped.");
    return;
  }
  const auth = Buffer.from(`${TWILIO_ACCOUNT_SID}:${TWILIO_AUTH_TOKEN}`).toString("base64");
  const params = new URLSearchParams();
  params.append("To", mobile);
  params.append("From", TWILIO_PHONE_NUMBER);
  params.append("Body", `Your TaskEarn OTP is: ${otp}`);

  await fetch(
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
}

async function generateAndSendOtp(user, type, purpose) {
  const otp = randomOtp();
  console.log(`[DEVELOPMENT OTP LOG] User: ${user.email} | Type: ${type} | OTP: ${otp}`);

  db.otpCodes = (db.otpCodes || []).filter(
    (item) => !(String(item.userId) === String(user.id) && item.type === type)
  );

  db.otpCodes.push({
    userId: user.id,
    type,
    purpose,
    otpHash: hashOtp(otp),
    expiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString()
  });

  saveDB(db);

  if (type === "email") {
    await sendEmailOtp(user.email, otp);
  } else if (type === "mobile") {
    await sendSmsOtp(user.mobile, otp);
  }
}

/* =====================================================
   ROUTES & ENDPOINTS
===================================================== */

app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// 1. REGISTER
app.post("/api/register", async (req, res) => {
  try {
    const name = cleanText(req.body.name);
    const email = normalizeEmail(req.body.email);
    const mobile = normalizeMobile(req.body.mobile);
    const password = String(req.body.password || "");

    if (!name || !email || !mobile || !password) {
      return res.status(400).json({ error: "అన్ని వివరాలు నమోదు చేయండి." });
    }

    let user = db.users.find((u) => normalizeEmail(u.email) === email);

    if (user && user.emailVerified && user.mobileVerified) {
      return res.status(400).json({ error: "ఈ ఇమెయిల్ తో అకౌంట్ ఇప్పటికే ఉంది. లాగిన్ అవ్వండి." });
    }

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
    } else {
      user.name = name;
      user.mobile = mobile;
      user.passwordHash = await bcrypt.hash(password, 10);
    }

    saveDB(db);

    // Save state in Session
    req.session.verification = {
      userId: user.id,
      step: "email",
      purpose: "register"
    };

    // Send Mail OTP
    await generateAndSendOtp(user, "email", "register");

    req.session.save((err) => {
      if (err) {
        console.error("Session Save Error:", err);
        return res.status(500).json({ error: "Session Error" });
      }
      return res.json({
        success: true,
        verificationRequired: true,
        step: "email",
        email: user.email,
        mobile: user.mobile,
        message: "OTP విజయవంతంగా పంపబడింది."
      });
    });
  } catch (error) {
    console.error("Register Error:", error);
    res.status(500).json({ error: error.message || "Registration Failed" });
  }
});

// 2. VERIFY OTP
app.post("/api/verify-otp", async (req, res) => {
  try {
    const verification = req.session.verification;
    if (!verification) {
      return res.status(400).json({ error: "సెషన్ గడువు ముగిసింది. మళ్ళీ ప్రయత్నించండి." });
    }

    const user = db.users.find((u) => String(u.id) === String(verification.userId));
    if (!user) return res.status(404).json({ error: "యూజర్ కనబడలేదు." });

    const otpInput = cleanText(req.body.otp);
    const inputHash = hashOtp(otpInput);

    const record = (db.otpCodes || []).find(
      (o) => String(o.userId) === String(user.id) && o.type === verification.step
    );

    if (!record || record.otpHash !== inputHash) {
      return res.status(400).json({ error: "సరికాని OTP. మళ్ళీ చూడండి." });
    }

    if (new Date() > new Date(record.expiresAt)) {
      return res.status(400).json({ error: "OTP ఎక్స్‌పైర్ అయింది." });
    }

    // Step Logic
    if (verification.step === "email") {
      user.emailVerified = true;
      saveDB(db);

      if (user.mobile && !user.mobileVerified) {
        verification.step = "mobile";
        req.session.verification = verification;
        await generateAndSendOtp(user, "mobile", verification.purpose);

        return req.session.save(() => {
          res.json({
            success: true,
            verificationRequired: true,
            step: "mobile",
            email: user.email,
            mobile: user.mobile,
            message: "Gmail వెరిఫై అయింది. ఇప్పుడు ఫోన్ నెంబర్ OTP నమోదు చేయండి."
          });
        });
      }
    } else if (verification.step === "mobile") {
      user.mobileVerified = true;
      saveDB(db);
    }

    req.session.userId = user.id;
    delete req.session.verification;

    req.session.save(() => {
      res.json({
        success: true,
        verificationRequired: false,
        step: "complete",
        user: publicUser(user),
        message: "అకౌంట్ విజయవంతంగా వెరిఫై చేయబడింది!"
      });
    });
  } catch (error) {
    console.error("OTP Verification Error:", error);
    res.status(500).json({ error: "Verification Failed" });
  }
});

// 3. RESEND OTP
app.post("/api/resend-otp", async (req, res) => {
  try {
    const verification = req.session.verification;
    if (!verification) return res.status(400).json({ error: "సెషన్ ముగిసింది." });

    const user = db.users.find((u) => String(u.id) === String(verification.userId));
    if (!user) return res.status(404).json({ error: "యూజర్ దొరకలేదు." });

    await generateAndSendOtp(user, verification.step, verification.purpose);
    res.json({ success: true, message: "కొత్త OTP పంపబడింది." });
  } catch (error) {
    res.status(500).json({ error: "OTP తిరిగి పంపడం విఫలమైంది." });
  }
});

// 4. LOGIN
app.post("/api/login", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");

    const user = db.users.find((u) => normalizeEmail(u.email) === email);
    if (!user) return res.status(400).json({ error: "ఈ ఇమెయిల్ తో అకౌంట్ లేదు." });

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return res.status(400).json({ error: "పాస్‌వర్డ్ తప్పు." });

    if (!user.emailVerified) {
      req.session.verification = { userId: user.id, step: "email", purpose: "login" };
      await generateAndSendOtp(user, "email", "login");

      return req.session.save(() => {
        res.json({ success: true, verificationRequired: true, step: "email", email: user.email });
      });
    }

    if (!user.mobileVerified && user.mobile) {
      req.session.verification = { userId: user.id, step: "mobile", purpose: "login" };
      await generateAndSendOtp(user, "mobile", "login");

      return req.session.save(() => {
        res.json({ success: true, verificationRequired: true, step: "mobile", mobile: user.mobile });
      });
    }

    req.session.userId = user.id;
    req.session.save(() => {
      res.json({ success: true, user: publicUser(user) });
    });
  } catch (error) {
    res.status(500).json({ error: "Login failed" });
  }
});

// GET CURRENT USER
app.get("/api/me", (req, res) => {
  if (!req.session.userId) return res.json(null);
  const user = db.users.find((u) => String(u.id) === String(req.session.userId));
  res.json(publicUser(user));
});

// LOGOUT
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ success: true });
  });
});

/* =====================================================
   PREVENT CRASHES & START SERVER
===================================================== */

process.on("uncaughtException", (err) => {
  console.error("Uncaught Exception Error:", err.message);
});

process.on("unhandledRejection", (reason) => {
  console.error("Unhandled Promise Rejection:", reason);
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server listening on port ${PORT}`);
});
