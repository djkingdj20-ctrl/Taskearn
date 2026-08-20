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

const PORT = Number(process.env.PORT) || 10000;

/* =====================================================
   CONFIGURATION
===================================================== */

const DATA_DIR = path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "database.json");

const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  "CHANGE_THIS_TASKEARN_SECRET_2026";

const GMAIL_USER =
  process.env.GMAIL_USER || "";

const GMAIL_APP_PASSWORD =
  process.env.GMAIL_APP_PASSWORD || "";

const GOOGLE_CLIENT_ID =
  process.env.GOOGLE_CLIENT_ID || "";

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

/* =====================================================
   DATABASE
===================================================== */

function defaultDatabase() {
  return {
    users: [],

    tasks: [
      {
        id: 1,
        title: "Complete a simple online task",
        description:
          "Complete the instructions carefully and submit the task for review.",
        type: "General",
        reward: 10,
        active: true
      },
      {
        id: 2,
        title: "Social Media Engagement",
        description:
          "Complete the specified social media activity and submit your task.",
        type: "Social",
        reward: 15,
        active: true
      },
      {
        id: 3,
        title: "Website Visit Task",
        description:
          "Visit the required website and complete the provided instructions.",
        type: "Website",
        reward: 20,
        active: true
      }
    ],

    submissions: [],
    withdrawals: [],
    otpCodes: []
  };
}

function saveDB(database) {
  const tempFile = DB_FILE + ".tmp";

  fs.writeFileSync(
    tempFile,
    JSON.stringify(database, null, 2),
    "utf8"
  );

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

    database.users.forEach(user => {
      user.mobile ??= "";
      user.city ??= "";
      user.profileImage ??= "";

      user.emailVerified ??= false;
      user.mobileVerified ??= false;

      user.googleId ??= "";

      user.authProvider ??=
        user.googleId ? "google" : "local";

      user.balance ??= 0;
      user.role ??= "Member";
      user.passwordHash ??= "";
    });

    return database;
  } catch (error) {
    console.error("Database error:", error);

    const database = defaultDatabase();
    saveDB(database);

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
      maxAge:
        1000 * 60 * 60 * 24 * 30
    }
  })
);

/* =====================================================
   HELPERS
===================================================== */

function cleanText(value, max = 200) {
  return String(value ?? "")
    .trim()
    .slice(0, max);
}

function normalizeEmail(value) {
  return cleanText(value, 160).toLowerCase();
}

function normalizeMobile(value) {
  return cleanText(value, 20)
    .replace(/[\s()-]/g, "");
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validMobile(mobile) {
  return /^\+?[0-9]{7,15}$/.test(mobile);
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
  return db.users.find(
    user =>
      String(user.id) === String(id)
  );
}

function currentUser(req) {
  return req.session.userId
    ? findUserById(req.session.userId)
    : null;
}

function requireLogin(req, res, next) {
  const user = currentUser(req);

  if (!user) {
    return res.status(401).json({
      error: "Please login first."
    });
  }

  req.user = user;
  next();
}

/* =====================================================
   OTP SYSTEM
   SINGLE OTP SYSTEM ONLY
===================================================== */

const OTP_EXPIRY_MS =
  10 * 60 * 1000;

const OTP_RESEND_MS =
  60 * 1000;

const OTP_MAX_ATTEMPTS = 5;

function randomOtp() {
  return String(
    crypto.randomInt(100000, 1000000)
  );
}

function hashOtp(otp) {
  return crypto
    .createHash("sha256")
    .update(String(otp))
    .digest("hex");
}

function safeCompare(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));

  if (aa.length !== bb.length) {
    return false;
  }

  return crypto.timingSafeEqual(
    aa,
    bb
  );
}

/*
  Creates exactly ONE OTP record.
*/

function createOtpRecord(
  user,
  type,
  purpose
) {
  const otp = randomOtp();
  const now = Date.now();

  /*
    Remove old OTP for the same user/type/purpose.
    This prevents multiple active OTPs.
  */

  db.otpCodes =
    db.otpCodes.filter(
      record =>
        !(
          String(record.userId) ===
            String(user.id) &&
          record.type === type &&
          record.purpose === purpose
        )
    );

  db.otpCodes.push({
    userId: user.id,
    type,
    purpose,

    otpHash: hashOtp(otp),

    createdAt:
      new Date(now).toISOString(),

    expiresAt:
      new Date(
        now + OTP_EXPIRY_MS
      ).toISOString(),

    attempts: 0,

    lastSentAt:
      new Date(now).toISOString()
  });

  saveDB(db);

  return otp;
}

function getOtpRecord(
  userId,
  type,
  purpose
) {
  return db.otpCodes
    .filter(
      record =>
        String(record.userId) ===
          String(userId) &&
        record.type === type &&
        record.purpose === purpose
    )
    .sort(
      (a, b) =>
        new Date(b.createdAt) -
        new Date(a.createdAt)
    )[0];
}

function deleteOtpRecord(
  userId,
  type,
  purpose
) {
  db.otpCodes =
    db.otpCodes.filter(
      record =>
        !(
          String(record.userId) ===
            String(userId) &&
          record.type === type &&
          record.purpose === purpose
        )
    );

  saveDB(db);
}

/* =====================================================
   GMAIL OTP
   ONLY EMAIL OTP SENDER
===================================================== */

const mailTransporter =
  nodemailer.createTransport({
    service: "gmail",

    auth: {
      user: GMAIL_USER,
      pass: GMAIL_APP_PASSWORD
    }
  });

async function sendEmailOtp(
  email,
  otp
) {
  if (
    !GMAIL_USER ||
    !GMAIL_APP_PASSWORD
  ) {
    throw new Error(
      "Gmail OTP service is not configured."
    );
  }

  await mailTransporter.sendMail({
    from:
      `"TaskEarn" <${GMAIL_USER}>`,

    to: email,

    subject:
      "TaskEarn Email Verification Code",

    html: `
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>TaskEarn OTP</title>
</head>

<body style="
margin:0;
padding:0;
background:#f5f7fb;
font-family:Arial,Helvetica,sans-serif;
">

<div style="
max-width:600px;
margin:30px auto;
background:#ffffff;
border-radius:16px;
padding:30px;
box-shadow:0 4px 20px rgba(0,0,0,0.08);
">

<h1 style="
margin:0 0 10px;
color:#ff5d2e;
">
TaskEarn
</h1>

<h2>
Email Verification
</h2>

<p>
Hello,
</p>

<p>
Your TaskEarn verification code is:
</p>

<div style="
font-size:36px;
font-weight:bold;
letter-spacing:10px;
text-align:center;
background:#f1f3f5;
padding:22px;
border-radius:12px;
margin:25px 0;
">
${otp}
</div>

<p>
This OTP expires in <strong>10 minutes</strong>.
</p>

<p>
If you did not request this code, please ignore this email.
</p>

<p style="
margin-top:30px;
color:#777;
font-size:13px;
">
TaskEarn
</p>

</div>

</body>
</html>
`
  });
}

/* =====================================================
   SINGLE OTP DISPATCHER
===================================================== */

async function sendOtpFor(
  user,
  type,
  purpose,
  force = false
) {
  const existing =
    getOtpRecord(
      user.id,
      type,
      purpose
    );

  /*
    Prevent rapid duplicate sending.
  */

  if (
    existing &&
    !force
  ) {
    const elapsed =
      Date.now() -
      new Date(
        existing.lastSentAt
      ).getTime();

    if (
      elapsed <
      OTP_RESEND_MS
    ) {
      const remaining =
        Math.ceil(
          (
            OTP_RESEND_MS -
            elapsed
          ) / 1000
        );

      throw new Error(
        `Please wait ${remaining} seconds before requesting another OTP.`
      );
    }
  }

  /*
    Create exactly ONE OTP.
  */

  const otp =
    createOtpRecord(
      user,
      type,
      purpose
    );

  try {
    if (type === "email") {
      /*
        ONLY Gmail is used here.
        No Resend.
        No second email sender.
      */

      await sendEmailOtp(
        user.email,
        otp
      );
    } else if (
      type === "mobile"
    ) {
      await sendSmsOtp(
        user.mobile,
        otp
      );
    } else {
      throw new Error(
        "Invalid OTP type."
      );
    }
  } catch (error) {
    deleteOtpRecord(
      user.id,
      type,
      purpose
    );

    throw error;
  }
}

/* =====================================================
   TWILIO MOBILE OTP
===================================================== */

async function sendSmsOtp(
  mobile,
  otp
) {
  const sid =
    process.env.TWILIO_ACCOUNT_SID;

  const token =
    process.env.TWILIO_AUTH_TOKEN;

  const from =
    process.env.TWILIO_PHONE_NUMBER;

  if (
    !sid ||
    !token ||
    !from
  ) {
    throw new Error(
      "Mobile verification service is not configured."
    );
  }

  if (
    typeof fetch !==
    "function"
  ) {
    throw new Error(
      "This server requires Node.js 18 or newer."
    );
  }

  const auth =
    Buffer.from(
      `${sid}:${token}`
    ).toString("base64");

  const params =
    new URLSearchParams();

  params.append(
    "To",
    mobile
  );

  params.append(
    "From",
    from
  );

  params.append(
    "Body",
    `TaskEarn verification code: ${otp}. This code expires in 10 minutes.`
  );

  const response =
    await fetch(
      `https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(
        sid
      )}/Messages.json`,
      {
        method: "POST",

        headers: {
          Authorization:
            `Basic ${auth}`,

          "Content-Type":
            "application/x-www-form-urlencoded"
        },

        body:
          params.toString()
      }
    );

  if (!response.ok) {
    const text =
      await response.text();

    console.error(
      "Twilio error:",
      text
    );

    throw new Error(
      "Unable to send mobile verification OTP."
    );
  }
}

/* =====================================================
   LOGIN SESSION
===================================================== */

function completeLogin(
  req,
  user,
  remember
) {
  req.session.userId =
    user.id;

  delete req.session.verification;
  delete req.session.withdrawalVerification;

  req.session.cookie.maxAge =
    remember
      ? 1000 *
        60 *
        60 *
        24 *
        30
      : 1000 *
        60 *
        60 *
        12;
}

/* =====================================================
   GOOGLE LOGIN
===================================================== */

async function verifyGoogleIdToken(
  idToken
) {
  if (!GOOGLE_CLIENT_ID) {
    throw new Error(
      "Google Sign-In is not configured."
    );
  }

  if (!idToken) {
    throw new Error(
      "Google authentication token is missing."
    );
  }

  if (
    typeof fetch !==
    "function"
  ) {
    throw new Error(
      "This server requires Node.js 18 or newer."
    );
  }

  const response =
    await fetch(
      "https://oauth2.googleapis.com/tokeninfo?id_token=" +
        encodeURIComponent(
          idToken
        )
    );

  if (!response.ok) {
    throw new Error(
      "Invalid Google authentication token."
    );
  }

  const data =
    await response.json();

  if (
    data.aud !==
    GOOGLE_CLIENT_ID
  ) {
    throw new Error(
      "Google client ID does not match."
    );
  }

  if (
    data.email_verified !==
      true &&
    data.email_verified !==
      "true"
  ) {
    throw new Error(
      "Your Google email is not verified."
    );
  }

  return {
    googleId:
      cleanText(
        data.sub,
        200
      ),

    email:
      normalizeEmail(
        data.email
      ),

    name:
      cleanText(
        data.name ||
          data.email.split("@")[0],
        80
      ),

    picture:
      cleanText(
        data.picture || "",
        1000
      )
  };
}

app.get(
  "/api/google-config",
  (req, res) => {
    res.json({
      clientId:
        GOOGLE_CLIENT_ID
    });
  }
);

app.post(
  "/api/auth/google",
  async (req, res) => {
    try {
      const google =
        await verifyGoogleIdToken(
          req.body.credential
        );

      let user =
        db.users.find(
          u =>
            u.googleId &&
            String(
              u.googleId
            ) ===
              String(
                google.googleId
              )
        );

      if (!user) {
        user =
          db.users.find(
            u =>
              normalizeEmail(
                u.email
              ) ===
                google.email
          );
      }

      if (!user) {
        user = {
          id:
            crypto.randomUUID(),

          name:
            google.name,

          email:
            google.email,

          passwordHash:
            "",

          role:
            "Member",

          mobile:
            "",

          city:
            "",

          profileImage:
            google.picture,

          emailVerified:
            true,

          mobileVerified:
            false,

          googleId:
            google.googleId,

          authProvider:
            "google",

          balance:
            0,

          createdAt:
            new Date().toISOString()
        };

        db.users.push(user);
      } else {
        user.googleId =
          google.googleId;

        user.emailVerified =
          true;

        user.authProvider =
          "google";

        if (
          !user.profileImage
        ) {
          user.profileImage =
            google.picture;
        }

        if (!user.name) {
          user.name =
            google.name;
        }
      }

      saveDB(db);

      completeLogin(
        req,
        user,
        true
      );

      res.json({
        success: true,
        user:
          publicUser(user)
      });
    } catch (error) {
      console.error(
        "Google login error:",
        error
      );

      res.status(401).json({
        error:
          error.message ||
          "Google login failed."
      });
    }
  }
);

/* =====================================================
   STATIC FILES
===================================================== */

app.get(
  "/",
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

app.use(
  express.static(
    path.join(
      __dirname,
      "public"
    )
  )
);

/* =====================================================
   REGISTER
   EMAIL OTP ONLY
===================================================== */

app.post(
  "/api/register",
  async (req, res) => {
    try {
      const name =
        cleanText(
          req.body.name,
          80
        );

      const email =
        normalizeEmail(
          req.body.email
        );

      const mobile =
        normalizeMobile(
          req.body.mobile
        );

      const city =
        cleanText(
          req.body.city,
          80
        );

      const password =
        String(
          req.body.password || ""
        );

      if (
        !name ||
        !email ||
        !mobile ||
        !city ||
        !password
      ) {
        return res.status(400).json({
          error:
            "Please complete all fields."
        });
      }

      if (
        !validEmail(email)
      ) {
        return res.status(400).json({
          error:
            "Please enter a valid email address."
        });
      }

      if (
        !validMobile(mobile)
      ) {
        return res.status(400).json({
          error:
            "Please enter a valid mobile number."
        });
      }

      if (
        password.length < 6
      ) {
        return res.status(400).json({
          error:
            "Password must contain at least 6 characters."
        });
      }

      if (
        db.users.some(
          u =>
            normalizeEmail(
              u.email
            ) === email
        )
      ) {
        return res.status(409).json({
          error:
            "An account with this email already exists. Please login."
        });
      }

      if (
        db.users.some(
          u =>
            u.mobile ===
            mobile
        )
      ) {
        return res.status(409).json({
          error:
            "This mobile number is already registered."
        });
      }

      const user = {
        id:
          crypto.randomUUID(),

        name,

        email,

        passwordHash:
          await bcrypt.hash(
            password,
            12
          ),

        role:
          "Member",

        mobile,

        city,

        profileImage:
          "",

        emailVerified:
          false,

        mobileVerified:
          false,

        googleId:
          "",

        authProvider:
          "local",

        balance:
          0,

        createdAt:
          new Date().toISOString()
      };

      db.users.push(user);
      saveDB(db);

      req.session.verification = {
        userId:
          user.id,

        purpose:
          "register",

        step:
          "email"
      };

      try {
        /*
          ONE email OTP.
        */

        await sendOtpFor(
          user,
          "email",
          "register",
          true
        );
      } catch (error) {
        db.users =
          db.users.filter(
            u =>
              String(
                u.id
              ) !==
              String(
                user.id
              )
          );

        saveDB(db);

        throw error;
      }

      res.json({
        verificationRequired:
          true,

        step:
          "email",

        email:
          user.email,

        mobile:
          user.mobile
      });
    } catch (error) {
      console.error(
        "Register error:",
        error
      );

      res.status(500).json({
        error:
          error.message ||
          "Unable to create account."
      });
    }
  }
);

/* =====================================================
   LOGIN
===================================================== */

app.post(
  "/api/login",
  async (req, res) => {
    try {
      const email =
        normalizeEmail(
          req.body.email
        );

      const password =
        String(
          req.body.password || ""
        );

      const remember =
        Boolean(
          req.body.remember
        );

      const user =
        db.users.find(
          u =>
            normalizeEmail(
              u.email
            ) === email
        );

      if (
        !user ||
        !user.passwordHash
      ) {
        return res.status(401).json({
          error:
            "Invalid email or password. If you registered with Google, use Google Sign-In."
        });
      }

      const valid =
        await bcrypt.compare(
          password,
          user.passwordHash
        );

      if (!valid) {
        return res.status(401).json({
          error:
            "Invalid email or password."
        });
      }

      if (
        !user.emailVerified
      ) {
        req.session.verification = {
          userId:
            user.id,

          purpose:
            "login",

          step:
            "email"
        };

        /*
          ONE email OTP.
        */

        await sendOtpFor(
          user,
          "email",
          "login",
          true
        );

        return res.json({
          verificationRequired:
            true,

          step:
            "email",

          email:
            user.email,

          mobile:
            user.mobile
        });
      }

      completeLogin(
        req,
        user,
        remember
      );

      res.json({
        user:
          publicUser(user)
      });
    } catch (error) {
      console.error(
        "Login error:",
        error
      );

      res.status(500).json({
        error:
          error.message ||
          "Unable to login."
      });
    }
  }
);

/* =====================================================
   VERIFY EMAIL OTP
===================================================== */

app.post(
  "/api/verify-otp",
  async (req, res) => {
    try {
      const verification =
        req.session.verification;

      if (!verification) {
        return res.status(400).json({
          error:
            "Verification session expired. Please login again."
        });
      }

      const user =
        findUserById(
          verification.userId
        );

      if (!user) {
        return res.status(404).json({
          error:
            "Account not found."
        });
      }

      const otp =
        cleanText(
          req.body.otp,
          6
        );

      if (
        !/^\d{6}$/.test(otp)
      ) {
        return res.status(400).json({
          error:
            "Please enter the 6-digit OTP."
        });
      }

      const record =
        getOtpRecord(
          user.id,
          "email",
          verification.purpose
        );

      if (!record) {
        return res.status(400).json({
          error:
            "OTP not found. Please request a new OTP."
        });
      }

      if (
        Date.now() >
        new Date(
          record.expiresAt
        ).getTime()
      ) {
        deleteOtpRecord(
          user.id,
          "email",
          verification.purpose
        );

        return res.status(400).json({
          error:
            "OTP has expired. Please request a new OTP."
        });
      }

      if (
        record.attempts >=
        OTP_MAX_ATTEMPTS
      ) {
        deleteOtpRecord(
          user.id,
          "email",
          verification.purpose
        );

        return res.status(429).json({
          error:
            "Too many incorrect attempts. Please request a new OTP."
        });
      }

      if (
        !safeCompare(
          record.otpHash,
          hashOtp(otp)
        )
      ) {
        record.attempts++;

        saveDB(db);

        return res.status(401).json({
          error:
            "Incorrect OTP."
        });
      }

      deleteOtpRecord(
        user.id,
        "email",
        verification.purpose
      );

      user.emailVerified =
        true;

      saveDB(db);

      completeLogin(
        req,
        user,
        true
      );

      res.json({
        step:
          "complete",

        user:
          publicUser(user)
      });
    } catch (error) {
      console.error(
        "Email OTP verification error:",
        error
      );

      res.status(500).json({
        error:
          error.message ||
          "Unable to verify OTP."
      });
    }
  }
);

/* =====================================================
   RESEND EMAIL OTP
===================================================== */

app.post(
  "/api/resend-otp",
  async (req, res) => {
    try {
      const verification =
        req.session.verification;

      if (!verification) {
        return res.status(400).json({
          error:
            "Verification session expired. Please login again."
        });
      }

      const user =
        findUserById(
          verification.userId
        );

      if (!user) {
        return res.status(404).json({
          error:
            "Account not found."
        });
      }

      /*
        This endpoint creates a new OTP only after
        the resend cooldown.

        It does NOT create two OTPs.
      */

      await sendOtpFor(
        user,
        "email",
        verification.purpose,
        false
      );

      res.json({
        message:
          "A new Gmail OTP has been sent."
      });
    } catch (error) {
      res.status(400).json({
        error:
          error.message ||
          "Unable to resend OTP."
      });
    }
  }
);

/* =====================================================
   CURRENT USER
===================================================== */

app.get(
  "/api/me",
  (req, res) => {
    res.json(
      publicUser(
        currentUser(req)
      )
    );
  }
);

/* =====================================================
   LOGOUT
===================================================== */

app.post(
  "/api/logout",
  (req, res) => {
    req.session.destroy(
      error => {
        if (error) {
          return res.status(500).json({
            error:
              "Unable to logout."
          });
        }

        res.clearCookie(
          "connect.sid"
        );

        res.json({
          message:
            "Logged out successfully."
        });
      }
    );
  }
);

/* =====================================================
   PROFILE
===================================================== */

app.put(
  "/api/profile",
  requireLogin,
  (req, res) => {
    try {
      const user =
        req.user;

      const name =
        cleanText(
          req.body.name,
          80
        );

      const mobile =
        normalizeMobile(
          req.body.mobile
        );

      const city =
        cleanText(
          req.body.city,
          80
        );

      if (
        !name ||
        !city
      ) {
        return res.status(400).json({
          error:
            "Name and city are required."
        });
      }

      if (
        mobile &&
        !validMobile(mobile)
      ) {
        return res.status(400).json({
          error:
            "Please enter a valid mobile number."
        });
      }

      const mobileChanged =
        mobile !== user.mobile;

      if (
        mobileChanged &&
        mobile
      ) {
        const duplicate =
          db.users.find(
            u =>
              String(u.id) !==
                String(user.id) &&
              u.mobile ===
                mobile
          );

        if (duplicate) {
          return res.status(409).json({
            error:
              "This mobile number is already registered."
          });
        }

        user.mobile =
          mobile;

        user.mobileVerified =
          false;
      }

      user.name =
        name;

      user.city =
        city;

      saveDB(db);

      res.json({
        message:
          "Profile saved successfully.",

        user:
          publicUser(user)
      });
    } catch (error) {
      res.status(500).json({
        error:
          "Unable to save profile."
      });
    }
  }
);

/* =====================================================
   TASKS
===================================================== */

app.get(
  "/api/tasks",
  requireLogin,
  (req, res) => {
    res.json(
      db.tasks
        .filter(
          task =>
            task.active !==
            false
        )
        .map(
          task => ({
            id:
              task.id,

            title:
              task.title,

            description:
              task.description,

            type:
              task.type,

            reward:
              Number(
                task.reward
              ) || 0
          })
        )
    );
  }
);

/* =====================================================
   SUBMIT TASK
===================================================== */

app.post(
  "/api/tasks/:id/submit",
  requireLogin,
  (req, res) => {
    const taskId =
      Number(
        req.params.id
      );

    const task =
      db.tasks.find(
        t =>
          Number(t.id) ===
            taskId &&
          t.active !==
            false
      );

    if (!task) {
      return res.status(404).json({
        error:
          "Task not found."
      });
    }

    const existing =
      db.submissions.find(
        submission =>
          String(
            submission.userId
          ) ===
            String(
              req.user.id
            ) &&
          Number(
            submission.taskId
          ) === taskId &&
          submission.status ===
            "pending"
      );

    if (existing) {
      return res.status(409).json({
        error:
          "You already submitted this task and it is under review."
      });
    }

    db.submissions.push({
      id:
        crypto.randomUUID(),

      userId:
        req.user.id,

      taskId:
        task.id,

      taskTitle:
        task.title,

      reward:
        Number(
          task.reward
        ) || 0,

      status:
        "pending",

      submittedAt:
        new Date().toISOString()
    });

    saveDB(db);

    res.json({
      message:
        "Task submitted for review successfully."
    });
  }
);

/* =====================================================
   MY SUBMISSIONS
===================================================== */

app.get(
  "/api/my-submissions",
  requireLogin,
  (req, res) => {
    res.json(
      db.submissions
        .filter(
          submission =>
            String(
              submission.userId
            ) ===
            String(
              req.user.id
            )
        )
        .sort(
          (a, b) =>
            new Date(
              b.submittedAt
            ) -
            new Date(
              a.submittedAt
            )
        )
    );
  }
);

/* =====================================================
   WALLET
===================================================== */

app.get(
  "/api/wallet",
  requireLogin,
  (req, res) => {
    const withdrawals =
      db.withdrawals
        .filter(
          withdrawal =>
            String(
              withdrawal.userId
            ) ===
            String(
              req.user.id
            )
        )
        .sort(
          (a, b) =>
            new Date(
              b.createdAt
            ) -
            new Date(
              a.createdAt
            )
        );

    res.json({
      balance:
        Number(
          req.user.balance
        ) || 0,

      withdrawals
    });
  }
);

/* =====================================================
   SEND MOBILE OTP
   BEFORE WITHDRAWAL
===================================================== */

app.post(
  "/api/withdrawal/send-mobile-otp",
  requireLogin,
  async (req, res) => {
    try {
      const user =
        req.user;

      if (!user.mobile) {
        return res.status(400).json({
          error:
            "Please add a mobile number in your profile before withdrawal."
        });
      }

      if (
        user.mobileVerified
      ) {
        return res.json({
          alreadyVerified:
            true,

          message:
            "Mobile number is already verified."
        });
      }

      req.session.withdrawalVerification = {
        userId:
          user.id,

        purpose:
          "withdrawal"
      };

      await sendOtpFor(
        user,
        "mobile",
        "withdrawal",
        false
      );

      res.json({
        verificationRequired:
          true,

        mobile:
          user.mobile,

        message:
          "Mobile verification OTP sent successfully."
      });
    } catch (error) {
      console.error(
        "Withdrawal mobile OTP:",
        error
      );

      res.status(400).json({
        error:
          error.message ||
          "Unable to send mobile verification OTP."
      });
    }
  }
);

/* =====================================================
   VERIFY MOBILE OTP
===================================================== */

app.post(
  "/api/withdrawal/verify-mobile-otp",
  requireLogin,
  async (req, res) => {
    try {
      const verification =
        req.session
          .withdrawalVerification;

      if (
        !verification ||
        String(
          verification.userId
        ) !==
          String(
            req.user.id
          )
      ) {
        return res.status(400).json({
          error:
            "Please request a new mobile verification OTP."
        });
      }

      const otp =
        cleanText(
          req.body.otp,
          6
        );

      if (
        !/^\d{6}$/.test(otp)
      ) {
        return res.status(400).json({
          error:
            "Please enter the 6-digit OTP."
        });
      }

      const record =
        getOtpRecord(
          req.user.id,
          "mobile",
          "withdrawal"
        );

      if (!record) {
        return res.status(400).json({
          error:
            "OTP not found. Please request a new OTP."
        });
      }

      if (
        Date.now() >
        new Date(
          record.expiresAt
        ).getTime()
      ) {
        deleteOtpRecord(
          req.user.id,
          "mobile",
          "withdrawal"
        );

        return res.status(400).json({
          error:
            "OTP has expired. Please request a new OTP."
        });
      }

      if (
        record.attempts >=
        OTP_MAX_ATTEMPTS
      ) {
        deleteOtpRecord(
          req.user.id,
          "mobile",
          "withdrawal"
        );

        return res.status(429).json({
          error:
            "Too many incorrect attempts. Please request a new OTP."
        });
      }

      if (
        !safeCompare(
          record.otpHash,
          hashOtp(otp)
        )
      ) {
        record.attempts++;

        saveDB(db);

        return res.status(401).json({
          error:
            "Incorrect OTP."
        });
      }

      deleteOtpRecord(
        req.user.id,
        "mobile",
        "withdrawal"
      );

      req.user.mobileVerified =
        true;

      saveDB(db);

      delete req.session
        .withdrawalVerification;

      res.json({
        verified:
          true,

        user:
          publicUser(
            req.user
          ),

        message:
          "Mobile number verified successfully."
      });
    } catch (error) {
      console.error(
        "Mobile OTP verification:",
        error
      );

      res.status(500).json({
        error:
          error.message ||
          "Unable to verify mobile number."
      });
    }
  }
);

/* =====================================================
   RESEND MOBILE OTP
===================================================== */

app.post(
  "/api/withdrawal/resend-mobile-otp",
  requireLogin,
  async (req, res) => {
    try {
      if (
        req.user.mobileVerified
      ) {
        return res.json({
          alreadyVerified:
            true
        });
      }

      if (
        !req.user.mobile
      ) {
        return res.status(400).json({
          error:
            "Please add a mobile number first."
        });
      }

      req.session.withdrawalVerification = {
        userId:
          req.user.id,

        purpose:
          "withdrawal"
      };

      await sendOtpFor(
        req.user,
        "mobile",
        "withdrawal",
        false
      );

      res.json({
        message:
          "A new mobile OTP has been sent."
      });
    } catch (error) {
      res.status(400).json({
        error:
          error.message ||
          "Unable to resend mobile OTP."
      });
    }
  }
);

/* =====================================================
   WITHDRAWAL
===================================================== */

app.post(
  "/api/withdraw",
  requireLogin,
  (req, res) => {
    try {
      if (
        !req.user.mobileVerified
      ) {
        return res.status(403).json({
          error:
            "Please verify your mobile number before requesting a withdrawal."
        });
      }

      const amount =
        Number(
          req.body.amount
        );

      const method =
        cleanText(
          req.body.method,
          30
        );

      const details =
        req.body.paymentDetails ||
        {};

      if (
        !Number.isFinite(
          amount
        ) ||
        amount < 100
      ) {
        return res.status(400).json({
          error:
            "Minimum withdrawal amount is ₹100."
        });
      }

      if (
        amount >
        Number(
          req.user.balance ||
            0
        )
      ) {
        return res.status(400).json({
          error:
            "Insufficient wallet balance."
        });
      }

      if (
        method !== "UPI" &&
        method !==
          "Bank Account"
      ) {
        return res.status(400).json({
          error:
            "Please select a valid payment method."
        });
      }

      let paymentDetails;

      if (
        method === "UPI"
      ) {
        const upiId =
          cleanText(
            details.upiId,
            100
          );

        if (
          !/^[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+$/.test(
            upiId
          )
        ) {
          return res.status(400).json({
            error:
              "Please enter a valid UPI ID."
          });
        }

        paymentDetails = {
          upiId
        };
      } else {
        const accountHolderName =
          cleanText(
            details.accountHolderName,
            100
          );

        const accountNumber =
          cleanText(
            details.accountNumber,
            40
          );

        const ifscCode =
          cleanText(
            details.ifscCode,
            20
          ).toUpperCase();

        const bankName =
          cleanText(
            details.bankName,
            100
          );

        if (
          !accountHolderName ||
          !accountNumber ||
          !ifscCode ||
          !bankName
        ) {
          return res.status(400).json({
            error:
              "Please complete all bank account details."
          });
        }

        if (
          !/^[A-Z]{4}0[A-Z0-9]{6}$/.test(
            ifscCode
          )
        ) {
          return res.status(400).json({
            error:
              "Please enter a valid IFSC code."
          });
        }

        paymentDetails = {
          accountHolderName,
          accountNumber,
          ifscCode,
          bankName
        };
      }

      req.user.balance =
        Number(
          req.user.balance ||
            0
        ) - amount;

      db.withdrawals.push({
        id:
          crypto.randomUUID(),

        userId:
          req.user.id,

        amount,

        method,

        paymentDetails,

        status:
          "pending",

        createdAt:
          new Date().toISOString()
      });

      saveDB(db);

      res.json({
        message:
          "Withdrawal request submitted successfully."
      });
    } catch (error) {
      console.error(
        "Withdrawal error:",
        error
      );

      res.status(500).json({
        error:
          "Unable to submit withdrawal."
      });
    }
  }
);

/* =====================================================
   HEALTH
===================================================== */

app.get(
  "/api/health",
  (req, res) => {
    res.json({
      status:
        "ok",

      service:
        "TaskEarn",

      time:
        new Date().toISOString()
    });
  }
);

/* =====================================================
   API 404
===================================================== */

app.use(
  "/api",
  (req, res) => {
    res.status(404).json({
      error:
        "API endpoint not found."
    });
  }
);

/* =====================================================
   ERROR HANDLER
===================================================== */

app.use(
  (err, req, res, next) => {
    console.error(
      "Server error:",
      err
    );

    if (
      res.headersSent
    ) {
      return next(err);
    }

    res.status(500).json({
      error:
        "Internal server error."
    });
  }
);

/* =====================================================
   START SERVER
===================================================== */

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `TaskEarn server running on port ${PORT}`
    );

    console.log(
      `Gmail OTP configured: ${
        GMAIL_USER &&
        GMAIL_APP_PASSWORD
          ? "YES"
          : "NO"
      }`
    );

    console.log(
      `Google Login configured: ${
        GOOGLE_CLIENT_ID
          ? "YES"
          : "NO"
      }`
    );

    console.log(
      `Mobile OTP configured: ${
        process.env.TWILIO_ACCOUNT_SID &&
        process.env.TWILIO_AUTH_TOKEN &&
        process.env.TWILIO_PHONE_NUMBER
          ? "YES"
          : "NO"
      }`
    );

    console.log(
      "Resend: DISABLED — Gmail SMTP is the only email OTP sender."
    );
  }
);
