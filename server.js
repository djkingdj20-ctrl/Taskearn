const express = require("express");
const session = require("express-session");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");

const app = express();

app.set("trust proxy", 1);
app.get("/api/google-config", (req, res) => {
  res.json({
    clientId:
      process.env.GOOGLE_CLIENT_ID || ""
  });
});
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true, limit: "100kb" }));

/* =====================================================
   DATABASE
===================================================== */

const DATA_DIR = path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "database.json");

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

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
    });

    return database;
  } catch (error) {
    console.error("Database load error:", error);

    const database = defaultDatabase();

    try {
      saveDB(database);
    } catch (saveError) {
      console.error("Database recovery error:", saveError);
    }

    return database;
  }
}

let db = loadDB();

/* =====================================================
   SESSION
===================================================== */

const sessionSecret =
  process.env.SESSION_SECRET ||
  "CHANGE_THIS_TASKEARN_SECRET_2026";

app.use(
  session({
    secret: sessionSecret,

    resave: false,

    saveUninitialized: false,

    cookie: {
      httpOnly: true,
      sameSite: "lax",

      secure:
        process.env.NODE_ENV === "production",

      maxAge:
        1000 *
        60 *
        60 *
        24 *
        30
    }
  })
);

/* =====================================================
   HELPERS
===================================================== */

function cleanText(value, maxLength = 200) {
  return String(value || "")
    .trim()
    .slice(0, maxLength);
}

function normalizeEmail(value) {
  return cleanText(value, 160).toLowerCase();
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function normalizeMobile(value) {
  return cleanText(value, 20).replace(
    /[\s()-]/g,
    ""
  );
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
    createdAt: user.createdAt
  };
}

function findUserById(id) {
  return db.users.find(
    (user) =>
      String(user.id) === String(id)
  );
}

function currentUser(req) {
  if (!req.session.userId) {
    return null;
  }

  return findUserById(
    req.session.userId
  );
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

/* =====================================================
   OTP SETTINGS
===================================================== */

const OTP_EXPIRY_MS =
  10 * 60 * 1000;

const OTP_RESEND_MS =
  60 * 1000;

const OTP_MAX_ATTEMPTS = 5;

/* =====================================================
   EMAIL OTP
===================================================== */

async function sendEmailOtp(
  email,
  otp,
  purpose
) {
  const apiKey =
    process.env.RESEND_API_KEY;

  const from =
    process.env.EMAIL_FROM;

  if (!apiKey || !from) {
    throw new Error(
      "Email verification service is not configured. Please contact the administrator."
    );
  }

  const subject =
    purpose === "login"
      ? "TaskEarn Login Verification Code"
      : "TaskEarn Email Verification Code";

  const html = `
    <div style="
      font-family:Arial,sans-serif;
      max-width:600px;
      margin:auto;
      padding:25px;
      color:#171b2d;
    ">
      <h2>TaskEarn Email Verification</h2>

      <p>Your TaskEarn verification code is:</p>

      <div style="
        font-size:32px;
        font-weight:900;
        letter-spacing:8px;
        margin:20px 0;
      ">
        ${otp}
      </div>

      <p>This code expires in 10 minutes.</p>

      <p>
        If you did not request this code,
        you can safely ignore this email.
      </p>
    </div>
  `;

  const response = await fetch(
    "https://api.resend.com/emails",
    {
      method: "POST",

      headers: {
        Authorization:
          "Bearer " + apiKey,

        "Content-Type":
          "application/json"
      },

      body: JSON.stringify({
        from,
        to: [email],
        subject,
        html
      })
    }
  );

  if (!response.ok) {
    const text =
      await response.text();

    console.error(
      "Resend error:",
      text
    );

    throw new Error(
      "Unable to send email verification code."
    );
  }
}

/* =====================================================
   SMS OTP
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

  if (!sid || !token || !from) {
    throw new Error(
      "Mobile verification service is not configured. Please contact the administrator."
    );
  }

  const auth =
    Buffer.from(
      sid + ":" + token
    ).toString("base64");

  const params =
    new URLSearchParams();

  params.append("To", mobile);

  params.append(
    "From",
    from
  );

  params.append(
    "Body",
    `TaskEarn verification code: ${otp}. This code expires in 10 minutes.`
  );

  const response = await fetch(
    `https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(
      sid
    )}/Messages.json`,
    {
      method: "POST",

      headers: {
        Authorization:
          "Basic " + auth,

        "Content-Type":
          "application/x-www-form-urlencoded"
      },

      body: params.toString()
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
      "Unable to send mobile verification code."
    );
  }
}

/* =====================================================
   OTP RECORDS
===================================================== */

function createOtpRecord(
  user,
  type,
  purpose
) {
  const otp = randomOtp();
  const now = Date.now();

  const record = {
    userId: user.id,

    type,

    purpose,

    otpHash:
      hashOtp(otp),

    createdAt:
      new Date(now).toISOString(),

    expiresAt:
      new Date(
        now + OTP_EXPIRY_MS
      ).toISOString(),

    attempts: 0,

    lastSentAt:
      new Date(now).toISOString()
  };

  db.otpCodes =
    (db.otpCodes || []).filter(
      (item) =>
        !(
          String(item.userId) ===
            String(user.id) &&
          item.type === type &&
          item.purpose === purpose
        )
    );

  db.otpCodes.push(record);

  saveDB(db);

  return otp;
}

function getOtpRecord(
  userId,
  type,
  purpose
) {
  db.otpCodes ||= [];

  return db.otpCodes
    .filter(
      (item) =>
        String(item.userId) ===
          String(userId) &&
        item.type === type &&
        item.purpose === purpose
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
    (db.otpCodes || []).filter(
      (item) =>
        !(
          String(item.userId) ===
            String(userId) &&
          item.type === type &&
          item.purpose === purpose
        )
    );

  saveDB(db);
}

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

  if (existing && !force) {
    const lastSent =
      new Date(
        existing.lastSentAt
      ).getTime();

    if (
      Date.now() -
        lastSent <
      OTP_RESEND_MS
    ) {
      const remaining =
        Math.ceil(
          (
            OTP_RESEND_MS -
            (
              Date.now() -
              lastSent
            )
          ) / 1000
        );

      throw new Error(
        `Please wait ${remaining} seconds before requesting another OTP.`
      );
    }
  }

  const otp =
    createOtpRecord(
      user,
      type,
      purpose
    );

  if (type === "email") {
    await sendEmailOtp(
      user.email,
      otp,
      purpose
    );
  } else {
    await sendSmsOtp(
      user.mobile,
      otp
    );
  }
}

/* =====================================================
   VERIFICATION FLOW
===================================================== */

async function startVerification(
  req,
  user,
  purpose
) {
  req.session.verification = {
    userId: user.id,
    purpose,
    emailVerified:
      Boolean(user.emailVerified),
    mobileVerified:
      Boolean(user.mobileVerified),
    createdAt: Date.now()
  };

  if (!user.emailVerified) {
    await sendOtpFor(
      user,
      "email",
      purpose,
      true
    );

    req.session.verification.step =
      "email";

    return "email";
  }

  if (!user.mobileVerified) {
    await sendOtpFor(
      user,
      "mobile",
      purpose,
      true
    );

    req.session.verification.step =
      "mobile";

    return "mobile";
  }

  return "complete";
}

function completeLogin(
  req,
  user,
  remember
) {
  req.session.userId =
    user.id;

  delete req.session.verification;

  delete req.session.remember;

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
   GOOGLE SIGN-IN
===================================================== */

async function verifyGoogleIdToken(
  idToken
) {
  const clientId =
    process.env.GOOGLE_CLIENT_ID;

  if (!clientId) {
    throw new Error(
      "Google Sign-In is not configured. Please add GOOGLE_CLIENT_ID."
    );
  }

  if (!idToken) {
    throw new Error(
      "Google authentication token is missing."
    );
  }

  const url =
    "https://oauth2.googleapis.com/tokeninfo?id_token=" +
    encodeURIComponent(idToken);

  const response =
    await fetch(url);

  if (!response.ok) {
    throw new Error(
      "Invalid Google authentication token."
    );
  }

  const data =
    await response.json();

  if (
    data.aud !== clientId
  ) {
    throw new Error(
      "Google client ID does not match."
    );
  }

  if (
    data.email_verified !==
      "true" &&
    data.email_verified !==
      true
  ) {
    throw new Error(
      "Your Google email is not verified."
    );
  }

  if (!validEmail(data.email)) {
    throw new Error(
      "Google account email is invalid."
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

/* =====================================================
   GOOGLE LOGIN / REGISTER
===================================================== */

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
          (u) =>
            u.googleId &&
            String(u.googleId) ===
              String(google.googleId)
        );

      if (!user) {
        user =
          db.users.find(
            (u) =>
              normalizeEmail(
                u.email
              ) === google.email
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
          !user.profileImage &&
          google.picture
        ) {
          user.profileImage =
            google.picture;
        }

        if (
          !user.name &&
          google.name
        ) {
          user.name =
            google.name;
        }
      }

      saveDB(db);

      /*
        Google has already verified
        the Gmail address.

        We therefore do NOT ask for
        Email OTP again.

        We also do NOT force mobile OTP
        for Google login.
      */

      completeLogin(
        req,
        user,
        true
      );

      return res.json({
        success:
          true,

        message:
          "Google login successful.",

        user:
          publicUser(user)
      });
    } catch (error) {
      console.error(
        "Google authentication error:",
        error
      );

      return res.status(401).json({
        error:
          error.message ||
          "Google login failed."
      });
    }
  }
);

/* =====================================================
   BASIC ROUTES
===================================================== */

app.get("/", (req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      "public",
      "index.html"
    )
  );
});

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

      if (!validEmail(email)) {
        return res.status(400).json({
          error:
            "Please enter a valid email address."
        });
      }

      if (!validMobile(mobile)) {
        return res.status(400).json({
          error:
            "Please enter a valid mobile number."
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          error:
            "Password must contain at least 6 characters."
        });
      }

      const existingEmail =
        db.users.find(
          (u) =>
            normalizeEmail(
              u.email
            ) === email
        );

      if (existingEmail) {
        return res.status(409).json({
          error:
            "An account with this email already exists. Please login with Google or your password."
        });
      }

      const existingMobile =
        db.users.find(
          (u) =>
            u.mobile === mobile
        );

      if (existingMobile) {
        return res.status(409).json({
          error:
            "This mobile number is already registered."
        });
      }

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      const user = {
        id:
          crypto.randomUUID(),

        name,

        email,

        passwordHash,

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

      req.session.remember =
        Boolean(
          req.body.remember
        );

      const step =
        await startVerification(
          req,
          user,
          "register"
        );

      return res.json({
        verificationRequired:
          true,

        step,

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

      return res.status(500).json({
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

      if (!email || !password) {
        return res.status(400).json({
          error:
            "Please enter email and password."
        });
      }

      const user =
        db.users.find(
          (u) =>
            normalizeEmail(
              u.email
            ) === email
        );

      if (!user) {
        return res.status(401).json({
          error:
            "Invalid email or password."
        });
      }

      /*
        Google-only account does not have
        a local password.
      */

      if (!user.passwordHash) {
        return res.status(401).json({
          error:
            "This account uses Google Sign-In. Please continue with Google."
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

      req.session.remember =
        remember;

      const step =
        await startVerification(
          req,
          user,
          "login"
        );

      if (
        step ===
        "complete"
      ) {
        completeLogin(
          req,
          user,
          remember
        );

        return res.json({
          user:
            publicUser(user)
        });
      }

      return res.json({
        verificationRequired:
          true,

        step,

        email:
          user.email,

        mobile:
          user.mobile
      });
    } catch (error) {
      console.error(
        "Login error:",
        error
      );

      return res.status(500).json({
        error:
          error.message ||
          "Unable to login."
      });
    }
  }
);

/* =====================================================
   VERIFY OTP
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
        !/^\d{6}$/.test(
          otp
        )
      ) {
        return res.status(400).json({
          error:
            "Please enter the 6-digit OTP."
        });
      }

      const step =
        verification.step;

      const record =
        getOtpRecord(
          user.id,
          step,
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
          step,
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
          step,
          verification.purpose
        );

        return res.status(429).json({
          error:
            "Too many incorrect attempts. Please request a new OTP."
        });
      }

      const valid =
        safeCompare(
          record.otpHash,
          hashOtp(otp)
        );

      if (!valid) {
        record.attempts++;

        saveDB(db);

        return res.status(401).json({
          error:
            "Incorrect OTP."
        });
      }

      deleteOtpRecord(
        user.id,
        step,
        verification.purpose
      );

      if (step === "email") {
        user.emailVerified =
          true;
      } else {
        user.mobileVerified =
          true;
      }

      saveDB(db);

      if (
        step === "email" &&
        !user.mobileVerified
      ) {
        await sendOtpFor(
          user,
          "mobile",
          verification.purpose,
          true
        );

        verification.emailVerified =
          true;

        verification.mobileVerified =
          false;

        verification.step =
          "mobile";

        req.session.verification =
          verification;

        return res.json({
          step:
            "mobile",

          email:
            user.email,

          mobile:
            user.mobile
        });
      }

      completeLogin(
        req,
        user,
        Boolean(
          req.session.remember
        )
      );

      saveDB(db);

      return res.json({
        step:
          "complete",

        user:
          publicUser(user)
      });
    } catch (error) {
      console.error(
        "Verify OTP error:",
        error
      );

      return res.status(500).json({
        error:
          error.message ||
          "Unable to verify OTP."
      });
    }
  }
);

/* =====================================================
   RESEND OTP
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

      await sendOtpFor(
        user,
        verification.step,
        verification.purpose,
        false
      );

      return res.json({
        message:
          verification.step ===
          "email"
            ? "A new email OTP has been sent."
            : "A new mobile OTP has been sent."
      });
    } catch (error) {
      console.error(
        "Resend OTP error:",
        error
      );

      return res.status(400).json({
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
    const user =
      currentUser(req);

    return res.json(
      publicUser(user)
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
      (error) => {
        if (error) {
          console.error(
            "Logout error:",
            error
          );

          return res.status(500).json({
            error:
              "Unable to logout."
          });
        }

        res.clearCookie(
          "connect.sid"
        );

        return res.json({
          message:
            "Logged out successfully."
        });
      }
    );
  }
);

/* =====================================================
   PROFILE UPDATE
===================================================== */

app.put(
  "/api/profile",
  requireLogin,
  async (req, res) => {
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

      const profileImage =
        String(
          req.body.profileImage ||
          ""
        );

      if (!name) {
        return res.status(400).json({
          error:
            "Name cannot be empty."
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

      if (!city) {
        return res.status(400).json({
          error:
            "City cannot be empty."
        });
      }

      if (
        profileImage.length >
        1500000
      ) {
        return res.status(400).json({
          error:
            "Profile image is too large."
        });
      }

      const mobileChanged =
        mobile !== user.mobile;

      if (mobileChanged) {
        if (!mobile) {
          user.mobile =
            "";

          user.mobileVerified =
            false;
        } else {
          const duplicate =
            db.users.find(
              (u) =>
                String(u.id) !==
                  String(user.id) &&
                u.mobile === mobile
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
      }

      user.name =
        name;

      user.city =
        city;

      user.profileImage =
        profileImage;

      saveDB(db);

      if (
        mobileChanged &&
        user.mobile &&
        !user.mobileVerified
      ) {
        req.session.profileVerification =
          {
            userId:
              user.id,

            step:
              "mobile",

            purpose:
              "profile"
          };

        try {
          await sendOtpFor(
            user,
            "mobile",
            "profile",
            true
          );
        } catch (error) {
          console.error(
            "Profile mobile OTP error:",
            error
          );

          return res.status(503).json({
            error:
              "Mobile number changed, but verification SMS could not be sent."
          });
        }

        return res.json({
          verificationRequired:
            true,

          step:
            "mobile",

          message:
            "Profile saved. Please verify your new mobile number."
        });
      }

      return res.json({
        message:
          "Profile saved successfully.",

        user:
          publicUser(user)
      });
    } catch (error) {
      console.error(
        "Profile update error:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to save profile."
      });
    }
  }
);

/* =====================================================
   PROFILE MOBILE OTP VERIFICATION
===================================================== */

app.post(
  "/api/profile/verify-otp",
  requireLogin,
  async (req, res) => {
    try {
      const verification =
        req.session.profileVerification;

      if (!verification) {
        return res.status(400).json({
          error:
            "Profile verification session expired."
        });
      }

      if (
        String(
          verification.userId
        ) !==
        String(req.user.id)
      ) {
        return res.status(403).json({
          error:
            "Invalid verification session."
        });
      }

      const otp =
        cleanText(
          req.body.otp,
          6
        );

      if (
        !/^\d{6}$/.test(
          otp
        )
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
          "profile"
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
          "profile"
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
          "profile"
        );

        return res.status(429).json({
          error:
            "Too many incorrect attempts. Please request a new OTP."
        });
      }

      const valid =
        safeCompare(
          record.otpHash,
          hashOtp(otp)
        );

      if (!valid) {
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
        "profile"
      );

      req.user.mobileVerified =
        true;

      saveDB(db);

      delete req.session.profileVerification;

      return res.json({
        message:
          "Mobile number verified successfully.",

        user:
          publicUser(req.user)
      });
    } catch (error) {
      console.error(
        "Profile OTP verification error:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to verify mobile number."
      });
    }
  }
);

/* =====================================================
   PROFILE MOBILE OTP RESEND
===================================================== */

app.post(
  "/api/profile/resend-otp",
  requireLogin,
  async (req, res) => {
    try {
      const verification =
        req.session.profileVerification;

      if (!verification) {
        return res.status(400).json({
          error:
            "Profile verification session expired."
        });
      }

      if (
        String(
          verification.userId
        ) !==
        String(req.user.id)
      ) {
        return res.status(403).json({
          error:
            "Invalid verification session."
        });
      }

      await sendOtpFor(
        req.user,
        "mobile",
        "profile",
        false
      );

      return res.json({
        message:
          "A new mobile OTP has been sent."
      });
    } catch (error) {
      console.error(
        "Profile OTP resend error:",
        error
      );

      return res.status(400).json({
        error:
          error.message ||
          "Unable to resend OTP."
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
    const tasks =
      db.tasks
        .filter(
          (t) =>
            t.active !== false
        )
        .map(
          (t) => ({
            id:
              t.id,

            title:
              t.title,

            description:
              t.description,

            type:
              t.type,

            reward:
              Number(
                t.reward
              ) || 0
          })
        );

    return res.json(tasks);
  }
);

/* =====================================================
   SUBMIT TASK
===================================================== */

app.post(
  "/api/tasks/:id/submit",
  requireLogin,
  (req, res) => {
    try {
      const taskId =
        Number(
          req.params.id
        );

      const task =
        db.tasks.find(
          (t) =>
            Number(t.id) ===
              taskId &&
            t.active !== false
        );

      if (!task) {
        return res.status(404).json({
          error:
            "Task not found."
        });
      }

      const alreadySubmitted =
        db.submissions.find(
          (s) =>
            String(s.userId) ===
              String(
                req.user.id
              ) &&
            Number(s.taskId) ===
              taskId &&
            s.status ===
              "pending"
        );

      if (alreadySubmitted) {
        return res.status(409).json({
          error:
            "You already submitted this task and it is under review."
        });
      }

      const submission = {
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
      };

      db.submissions.push(
        submission
      );

      saveDB(db);

      return res.json({
        message:
          "Task submitted for review successfully."
      });
    } catch (error) {
      console.error(
        "Submit task error:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to submit task."
      });
    }
  }
);

/* =====================================================
   MY SUBMISSIONS
===================================================== */

app.get(
  "/api/my-submissions",
  requireLogin,
  (req, res) => {
    const submissions =
      db.submissions
        .filter(
          (s) =>
            String(s.userId) ===
            String(req.user.id)
        )
        .sort(
          (a, b) =>
            new Date(
              b.submittedAt
            ) -
            new Date(
              a.submittedAt
            )
        );

    return res.json(
      submissions
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
    const user =
      req.user;

    const completed =
      db.submissions.filter(
        (s) =>
          String(s.userId) ===
            String(user.id) &&
          s.status ===
            "approved"
      ).length;

    const withdrawals =
      db.withdrawals
        .filter(
          (w) =>
            String(w.userId) ===
            String(user.id)
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

    return res.json({
      balance:
        Number(
          user.balance || 0
        ),

      completed,

      withdrawals
    });
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
        )
      ) {
        return res.status(400).json({
          error:
            "Invalid amount."
        });
      }

      if (amount < 100) {
        return res.status(400).json({
          error:
            "Minimum withdrawal amount is ₹100."
        });
      }

      if (
        amount >
        Number(
          req.user.balance || 0
        )
      ) {
        return res.status(400).json({
          error:
            "Insufficient wallet balance."
        });
      }

      if (
        method !== "UPI" &&
        method !== "Bank Account"
      ) {
        return res.status(400).json({
          error:
            "Please select a valid payment method."
        });
      }

      let paymentDetails;

      if (method === "UPI") {
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
          req.user.balance || 0
        ) - amount;

      const withdrawal = {
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
      };

      db.withdrawals.push(
        withdrawal
      );

      saveDB(db);

      return res.json({
        message:
          "Withdrawal request submitted successfully."
      });
    } catch (error) {
      console.error(
        "Withdrawal error:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to submit withdrawal."
      });
    }
  }
);

/* =====================================================
   HEALTH CHECK
===================================================== */

app.get(
  "/api/health",
  (req, res) => {
    return res.json({
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
   ERROR HANDLER
===================================================== */

app.use(
  (
    err,
    req,
    res,
    next
  ) => {
    console.error(
      "Server error:",
      err
    );

    if (res.headersSent) {
      return next(err);
    }

    return res.status(500).json({
      error:
        "Internal server error."
    });
  }
);

/* =====================================================
   SERVER
===================================================== */

const PORT =
  process.env.PORT ||
  10000;

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `TaskEarn server running on port ${PORT}`
    );
  }
);
