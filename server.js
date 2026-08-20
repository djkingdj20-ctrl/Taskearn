require("dotenv").config();

const express = require("express");
const session = require("express-session");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { google } = require("googleapis");

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
  String(process.env.SESSION_SECRET || "").trim() ||
  "CHANGE_THIS_TASKEARN_SECRET_2026";

const GMAIL_USER =
  String(process.env.GMAIL_USER || "").trim();

const EMAIL_FROM =
  String(process.env.EMAIL_FROM || GMAIL_USER).trim();

const GOOGLE_CLIENT_ID =
  String(process.env.GOOGLE_CLIENT_ID || "").trim();

const GOOGLE_CLIENT_SECRET =
  String(process.env.GOOGLE_CLIENT_SECRET || "").trim();

const GOOGLE_REFRESH_TOKEN =
  String(process.env.GOOGLE_REFRESH_TOKEN || "").trim();

/*
   IMPORTANT
   --------------------------------------------------
   This secret is used to authenticate server-to-server
   reward confirmation requests.

   Do NOT put this value in frontend JavaScript.
*/
const AD_REWARD_SECRET =
  String(process.env.AD_REWARD_SECRET || "").trim();

/*
   Reward configuration
*/
const AD_REWARD_POINTS =
  Number(process.env.AD_REWARD_POINTS) || 10;

const DAILY_AD_LIMIT =
  Number(process.env.DAILY_AD_LIMIT) || 10;

const DAILY_POINT_LIMIT =
  AD_REWARD_POINTS * DAILY_AD_LIMIT;

const REWARD_RATE_WINDOW_MS =
  60 * 1000;

const REWARD_RATE_MAX =
  5;

const GOOGLE_CLIENT_ID_FOR_LOGIN =
  GOOGLE_CLIENT_ID;

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
        title: "Watch Ad",
        description:
          "Watch one rewarded advertisement and receive TaskEarn Points after the reward is confirmed.",
        type: "Rewarded Ad",
        reward: AD_REWARD_POINTS,
        active: true,
        rewardType: "ad"
      },

      {
        id: 2,
        title: "Complete a simple online task",
        description:
          "Complete the instructions carefully and submit the task for review.",
        type: "General",
        reward: 10,
        active: true,
        rewardType: "task"
      },

      {
        id: 3,
        title: "Social Media Engagement",
        description:
          "Complete the specified social media activity and submit your task.",
        type: "Social",
        reward: 15,
        active: true,
        rewardType: "task"
      },

      {
        id: 4,
        title: "Website Visit Task",
        description:
          "Visit the required website and complete the provided instructions.",
        type: "Website",
        reward: 20,
        active: true,
        rewardType: "task"
      }
    ],

    submissions: [],

    /*
      Legacy withdrawal records are retained so old data
      does not break, but the rewarded-ad points system
      does NOT add money to the withdrawal balance.
    */
    withdrawals: [],

    /*
      Legacy OTP records.
    */
    otpCodes: [],

    /*
      TaskEarn Points ledger.
    */
    pointTransactions: [],

    /*
      Reward event records.

      One provider event ID can only be processed once.
    */
    adRewards: [],

    /*
      Suspicious reward activity.
    */
    suspiciousActivity: [],

    /*
      Temporary server-issued reward sessions.
    */
    rewardSessions: []
  };
}

function saveDB(database) {
  const tempFile = DB_FILE + ".tmp";

  fs.writeFileSync(
    tempFile,
    JSON.stringify(database, null, 2),
    "utf8"
  );

  fs.renameSync(
    tempFile,
    DB_FILE
  );
}

function loadDB() {
  try {
    if (!fs.existsSync(DB_FILE)) {
      const database = defaultDatabase();

      saveDB(database);

      return database;
    }

    const raw =
      fs.readFileSync(
        DB_FILE,
        "utf8"
      );

    if (!raw.trim()) {
      const database = defaultDatabase();

      saveDB(database);

      return database;
    }

    const database =
      JSON.parse(raw);

    database.users ||= [];
    database.tasks ||= [];
    database.submissions ||= [];
    database.withdrawals ||= [];
    database.otpCodes ||= [];
    database.pointTransactions ||= [];
    database.adRewards ||= [];
    database.suspiciousActivity ||= [];
    database.rewardSessions ||= [];

    database.users.forEach(user => {
      user.mobile ??= "";
      user.city ??= "";
      user.profileImage ??= "";

      user.emailVerified ??= false;
      user.mobileVerified ??= false;

      user.googleId ??= "";

      user.authProvider ??=
        user.googleId
          ? "google"
          : "local";

      /*
        New Points balance.

        We intentionally do not automatically convert
        old wallet money into Points.
      */
      user.points ??= 0;

      /*
        Keep old balance for compatibility with existing
        database data. It is NOT used for ad rewards.
      */
      user.balance ??= 0;

      user.role ??= "Member";
      user.passwordHash ??= "";
    });

    database.tasks.forEach(task => {
      task.active ??= true;
      task.rewardType ??=
        task.type === "Rewarded Ad"
          ? "ad"
          : "task";
    });

    return database;

  } catch (error) {
    console.error(
      "Database error:",
      error
    );

    const database =
      defaultDatabase();

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
    secret:
      SESSION_SECRET,

    resave:
      false,

    saveUninitialized:
      false,

    cookie: {
      httpOnly:
        true,

      sameSite:
        "lax",

      secure:
        process.env.NODE_ENV ===
        "production",

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
   GENERAL HELPERS
===================================================== */

function cleanText(
  value,
  max = 200
) {
  return String(
    value ?? ""
  )
    .trim()
    .slice(0, max);
}

function normalizeEmail(value) {
  return cleanText(
    value,
    160
  ).toLowerCase();
}

function normalizeMobile(value) {
  return cleanText(
    value,
    20
  ).replace(
    /[\s()-]/g,
    ""
  );
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
    email
  );
}

function validMobile(mobile) {
  return /^\+?[0-9]{7,15}$/.test(
    mobile
  );
}

function publicUser(user) {
  if (!user) {
    return null;
  }

  return {
    id:
      user.id,

    name:
      user.name || "",

    email:
      user.email || "",

    role:
      user.role || "Member",

    mobile:
      user.mobile || "",

    city:
      user.city || "",

    profileImage:
      user.profileImage || "",

    emailVerified:
      Boolean(
        user.emailVerified
      ),

    mobileVerified:
      Boolean(
        user.mobileVerified
      ),

    authProvider:
      user.authProvider ||
      "local",

    /*
      Points are shown to the user.
    */
    points:
      Number(
        user.points || 0
      ),

    createdAt:
      user.createdAt
  };
}

function findUserById(id) {
  return db.users.find(
    user =>
      String(user.id) ===
      String(id)
  );
}

function currentUser(req) {
  return req.session.userId
    ? findUserById(
        req.session.userId
      )
    : null;
}

function requireLogin(
  req,
  res,
  next
) {
  const user =
    currentUser(req);

  if (!user) {
    return res.status(401).json({
      error:
        "Please login first."
    });
  }

  req.user =
    user;

  next();
}

function isAdmin(user) {
  return (
    user &&
    (
      user.role === "Admin" ||
      user.role === "admin"
    )
  );
}

function requireAdmin(
  req,
  res,
  next
) {
  const user =
    currentUser(req);

  if (!user) {
    return res.status(401).json({
      error:
        "Please login first."
    });
  }

  if (!isAdmin(user)) {
    return res.status(403).json({
      error:
        "Admin access required."
    });
  }

  req.user =
    user;

  next();
}

/* =====================================================
   POINT HELPERS
===================================================== */

function getPointsBalance(user) {
  return Number(
    user.points || 0
  );
}

function todayKey(
  date = new Date()
) {
  const year =
    date.getUTCFullYear();

  const month =
    String(
      date.getUTCMonth() + 1
    ).padStart(
      2,
      "0"
    );

  const day =
    String(
      date.getUTCDate()
    ).padStart(
      2,
      "0"
    );

  return `${year}-${month}-${day}`;
}

function getTodayAdRewards(userId) {
  const today =
    todayKey();

  return db.adRewards.filter(
    reward =>
      String(
        reward.userId
      ) ===
        String(userId) &&
      reward.status ===
        "credited" &&
      todayKey(
        new Date(
          reward.createdAt
        )
      ) ===
        today
  );
}

function getTodayAdRewardCount(userId) {
  return getTodayAdRewards(
    userId
  ).length;
}

function getTodayAdPoints(userId) {
  return getTodayAdRewards(
    userId
  ).reduce(
    (total, reward) =>
      total +
      Number(
        reward.points || 0
      ),
    0
  );
}

function createPointTransaction({
  userId,
  type,
  points,
  source,
  taskId = null,
  adEventId = null,
  status = "completed",
  metadata = {}
}) {
  const transaction = {
    id:
      crypto.randomUUID(),

    userId,

    type,

    points:
      Number(points),

    source,

    taskId,

    adEventId,

    status,

    metadata,

    createdAt:
      new Date().toISOString()
  };

  db.pointTransactions.push(
    transaction
  );

  return transaction;
}

function creditPoints({
  user,
  points,
  source,
  taskId = null,
  adEventId = null,
  metadata = {}
}) {
  const amount =
    Number(points);

  if (
    !Number.isInteger(
      amount
    ) ||
    amount <= 0
  ) {
    throw new Error(
      "Invalid point amount."
    );
  }

  user.points =
    getPointsBalance(
      user
    ) +
    amount;

  const transaction =
    createPointTransaction({
      userId:
        user.id,

      type:
        "credit",

      points:
        amount,

      source,

      taskId,

      adEventId,

      metadata
    });

  return transaction;
}

/* =====================================================
   OTP
===================================================== */

const OTP_EXPIRY_MS =
  10 * 60 * 1000;

const OTP_RESEND_MS =
  60 * 1000;

const OTP_MAX_ATTEMPTS =
  5;

function randomOtp() {
  return String(
    crypto.randomInt(
      100000,
      1000000
    )
  );
}

function hashOtp(otp) {
  return crypto
    .createHash("sha256")
    .update(
      String(otp)
    )
    .digest("hex");
}

function safeCompare(
  a,
  b
) {
  const aa =
    Buffer.from(
      String(a)
    );

  const bb =
    Buffer.from(
      String(b)
    );

  if (
    aa.length !==
    bb.length
  ) {
    return false;
  }

  return crypto.timingSafeEqual(
    aa,
    bb
  );
}

function createOtpRecord(
  user,
  type,
  purpose
) {
  const otp =
    randomOtp();

  const now =
    Date.now();

  db.otpCodes =
    db.otpCodes.filter(
      record =>
        !(
          String(
            record.userId
          ) ===
            String(
              user.id
            ) &&
          record.type ===
            type &&
          record.purpose ===
            purpose
        )
    );

  db.otpCodes.push({
    userId:
      user.id,

    type,

    purpose,

    otpHash:
      hashOtp(otp),

    createdAt:
      new Date(
        now
      ).toISOString(),

    expiresAt:
      new Date(
        now +
          OTP_EXPIRY_MS
      ).toISOString(),

    attempts:
      0,

    lastSentAt:
      new Date(
        now
      ).toISOString()
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
        String(
          record.userId
        ) ===
          String(
            userId
          ) &&
        record.type ===
          type &&
        record.purpose ===
          purpose
    )
    .sort(
      (a, b) =>
        new Date(
          b.createdAt
        ) -
        new Date(
          a.createdAt
        )
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
          String(
            record.userId
          ) ===
            String(
              userId
            ) &&
          record.type ===
            type &&
          record.purpose ===
            purpose
        )
    );

  saveDB(db);
}

/* =====================================================
   GMAIL API
===================================================== */

let gmailClient = null;
let gmailApiConfigured = false;

function configureGmailApi() {
  if (
    !GMAIL_USER ||
    !GOOGLE_CLIENT_ID ||
    !GOOGLE_CLIENT_SECRET ||
    !GOOGLE_REFRESH_TOKEN
  ) {
    console.log(
      "Gmail API: NOT CONFIGURED"
    );

    gmailApiConfigured =
      false;

    gmailClient =
      null;

    return;
  }

  try {
    const oauth2Client =
      new google.auth.OAuth2(
        GOOGLE_CLIENT_ID,
        GOOGLE_CLIENT_SECRET,
        "https://developers.google.com/oauthplayground"
      );

    oauth2Client.setCredentials({
      refresh_token:
        GOOGLE_REFRESH_TOKEN
    });

    gmailClient =
      google.gmail({
        version: "v1",
        auth: oauth2Client
      });

    gmailApiConfigured =
      true;

    console.log(
      "Gmail API: CONFIGURED"
    );

  } catch (error) {
    gmailApiConfigured =
      false;

    gmailClient =
      null;

    console.error(
      "Gmail API configuration error:",
      error.message ||
        error
    );
  }
}

configureGmailApi();

/* =====================================================
   RFC 2047 / BASE64 GMAIL MESSAGE
===================================================== */

function createRawEmail({
  from,
  to,
  subject,
  text,
  html
}) {
  const boundary =
    "TaskEarnBoundary" +
    crypto
      .randomBytes(16)
      .toString("hex");

  const safeFrom =
    String(from)
      .replace(
        /[\r\n]/g,
        ""
      );

  const safeTo =
    String(to)
      .replace(
        /[\r\n]/g,
        ""
      );

  const safeSubject =
    String(subject)
      .replace(
        /[\r\n]/g,
        " "
      );

  const message = [
    `From: ${safeFrom}`,
    `To: ${safeTo}`,
    `Subject: ${safeSubject}`,
    "MIME-Version: 1.0",
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
    "",
    `--${boundary}`,
    'Content-Type: text/plain; charset="UTF-8"',
    "Content-Transfer-Encoding: 8bit",
    "",
    text,
    "",
    `--${boundary}`,
    'Content-Type: text/html; charset="UTF-8"',
    "Content-Transfer-Encoding: 8bit",
    "",
    html,
    "",
    `--${boundary}--`
  ].join("\r\n");

  return Buffer.from(
    message,
    "utf8"
  )
    .toString("base64")
    .replace(
      /\+/g,
      "-"
    )
    .replace(
      /\//g,
      "_"
    )
    .replace(
      /=+$/,
      ""
    );
}

/* =====================================================
   SEND EMAIL OTP
===================================================== */

async function sendEmailOtp(
  email,
  otp
) {
  if (
    !gmailApiConfigured ||
    !gmailClient
  ) {
    throw new Error(
      "Gmail API is not configured. Check GMAIL_USER, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET and GOOGLE_REFRESH_TOKEN."
    );
  }

  const text =
    `Your TaskEarn verification code is ${otp}. ` +
    `This OTP expires in 10 minutes.\n\n` +
    `If you did not request this code, please ignore this email.`;

  const html = `
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

<h1 style="color:#ff5d2e;">
TaskEarn
</h1>

<h2>Email Verification</h2>

<p>Hello,</p>

<p>Your TaskEarn verification code is:</p>

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
This OTP expires in
<strong>10 minutes</strong>.
</p>

<p>
If you did not request this code,
please ignore this email.
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
`;

  const raw =
    createRawEmail({
      from:
        EMAIL_FROM ||
        GMAIL_USER,

      to:
        email,

      subject:
        "TaskEarn Email Verification Code",

      text,

      html
    });

  try {
    const result =
      await gmailClient.users.messages.send({
        userId:
          "me",

        requestBody: {
          raw
        }
      });

    console.log(
      "Gmail API OTP sent successfully:",
      result.data.id,
      "to:",
      email
    );

    return result.data;

  } catch (error) {
    console.error(
      "Gmail API send error:"
    );

    console.error(
      error?.response?.data ||
      error?.message ||
      error
    );

    throw new Error(
      "Unable to send Gmail OTP. Please check Gmail API OAuth configuration and GOOGLE_REFRESH_TOKEN."
    );
  }
}

/* =====================================================
   TWILIO SMS OTP
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
    ).toString(
      "base64"
    );

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
        method:
          "POST",

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

  console.log(
    "Mobile OTP sent successfully to:",
    mobile
  );
}

/* =====================================================
   OTP DISPATCHER
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

  const otp =
    createOtpRecord(
      user,
      type,
      purpose
    );

  try {
    if (
      type ===
      "email"
    ) {
      await sendEmailOtp(
        user.email,
        otp
      );

    } else if (
      type ===
      "mobile"
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
   LOGIN
===================================================== */

function completeLogin(
  req,
  user,
  remember
) {
  req.session.userId =
    user.id;

  delete req.session
    .verification;

  delete req.session
    .withdrawalVerification;

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
  if (
    !GOOGLE_CLIENT_ID_FOR_LOGIN
  ) {
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
    GOOGLE_CLIENT_ID_FOR_LOGIN
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
        data.picture ||
          "",
        1000
      )
  };
}

app.get(
  "/api/google-config",
  (
    req,
    res
  ) => {
    res.json({
      clientId:
        GOOGLE_CLIENT_ID
    });
  }
);

app.post(
  "/api/auth/google",
  async (
    req,
    res
  ) => {
    try {
      const googleUser =
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
                googleUser.googleId
              )
        );

      if (!user) {
        user =
          db.users.find(
            u =>
              normalizeEmail(
                u.email
              ) ===
                googleUser.email
          );
      }

      if (!user) {
        user = {
          id:
            crypto.randomUUID(),

          name:
            googleUser.name,

          email:
            googleUser.email,

          passwordHash:
            "",

          role:
            "Member",

          mobile:
            "",

          city:
            "",

          profileImage:
            googleUser.picture,

          emailVerified:
            true,

          mobileVerified:
            false,

          googleId:
            googleUser.googleId,

          authProvider:
            "google",

          points:
            0,

          balance:
            0,

          createdAt:
            new Date().toISOString()
        };

        db.users.push(
          user
        );

      } else {
        user.googleId =
          googleUser.googleId;

        user.emailVerified =
          true;

        user.authProvider =
          "google";

        user.points ??= 0;

        if (
          !user.profileImage
        ) {
          user.profileImage =
            googleUser.picture;
        }

        if (!user.name) {
          user.name =
            googleUser.name;
        }
      }

      saveDB(db);

      completeLogin(
        req,
        user,
        true
      );

      res.json({
        success:
          true,

        user:
          publicUser(
            user
          )
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
  (
    req,
    res
  ) => {
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
===================================================== */

app.post(
  "/api/register",
  async (
    req,
    res
  ) => {
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
          req.body.password ||
            ""
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
        !validEmail(
          email
        )
      ) {
        return res.status(400).json({
          error:
            "Please enter a valid email address."
        });
      }

      if (
        !validMobile(
          mobile
        )
      ) {
        return res.status(400).json({
          error:
            "Please enter a valid mobile number."
        });
      }

      if (
        password.length <
        6
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
            ) ===
              email
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

        /*
          New users start with zero Points.
        */
        points:
          0,

        /*
          Legacy balance retained but not used
          by rewarded advertisements.
        */
        balance:
          0,

        createdAt:
          new Date().toISOString()
      };

      db.users.push(
        user
      );

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

      const record =
        getOtpRecord(
          user.id,
          "email",
          "register"
        );

      res.json({
        verificationRequired:
          true,

        step:
          "email",

        email:
          user.email,

        mobile:
          user.mobile,

        expiresAt:
          record
            ? record.expiresAt
            : null,

        resendAt:
          record
            ? new Date(
                new Date(
                  record.lastSentAt
                ).getTime() +
                  OTP_RESEND_MS
              ).toISOString()
            : null
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
  async (
    req,
    res
  ) => {
    try {
      const email =
        normalizeEmail(
          req.body.email
        );

      const password =
        String(
          req.body.password ||
            ""
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
            ) ===
              email
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

        await sendOtpFor(
          user,
          "email",
          "login",
          true
        );

        const record =
          getOtpRecord(
            user.id,
            "email",
            "login"
          );

        return res.json({
          verificationRequired:
            true,

          step:
            "email",

          email:
            user.email,

          mobile:
            user.mobile,

          expiresAt:
            record
              ? record.expiresAt
              : null,

          resendAt:
            record
              ? new Date(
                  new Date(
                    record.lastSentAt
                  ).getTime() +
                    OTP_RESEND_MS
                ).toISOString()
              : null
        });
      }

      user.points ??= 0;

      completeLogin(
        req,
        user,
        remember
      );

      res.json({
        user:
          publicUser(
            user
          )
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
  async (
    req,
    res
  ) => {
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
            "OTP has expired. Please click Resend OTP."
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
            "Too many incorrect attempts. Please click Resend OTP."
        });
      }

      if (
        !safeCompare(
          record.otpHash,
          hashOtp(
            otp
          )
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

      user.points ??= 0;

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
          publicUser(
            user
          )
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
  async (
    req,
    res
  ) => {
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
        "email",
        verification.purpose,
        false
      );

      const record =
        getOtpRecord(
          user.id,
          "email",
          verification.purpose
        );

      res.json({
        success:
          true,

        message:
          "A new Gmail OTP has been sent.",

        expiresAt:
          record
            ? record.expiresAt
            : null,

        resendAt:
          record
            ? new Date(
                new Date(
                  record.lastSentAt
                ).getTime() +
                  OTP_RESEND_MS
              ).toISOString()
            : null
      });

    } catch (error) {
      console.error(
        "Resend email OTP error:",
        error
      );

      res.status(400).json({
        error:
          error.message ||
          "Unable to resend OTP."
      });
    }
  }
);

/* =====================================================
   OTP STATUS
===================================================== */

app.get(
  "/api/otp-status",
  (
    req,
    res
  ) => {
    const verification =
      req.session.verification;

    if (!verification) {
      return res.json({
        active:
          false
      });
    }

    const user =
      findUserById(
        verification.userId
      );

    if (!user) {
      return res.json({
        active:
          false
      });
    }

    const record =
      getOtpRecord(
        user.id,
        "email",
        verification.purpose
      );

    if (!record) {
      return res.json({
        active:
          false
      });
    }

    const now =
      Date.now();

    const expiresAt =
      new Date(
        record.expiresAt
      ).getTime();

    const resendAt =
      new Date(
        record.lastSentAt
      ).getTime() +
      OTP_RESEND_MS;

    res.json({
      active:
        expiresAt > now,

      expiresAt:
        record.expiresAt,

      resendAt:
        new Date(
          resendAt
        ).toISOString(),

      expiresIn:
        Math.max(
          0,
          Math.ceil(
            (
              expiresAt -
              now
            ) / 1000
          )
        ),

      resendIn:
        Math.max(
          0,
          Math.ceil(
            (
              resendAt -
              now
            ) / 1000
          )
        )
    });
  }
);

/* =====================================================
   CURRENT USER
===================================================== */

app.get(
  "/api/me",
  (
    req,
    res
  ) => {
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
  (
    req,
    res
  ) => {
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
  (
    req,
    res
  ) => {
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
        !validMobile(
          mobile
        )
      ) {
        return res.status(400).json({
          error:
            "Please enter a valid mobile number."
        });
      }

      if (
        mobile !==
        user.mobile
      ) {
        if (mobile) {
          const duplicate =
            db.users.find(
              u =>
                String(
                  u.id
                ) !==
                  String(
                    user.id
                  ) &&
                u.mobile ===
                  mobile
            );

          if (duplicate) {
            return res.status(409).json({
              error:
                "This mobile number is already registered."
            });
          }
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
          publicUser(
            user
          )
      });

    } catch (error) {
      console.error(
        "Profile error:",
        error
      );

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
  (
    req,
    res
  ) => {
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
              ) || 0,

            rewardType:
              task.rewardType ||
              "task"
          })
        )
    );
  }
);

/* =====================================================
   POINTS SUMMARY
===================================================== */

app.get(
  "/api/points",
  requireLogin,
  (
    req,
    res
  ) => {
    const transactions =
      db.pointTransactions
        .filter(
          transaction =>
            String(
              transaction.userId
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
      points:
        getPointsBalance(
          req.user
        ),

      todayAdCount:
        getTodayAdRewardCount(
          req.user.id
        ),

      todayAdPoints:
        getTodayAdPoints(
          req.user.id
        ),

      dailyAdLimit:
        DAILY_AD_LIMIT,

      dailyPointLimit:
        DAILY_POINT_LIMIT,

      transactions
    });
  }
);

/* =====================================================
   START REWARDED AD SESSION
=====================================================

   The frontend calls this before opening the ad.

   IMPORTANT:
   This does NOT give Points.

   It creates a short-lived server-side session.
===================================================== */

app.post(
  "/api/rewards/ad-start",
  requireLogin,
  (
    req,
    res
  ) => {
    try {
      const user =
        req.user;

      const taskId =
        Number(
          req.body.taskId
        );

      const task =
        db.tasks.find(
          item =>
            Number(
              item.id
            ) ===
              taskId &&
            item.active !==
              false &&
            item.rewardType ===
              "ad"
        );

      if (!task) {
        return res.status(404).json({
          error:
            "Rewarded ad task not found."
        });
      }

      const todayCount =
        getTodayAdRewardCount(
          user.id
        );

      if (
        todayCount >=
        DAILY_AD_LIMIT
      ) {
        return res.status(429).json({
          error:
            "Daily rewarded-ad limit reached. Please try again tomorrow."
        });
      }

      const todayPoints =
        getTodayAdPoints(
          user.id
        );

      if (
        todayPoints +
          AD_REWARD_POINTS >
        DAILY_POINT_LIMIT
      ) {
        return res.status(429).json({
          error:
            "Daily Points limit reached. Please try again tomorrow."
        });
      }

      /*
        Remove expired sessions.
      */
      const now =
        Date.now();

      db.rewardSessions =
        db.rewardSessions.filter(
          session =>
            new Date(
              session.expiresAt
            ).getTime() >
            now
        );

      const rewardSessionId =
        crypto.randomUUID();

      const rewardSessionSecret =
        crypto
          .randomBytes(32)
          .toString("hex");

      const rewardSessionHash =
        crypto
          .createHash("sha256")
          .update(
            rewardSessionSecret
          )
          .digest("hex");

      db.rewardSessions.push({
        id:
          rewardSessionId,

        userId:
          user.id,

        taskId:
          task.id,

        rewardPoints:
          AD_REWARD_POINTS,

        secretHash:
          rewardSessionHash,

        createdAt:
          new Date().toISOString(),

        expiresAt:
          new Date(
            now +
              10 * 60 * 1000
          ).toISOString(),

        status:
          "created"
      });

      saveDB(db);

      /*
        The secret is returned only to the logged-in
        frontend. It is NOT itself a reward confirmation.
      */
      res.json({
        success:
          true,

        rewardSessionId,

        rewardSessionToken:
          rewardSessionSecret,

        taskId:
          task.id,

        points:
          AD_REWARD_POINTS,

        remainingToday:
          Math.max(
            0,
            DAILY_AD_LIMIT -
              todayCount
          )
      });

    } catch (error) {
      console.error(
        "Ad start error:",
        error
      );

      res.status(500).json({
        error:
          "Unable to start rewarded ad."
      });
    }
  }
);

/* =====================================================
   REWARD RATE LIMIT
===================================================== */

function rewardRateLimited(
  userId
) {
  const now =
    Date.now();

  const recent =
    db.adRewards.filter(
      reward =>
        String(
          reward.userId
        ) ===
          String(userId) &&
        now -
          new Date(
            reward.createdAt
          ).getTime() <
          REWARD_RATE_WINDOW_MS
    );

  return (
    recent.length >=
    REWARD_RATE_MAX
  );
}

/* =====================================================
   GOOGLE-STYLE SERVER-SIDE REWARD VERIFICATION
=====================================================

   This endpoint is intentionally separated from the
   browser-facing reward endpoint.

   A real ad provider should call this endpoint from
   its server-side reward/SSV mechanism.

   Expected body:

   {
     userId,
     rewardSessionId,
     adEventId,
     points,
     signature
   }

   signature =
     HMAC-SHA256(
       userId + "|" +
       rewardSessionId + "|" +
       adEventId + "|" +
       points,
       AD_REWARD_SECRET
     )

   DO NOT expose AD_REWARD_SECRET to frontend.
===================================================== */

function createRewardSignature({
  userId,
  rewardSessionId,
  adEventId,
  points
}) {
  if (!AD_REWARD_SECRET) {
    return "";
  }

  const payload =
    [
      userId,
      rewardSessionId,
      adEventId,
      points
    ].join("|");

  return crypto
    .createHmac(
      "sha256",
      AD_REWARD_SECRET
    )
    .update(
      payload
    )
    .digest("hex");
}

function verifyRewardSignature({
  userId,
  rewardSessionId,
  adEventId,
  points,
  signature
}) {
  if (
    !AD_REWARD_SECRET
  ) {
    return false;
  }

  const expected =
    createRewardSignature({
      userId,
      rewardSessionId,
      adEventId,
      points
    });

  return safeCompare(
    expected,
    signature
  );
}

/* =====================================================
   SERVER-TO-SERVER REWARD CONFIRMATION
===================================================== */

app.post(
  "/api/rewards/provider-confirm",
  async (
    req,
    res
  ) => {
    try {
      if (
        !AD_REWARD_SECRET
      ) {
        return res.status(503).json({
          error:
            "Reward provider verification is not configured on the server."
        });
      }

      const userId =
        cleanText(
          req.body.userId,
          200
        );

      const rewardSessionId =
        cleanText(
          req.body.rewardSessionId,
          200
        );

      const adEventId =
        cleanText(
          req.body.adEventId,
          300
        );

      const points =
        Number(
          req.body.points
        );

      const signature =
        cleanText(
          req.body.signature,
          500
        );

      if (
        !userId ||
        !rewardSessionId ||
        !adEventId ||
        !signature
      ) {
        return res.status(400).json({
          error:
            "Invalid reward confirmation data."
        });
      }

      if (
        !Number.isInteger(
          points
        ) ||
        points <= 0
      ) {
        return res.status(400).json({
          error:
            "Invalid reward points."
        });
      }

      /*
        Signature verification happens before any
        Points are credited.
      */
      if (
        !verifyRewardSignature({
          userId,
          rewardSessionId,
          adEventId,
          points,
          signature
        })
      ) {
        return res.status(403).json({
          error:
            "Invalid reward verification signature."
        });
      }

      /*
        Duplicate provider event protection.
      */
      const duplicate =
        db.adRewards.find(
          reward =>
            reward.adEventId ===
            adEventId
        );

      if (duplicate) {
        return res.status(409).json({
          error:
            "This reward has already been claimed.",
          alreadyProcessed:
            true
        });
      }

      const user =
        findUserById(
          userId
        );

      if (!user) {
        return res.status(404).json({
          error:
            "User account not found."
        });
      }

      const rewardSession =
        db.rewardSessions.find(
          session =>
            session.id ===
              rewardSessionId &&
            String(
              session.userId
            ) ===
              String(
                user.id
              )
        );

      if (!rewardSession) {
        return res.status(400).json({
          error:
            "Reward session not found."
        });
      }

      if (
        rewardSession.status ===
        "credited"
      ) {
        return res.status(409).json({
          error:
            "This reward session has already been processed."
        });
      }

      if (
        rewardSession.status ===
        "blocked"
      ) {
        return res.status(403).json({
          error:
            "This reward session is blocked."
        });
      }

      if (
        Date.now() >
        new Date(
          rewardSession.expiresAt
        ).getTime()
      ) {
        rewardSession.status =
          "expired";

        saveDB(db);

        return res.status(400).json({
          error:
            "Reward session expired."
        });
      }

      /*
        The provider cannot choose an arbitrary reward.
        It must match the server-created reward session.
      */
      if (
        points !==
        Number(
          rewardSession.rewardPoints
        )
      ) {
        return res.status(400).json({
          error:
            "Reward amount does not match the task."
        });
      }

      const task =
        db.tasks.find(
          item =>
            Number(
              item.id
            ) ===
              Number(
                rewardSession.taskId
              ) &&
            item.active !==
              false &&
            item.rewardType ===
              "ad"
        );

      if (!task) {
        return res.status(404).json({
          error:
            "Reward task is no longer available."
        });
      }

      if (
        points !==
        Number(
          task.reward
        )
      ) {
        return res.status(400).json({
          error:
            "Reward amount does not match the task configuration."
        });
      }

      /*
        Rate-limit suspicious bursts.
      */
      if (
        rewardRateLimited(
          user.id
        )
      ) {
        db.suspiciousActivity.push({
          id:
            crypto.randomUUID(),

          userId:
            user.id,

          type:
            "reward_rate_limit",

          details:
            "Reward confirmation rate exceeded.",

          createdAt:
            new Date().toISOString()
        });

        rewardSession.status =
          "blocked";

        saveDB(db);

        return res.status(429).json({
          error:
            "Too many reward requests. Please try again later."
        });
      }

      const todayCount =
        getTodayAdRewardCount(
          user.id
        );

      if (
        todayCount >=
        DAILY_AD_LIMIT
      ) {
        rewardSession.status =
          "blocked";

        db.suspiciousActivity.push({
          id:
            crypto.randomUUID(),

          userId:
            user.id,

          type:
            "daily_limit",

          details:
            "Reward confirmation attempted after daily limit.",

          createdAt:
            new Date().toISOString()
        });

        saveDB(db);

        return res.status(429).json({
          error:
            "Daily rewarded-ad limit reached."
        });
      }

      const todayPoints =
        getTodayAdPoints(
          user.id
        );

      if (
        todayPoints +
          points >
        DAILY_POINT_LIMIT
      ) {
        rewardSession.status =
          "blocked";

        db.suspiciousActivity.push({
          id:
            crypto.randomUUID(),

          userId:
            user.id,

          type:
            "daily_points_limit",

          details:
            "Reward confirmation attempted after daily Points limit.",

          createdAt:
            new Date().toISOString()
        });

        saveDB(db);

        return res.status(429).json({
          error:
            "Daily Points limit reached."
        });
      }

      /*
        Final duplicate check immediately before credit.
      */
      const duplicateAgain =
        db.adRewards.find(
          reward =>
            reward.adEventId ===
            adEventId
        );

      if (duplicateAgain) {
        return res.status(409).json({
          error:
            "This reward has already been claimed.",
          alreadyProcessed:
            true
        });
      }

      /*
        CREDIT POINTS
        ------------------------------------------------
        This is the only place where the server awards
        automatic rewarded-ad Points.
      */
      const transaction =
        creditPoints({
          user,

          points,

          source:
            "rewarded_ad",

          taskId:
            task.id,

          adEventId,

          metadata: {
            rewardSessionId,
            provider:
              "server_verified"
          }
        });

      db.adRewards.push({
        id:
          crypto.randomUUID(),

        userId:
          user.id,

        taskId:
          task.id,

        rewardType:
          "ad",

        points,

        adEventId,

        rewardSessionId,

        status:
          "credited",

        transactionId:
          transaction.id,

        createdAt:
          new Date().toISOString()
      });

      rewardSession.status =
        "credited";

      rewardSession.completedAt =
        new Date().toISOString();

      saveDB(db);

      return res.json({
        success:
          true,

        message:
          "Reward confirmed successfully.",

        pointsAdded:
          points,

        newBalance:
          getPointsBalance(
            user
          )
      });

    } catch (error) {
      console.error(
        "Provider reward confirmation error:",
        error
      );

      res.status(500).json({
        error:
          "Unable to confirm reward."
      });
    }
  }
);

/* =====================================================
   BROWSER REWARD COMPLETE
=====================================================

   IMPORTANT:
   This endpoint NEVER credits Points merely because
   the browser says "completed".

   It is intentionally rejected unless the server has
   already received a verified provider event.

   The frontend can poll /api/rewards/status instead.
===================================================== */

app.post(
  "/api/rewards/ad-complete",
  requireLogin,
  (
    req,
    res
  ) => {
    const rewardSessionId =
      cleanText(
        req.body.rewardSessionId,
        200
      );

    if (!rewardSessionId) {
      return res.status(400).json({
        error:
          "Reward session is required."
      });
    }

    const rewardSession =
      db.rewardSessions.find(
        session =>
          session.id ===
            rewardSessionId &&
          String(
            session.userId
          ) ===
            String(
              req.user.id
            )
      );

    if (!rewardSession) {
      return res.status(404).json({
        error:
          "Reward session not found."
      });
    }

    if (
      rewardSession.status ===
      "credited"
    ) {
      const reward =
        db.adRewards.find(
          item =>
            item.rewardSessionId ===
            rewardSessionId
        );

      return res.json({
        success:
          true,

        completed:
          true,

        pointsAdded:
          reward
            ? reward.points
            : 0,

        newBalance:
          getPointsBalance(
            req.user
          ),

        message:
          "Ad reward has already been confirmed."
      });
    }

    /*
      No verified provider event yet.
    */
    return res.status(202).json({
      success:
        false,

      completed:
        false,

      rewardPending:
        true,

      message:
        "Ad completion is waiting for reward confirmation."
    });
  }
);

/* =====================================================
   REWARD STATUS
===================================================== */

app.get(
  "/api/rewards/status/:sessionId",
  requireLogin,
  (
    req,
    res
  ) => {
    const sessionId =
      cleanText(
        req.params.sessionId,
        200
      );

    const rewardSession =
      db.rewardSessions.find(
        session =>
          session.id ===
            sessionId &&
          String(
            session.userId
          ) ===
            String(
              req.user.id
            )
      );

    if (!rewardSession) {
      return res.status(404).json({
        error:
          "Reward session not found."
      });
    }

    const reward =
      db.adRewards.find(
        item =>
          item.rewardSessionId ===
          sessionId
      );

    if (
      rewardSession.status ===
      "credited" &&
      reward
    ) {
      return res.json({
        completed:
          true,

        status:
          "credited",

        pointsAdded:
          reward.points,

        newBalance:
          getPointsBalance(
            req.user
          )
      });
    }

    if (
      rewardSession.status ===
      "expired"
    ) {
      return res.json({
        completed:
          false,

        status:
          "expired",

        message:
          "Reward session expired."
      });
    }

    if (
      rewardSession.status ===
      "blocked"
    ) {
      return res.json({
        completed:
          false,

        status:
          "blocked",

        message:
          "This reward session was blocked."
      });
    }

    res.json({
      completed:
        false,

      status:
        "pending",

      message:
        "Reward is waiting for provider confirmation."
    });
  }
);

/* =====================================================
   AD REWARD HISTORY
===================================================== */

app.get(
  "/api/rewards/history",
  requireLogin,
  (
    req,
    res
  ) => {
    const history =
      db.adRewards
        .filter(
          reward =>
            String(
              reward.userId
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
        )
        .map(
          reward => ({
            id:
              reward.id,

            taskId:
              reward.taskId,

            rewardType:
              reward.rewardType,

            points:
              reward.points,

            status:
              reward.status,

            createdAt:
              reward.createdAt
          })
        );

    res.json({
      history
    });
  }
);

/* =====================================================
   SUBMIT NORMAL TASK
===================================================== */

app.post(
  "/api/tasks/:id/submit",
  requireLogin,
  (
    req,
    res
  ) => {
    const taskId =
      Number(
        req.params.id
      );

    const task =
      db.tasks.find(
        t =>
          Number(
            t.id
          ) ===
            taskId &&
          t.active !==
            false &&
          t.rewardType !==
            "ad"
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
          ) ===
            taskId &&
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
  (
    req,
    res
  ) => {
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
=====================================================

   The old wallet endpoint is retained only for
   compatibility with existing frontend code.

   Rewarded ads DO NOT add money to balance.
===================================================== */

app.get(
  "/api/wallet",
  requireLogin,
  (
    req,
    res
  ) => {
    res.json({
      balance:
        0,

      points:
        getPointsBalance(
          req.user
        ),

      withdrawals: [],

      message:
        "TaskEarn rewarded-ad rewards are Points, not cash."
    });
  }
);

/* =====================================================
   SEND MOBILE OTP
===================================================== */

app.post(
  "/api/withdrawal/send-mobile-otp",
  requireLogin,
  async (
    req,
    res
  ) => {
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

      const record =
        getOtpRecord(
          user.id,
          "mobile",
          "withdrawal"
        );

      res.json({
        verificationRequired:
          true,

        mobile:
          user.mobile,

        expiresAt:
          record
            ? record.expiresAt
            : null,

        resendAt:
          record
            ? new Date(
                new Date(
                  record.lastSentAt
                ).getTime() +
                  OTP_RESEND_MS
              ).toISOString()
            : null,

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
  async (
    req,
    res
  ) => {
    try {
      const verification =
        req.session.withdrawalVerification;

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
          hashOtp(
            otp
          )
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
  async (
    req,
    res
  ) => {
    try {
      if (
        req.user.mobileVerified
      ) {
        return res.json({
          alreadyVerified:
            true
        });
      }

      if (!req.user.mobile) {
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

      const record =
        getOtpRecord(
          req.user.id,
          "mobile",
          "withdrawal"
        );

      res.json({
        message:
          "A new mobile OTP has been sent.",

        expiresAt:
          record
            ? record.expiresAt
            : null,

        resendAt:
          record
            ? new Date(
                new Date(
                  record.lastSentAt
                ).getTime() +
                  OTP_RESEND_MS
              ).toISOString()
            : null
      });

    } catch (error) {
      console.error(
        "Resend mobile OTP:",
        error
      );

      res.status(400).json({
        error:
          error.message ||
          "Unable to resend mobile OTP."
      });
    }
  }
);

/* =====================================================
   WITHDRAWAL DISABLED FOR AD POINTS
===================================================== */

app.post(
  "/api/withdraw",
  requireLogin,
  (
    req,
    res
  ) => {
    return res.status(403).json({
      error:
        "Cash withdrawal is disabled for TaskEarn Points. Rewarded-ad Points cannot be converted directly to cash."
    });
  }
);

/* =====================================================
   ADMIN — USERS
===================================================== */

app.get(
  "/api/admin/users",
  requireAdmin,
  (
    req,
    res
  ) => {
    res.json({
      users:
        db.users.map(
          user =>
            publicUser(
              user
            )
        )
    });
  }
);

/* =====================================================
   ADMIN — AD REWARD HISTORY
===================================================== */

app.get(
  "/api/admin/rewards",
  requireAdmin,
  (
    req,
    res
  ) => {
    const rewards =
      db.adRewards
        .slice()
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
      rewards
    });
  }
);

/* =====================================================
   ADMIN — SUSPICIOUS ACTIVITY
===================================================== */

app.get(
  "/api/admin/suspicious-activity",
  requireAdmin,
  (
    req,
    res
  ) => {
    const records =
      db.suspiciousActivity
        .slice()
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
      records
    });
  }
);

/* =====================================================
   ADMIN — POINT TRANSACTIONS
===================================================== */

app.get(
  "/api/admin/points",
  requireAdmin,
  (
    req,
    res
  ) => {
    const transactions =
      db.pointTransactions
        .slice()
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
      transactions
    });
  }
);

/* =====================================================
   ADMIN — POINT ADJUSTMENT
=====================================================

   This is for manual admin adjustments only.

   It is separate from rewarded-ad automatic rewards.
===================================================== */

app.post(
  "/api/admin/points-adjust",
  requireAdmin,
  (
    req,
    res
  ) => {
    try {
      const userId =
        cleanText(
          req.body.userId,
          200
        );

      const points =
        Number(
          req.body.points
        );

      const reason =
        cleanText(
          req.body.reason,
          300
        );

      if (!userId) {
        return res.status(400).json({
          error:
            "User ID is required."
        });
      }

      if (
        !Number.isInteger(
          points
        ) ||
        points === 0
      ) {
        return res.status(400).json({
          error:
            "Points adjustment must be a non-zero integer."
        });
      }

      if (!reason) {
        return res.status(400).json({
          error:
            "Adjustment reason is required."
        });
      }

      const user =
        findUserById(
          userId
        );

      if (!user) {
        return res.status(404).json({
          error:
            "User not found."
        });
      }

      user.points =
        getPointsBalance(
          user
        ) +
        points;

      if (
        user.points <
        0
      ) {
        user.points =
          0;
      }

      const transaction =
        createPointTransaction({
          userId:
            user.id,

          type:
            "admin_adjustment",

          points,

          source:
            "admin",

          metadata: {
            adminUserId:
              req.user.id,

            reason
          }
        });

      saveDB(db);

      res.json({
        success:
          true,

        user:
          publicUser(
            user
          ),

        transaction
      });

    } catch (error) {
      console.error(
        "Admin point adjustment:",
        error
      );

      res.status(500).json({
        error:
          "Unable to adjust Points."
      });
    }
  }
);

/* =====================================================
   ADMIN — TASKS
===================================================== */

app.get(
  "/api/admin/tasks",
  requireAdmin,
  (
    req,
    res
  ) => {
    res.json({
      tasks:
        db.tasks
    });
  }
);

/* =====================================================
   HEALTH
===================================================== */

app.get(
  "/api/health",
  (
    req,
    res
  ) => {
    res.json({
      status:
        "ok",

      service:
        "TaskEarn",

      time:
        new Date().toISOString(),

      gmailConfigured:
        Boolean(
          GMAIL_USER
        ),

      gmailApiConfigured:
        Boolean(
          gmailApiConfigured
        ),

      googleConfigured:
        Boolean(
          GOOGLE_CLIENT_ID
        ),

      googleClientSecretConfigured:
        Boolean(
          GOOGLE_CLIENT_SECRET
        ),

      googleRefreshTokenConfigured:
        Boolean(
          GOOGLE_REFRESH_TOKEN
        ),

      twilioConfigured:
        Boolean(
          process.env.TWILIO_ACCOUNT_SID &&
          process.env.TWILIO_AUTH_TOKEN &&
          process.env.TWILIO_PHONE_NUMBER
        ),

      adRewardVerificationConfigured:
        Boolean(
          AD_REWARD_SECRET
        ),

      adRewardPoints:
        AD_REWARD_POINTS,

      dailyAdLimit:
        DAILY_AD_LIMIT,

      dailyPointLimit:
        DAILY_POINT_LIMIT,

      emailProvider:
        "Gmail API",

      smtp:
        false,

      cashWithdrawalForAdPoints:
        false
    });
  }
);

/* =====================================================
   API 404
===================================================== */

app.use(
  "/api",
  (
    req,
    res
  ) => {
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
      `Gmail API configured: ${
        gmailApiConfigured
          ? "YES"
          : "NO"
      }`
    );

    console.log(
      `Gmail User configured: ${
        GMAIL_USER
          ? "YES"
          : "NO"
      }`
    );

    console.log(
      `Email From configured: ${
        EMAIL_FROM
          ? "YES"
          : "NO"
      }`
    );

    console.log(
      `Google Client ID configured: ${
        GOOGLE_CLIENT_ID
          ? "YES"
          : "NO"
      }`
    );

    console.log(
      `Google Client Secret configured: ${
        GOOGLE_CLIENT_SECRET
          ? "YES"
          : "NO"
      }`
    );

    console.log(
      `Google Refresh Token configured: ${
        GOOGLE_REFRESH_TOKEN
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
      `Ad reward verification configured: ${
        AD_REWARD_SECRET
          ? "YES"
          : "NO"
      }`
    );

    console.log(
      `Reward per ad: ${AD_REWARD_POINTS} Points`
    );

    console.log(
      `Daily rewarded ads: ${DAILY_AD_LIMIT}`
    );

    console.log(
      `Daily Points limit: ${DAILY_POINT_LIMIT}`
    );

    console.log(
      "Cash withdrawal for rewarded-ad Points: DISABLED"
    );

    console.log(
      "Email OTP provider: Gmail API"
    );

    console.log(
      "SMTP: DISABLED"
    );
  }
);
