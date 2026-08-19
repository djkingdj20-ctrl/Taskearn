const express = require("express");
const session = require("express-session");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();

/* =====================================================
   BASIC CONFIG
===================================================== */

const IS_PRODUCTION =
  process.env.NODE_ENV === "production";

app.set("trust proxy", 1);

/* =====================================================
   SECURITY CONFIG
===================================================== */

const SESSION_SECRET =
  process.env.SESSION_SECRET;

if (IS_PRODUCTION && !SESSION_SECRET) {
  console.error(
    "ERROR: SESSION_SECRET is required in production."
  );

  process.exit(1);
}

const FINAL_SESSION_SECRET =
  SESSION_SECRET ||
  crypto.randomBytes(48).toString("hex");

/* =====================================================
   BODY LIMITS
===================================================== */

app.use(
  express.json({
    limit: "50kb"
  })
);

app.use(
  express.urlencoded({
    extended: false,
    limit: "50kb"
  })
);

/* =====================================================
   SECURITY HEADERS
   IMPORTANT: BEFORE ROUTES
===================================================== */

app.disable("x-powered-by");

app.use((req, res, next) => {

  res.setHeader(
    "X-Content-Type-Options",
    "nosniff"
  );

  res.setHeader(
    "X-Frame-Options",
    "DENY"
  );

  res.setHeader(
    "Referrer-Policy",
    "strict-origin-when-cross-origin"
  );

  res.setHeader(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=()"
  );

  res.setHeader(
    "Cross-Origin-Opener-Policy",
    "same-origin"
  );

  res.setHeader(
    "Cross-Origin-Resource-Policy",
    "same-origin"
  );

  if (IS_PRODUCTION) {
    res.setHeader(
      "Strict-Transport-Security",
      "max-age=31536000; includeSubDomains"
    );
  }

  next();
});

/* =====================================================
   DATABASE
===================================================== */

const DATA_DIR =
  path.join(__dirname, "data");

const DATA_FILE =
  path.join(DATA_DIR, "database.json");

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, {
    recursive: true
  });
}

/* =====================================================
   PASSWORD HASHING
   NODE.JS SCRYPT
===================================================== */

const PASSWORD_KEY_LENGTH = 64;

const SCRYPT_OPTIONS = {
  N: 16384,
  r: 8,
  p: 1,
  maxmem: 32 * 1024 * 1024
};

function hashPassword(password) {

  const salt =
    crypto.randomBytes(16).toString("hex");

  const hash =
    crypto.scryptSync(
      password,
      salt,
      PASSWORD_KEY_LENGTH,
      SCRYPT_OPTIONS
    ).toString("hex");

  return `scrypt:${salt}:${hash}`;
}

function isHashedPassword(password) {

  return (
    typeof password === "string" &&
    password.startsWith("scrypt:")
  );
}

function verifyPassword(
  password,
  storedPassword
) {

  try {

    if (
      !isHashedPassword(
        storedPassword
      )
    ) {
      return false;
    }

    const parts =
      storedPassword.split(":");

    if (parts.length !== 3) {
      return false;
    }

    const salt = parts[1];
    const storedHash = parts[2];

    if (
      !/^[a-f0-9]{32}$/i.test(salt)
    ) {
      return false;
    }

    if (
      !/^[a-f0-9]{128}$/i.test(
        storedHash
      )
    ) {
      return false;
    }

    const calculatedHash =
      crypto.scryptSync(
        password,
        salt,
        PASSWORD_KEY_LENGTH,
        SCRYPT_OPTIONS
      );

    const storedBuffer =
      Buffer.from(
        storedHash,
        "hex"
      );

    if (
      calculatedHash.length !==
      storedBuffer.length
    ) {
      return false;
    }

    return crypto.timingSafeEqual(
      calculatedHash,
      storedBuffer
    );

  } catch (error) {

    console.error(
      "Password verification error:",
      error.message
    );

    return false;
  }
}

/* =====================================================
   DEFAULT DATABASE
===================================================== */

const defaultDatabase = {
  users: [],
  tasks: [
    {
      id: 1,
      title: "Welcome Task",
      description:
        "Complete the basic TaskEarn welcome activity and submit it for review.",
      type: "Welcome",
      reward: 5,
      active: true,
      createdAt:
        new Date().toISOString()
    },
    {
      id: 2,
      title: "Website Feedback",
      description:
        "Review the website and provide useful feedback about your experience.",
      type: "Feedback",
      reward: 10,
      active: true,
      createdAt:
        new Date().toISOString()
    }
  ],
  submissions: [],
  withdrawals: []
};

/* =====================================================
   DATABASE LOAD
===================================================== */

function loadDatabase() {

  try {

    if (!fs.existsSync(DATA_FILE)) {

      const initial =
        JSON.parse(
          JSON.stringify(
            defaultDatabase
          )
        );

      fs.writeFileSync(
        DATA_FILE,
        JSON.stringify(
          initial,
          null,
          2
        ),
        {
          encoding: "utf8",
          flag: "wx"
        }
      );

      return initial;
    }

    const raw =
      fs.readFileSync(
        DATA_FILE,
        "utf8"
      );

    const data =
      JSON.parse(raw);

    return {
      users:
        Array.isArray(data.users)
          ? data.users
          : [],

      tasks:
        Array.isArray(data.tasks)
          ? data.tasks
          : [],

      submissions:
        Array.isArray(
          data.submissions
        )
          ? data.submissions
          : [],

      withdrawals:
        Array.isArray(
          data.withdrawals
        )
          ? data.withdrawals
          : []
    };

  } catch (error) {

    console.error(
      "Database load error:",
      error
    );

    process.exit(1);
  }
}

let db = loadDatabase();

/* =====================================================
   DATABASE SAVE
===================================================== */

let databaseWriteQueue =
  Promise.resolve();

function saveDatabase() {

  databaseWriteQueue =
    databaseWriteQueue.then(
      async () => {

        const tempFile =
          DATA_FILE +
          "." +
          process.pid +
          ".tmp";

        await fs.promises.writeFile(
          tempFile,
          JSON.stringify(
            db,
            null,
            2
          ),
          "utf8"
        );

        await fs.promises.rename(
          tempFile,
          DATA_FILE
        );
      }
    );

  return databaseWriteQueue;
}

/* =====================================================
   ADMIN SETUP
===================================================== */

function ensureAdminAccount() {

  const adminEmail =
    process.env.ADMIN_EMAIL;

  const adminPassword =
    process.env.ADMIN_PASSWORD;

  if (
    !adminEmail ||
    !adminPassword
  ) {

    if (IS_PRODUCTION) {

      console.warn(
        "WARNING: ADMIN_EMAIL and ADMIN_PASSWORD are not configured."
      );

    }

    return;
  }

  const normalizedEmail =
    String(adminEmail)
      .trim()
      .toLowerCase();

  let admin =
    db.users.find(
      user =>
        user.role === "admin"
    );

  if (!admin) {

    admin = {

      id:
        nextId(db.users),

      name:
        "TaskEarn Admin",

      email:
        normalizedEmail,

      password:
        hashPassword(
          String(adminPassword)
        ),

      role:
        "admin",

      balance:
        0,

      createdAt:
        new Date().toISOString()
    };

    db.users.push(admin);

    saveDatabase()
      .catch(error => {
        console.error(
          "Admin save error:",
          error
        );
      });

    console.log(
      "Admin account created."
    );

    return;
  }

  if (
    admin.email !==
    normalizedEmail
  ) {

    admin.email =
      normalizedEmail;

    saveDatabase()
      .catch(error => {
        console.error(
          "Admin update error:",
          error
        );
      });
  }
}

function nextId(array) {

  if (!array.length) {
    return 1;
  }

  return (
    Math.max(
      ...array.map(
        item =>
          Number(item.id) || 0
      )
    ) + 1
  );
}

ensureAdminAccount();

/* =====================================================
   SESSION
===================================================== */

app.use(
  session({

    name:
      "taskearn.sid",

    secret:
      FINAL_SESSION_SECRET,

    resave:
      false,

    saveUninitialized:
      false,

    rolling:
      true,

    cookie: {

      httpOnly:
        true,

      secure:
        IS_PRODUCTION,

      sameSite:
        "lax",

      maxAge:
        1000 *
        60 *
        60 *
        24 *
        7
    }
  })
);

/* =====================================================
   STATIC WEBSITE
===================================================== */

app.use(
  express.static(
    path.join(
      __dirname,
      "public"
    ),
    {
      index: "index.html",
      dotfiles: "deny",
      maxAge:
        IS_PRODUCTION
          ? "1d"
          : 0
    }
  )
);

/* =====================================================
   HELPERS
===================================================== */

function getCurrentUser(req) {

  if (
    !req.session ||
    !req.session.userId
  ) {
    return null;
  }

  return (
    db.users.find(
      user =>
        user.id ===
        req.session.userId
    ) || null
  );
}

function safeUser(user) {

  if (!user) {
    return null;
  }

  return {

    id:
      user.id,

    name:
      user.name,

    email:
      user.email,

    role:
      user.role,

    balance:
      Number(
        user.balance || 0
      ),

    createdAt:
      user.createdAt
  };
}

function cleanText(
  value,
  maxLength = 500
) {

  if (
    typeof value !== "string"
  ) {
    return "";
  }

  return value
    .normalize("NFKC")
    .trim()
    .slice(0, maxLength);
}

function validEmail(email) {

  if (
    typeof email !== "string"
  ) {
    return false;
  }

  if (
    email.length < 5 ||
    email.length > 150
  ) {
    return false;
  }

  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    .test(email);
}

function validPassword(password) {

  return (
    typeof password === "string" &&
    password.length >= 8 &&
    password.length <= 200
  );
}

/* =====================================================
   ORIGIN PROTECTION
===================================================== */

function checkOrigin(req, res, next) {

  const method =
    req.method.toUpperCase();

  const protectedMethod =
    method === "POST" ||
    method === "PUT" ||
    method === "PATCH" ||
    method === "DELETE";

  if (!protectedMethod) {
    return next();
  }

  if (
    !req.path.startsWith("/api/")
  ) {
    return next();
  }

  const origin =
    req.get("origin");

  const host =
    req.get("host");

  if (!origin) {

    return next();
  }

  try {

    const originUrl =
      new URL(origin);

    if (
      originUrl.host !== host
    ) {

      return res.status(403).json({
        error:
          "Request origin is not allowed."
      });
    }

  } catch {

    return res.status(403).json({
      error:
        "Invalid request origin."
    });
  }

  next();
}

app.use(checkOrigin);

/* =====================================================
   AUTH MIDDLEWARE
===================================================== */

function requireLogin(
  req,
  res,
  next
) {

  const user =
    getCurrentUser(req);

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

function requireUser(
  req,
  res,
  next
) {

  const user =
    getCurrentUser(req);

  if (!user) {

    return res.status(401).json({
      error:
        "Please login first."
    });
  }

  if (
    user.role !== "user"
  ) {

    return res.status(403).json({
      error:
        "User account required."
    });
  }

  req.user =
    user;

  next();
}

function requireAdmin(
  req,
  res,
  next
) {

  const user =
    getCurrentUser(req);

  if (!user) {

    return res.status(401).json({
      error:
        "Please login first."
    });
  }

  if (
    user.role !== "admin"
  ) {

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
   RATE LIMITING
===================================================== */

const loginAttempts =
  new Map();

const MAX_LOGIN_ATTEMPTS =
  8;

const LOGIN_WINDOW =
  15 * 60 * 1000;

function getClientIp(req) {

  return (
    req.ip ||
    "unknown"
  );
}

function checkLoginRateLimit(
  req
) {

  const ip =
    getClientIp(req);

  const now =
    Date.now();

  const record =
    loginAttempts.get(ip);

  if (!record) {
    return true;
  }

  if (
    now -
      record.firstAttempt >
    LOGIN_WINDOW
  ) {

    loginAttempts.delete(ip);

    return true;
  }

  return (
    record.count <
    MAX_LOGIN_ATTEMPTS
  );
}

function recordFailedLogin(
  req
) {

  const ip =
    getClientIp(req);

  const now =
    Date.now();

  let record =
    loginAttempts.get(ip);

  if (
    !record ||
    now -
      record.firstAttempt >
      LOGIN_WINDOW
  ) {

    record = {
      count: 0,
      firstAttempt: now
    };
  }

  record.count++;

  loginAttempts.set(
    ip,
    record
  );
}

function clearLoginAttempts(
  req
) {

  loginAttempts.delete(
    getClientIp(req)
  );
}

/* =====================================================
   GENERAL API RATE LIMIT
===================================================== */

const apiRateMap =
  new Map();

function generalApiRateLimit(
  req,
  res,
  next
) {

  if (
    !req.path.startsWith("/api/")
  ) {
    return next();
  }

  const ip =
    getClientIp(req);

  const now =
    Date.now();

  let record =
    apiRateMap.get(ip);

  if (
    !record ||
    now - record.start >
      60 * 1000
  ) {

    record = {
      start: now,
      count: 0
    };
  }

  record.count++;

  apiRateMap.set(
    ip,
    record
  );

  if (
    record.count > 120
  ) {

    return res.status(429).json({
      error:
        "Too many requests. Please try again later."
    });
  }

  next();
}

app.use(
  generalApiRateLimit
);

/* =====================================================
   HEALTH
===================================================== */

app.get(
  "/health",
  (req, res) => {

    res.json({
      success:
        true,

      message:
        "TaskEarn server is running.",

      time:
        new Date().toISOString()
    });
  }
);

/* =====================================================
   CURRENT USER
===================================================== */

app.get(
  "/api/me",
  (req, res) => {

    const user =
      getCurrentUser(req);

    res.json(
      safeUser(user)
    );
  }
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
        cleanText(
          req.body.email,
          150
        ).toLowerCase();

      const password =
        String(
          req.body.password ||
          ""
        );

      if (
        !name ||
        !email ||
        !password
      ) {

        return res.status(400).json({
          error:
            "Please complete all fields."
        });
      }

      if (
        name.length < 2
      ) {

        return res.status(400).json({
          error:
            "Please enter a valid name."
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
        !validPassword(password)
      ) {

        return res.status(400).json({
          error:
            "Password must contain 8 to 200 characters."
        });
      }

      const existing =
        db.users.find(
          user =>
            user.email ===
            email
        );

      if (existing) {

        return res.status(400).json({
          error:
            "An account with this email already exists."
        });
      }

      const user = {

        id:
          nextId(db.users),

        name,

        email,

        password:
          hashPassword(
            password
          ),

        role:
          "user",

        balance:
          0,

        createdAt:
          new Date().toISOString()
      };

      db.users.push(user);

      await saveDatabase();

      req.session.regenerate(
        error => {

          if (error) {

            console.error(
              "Session error:",
              error
            );

            return res.status(500).json({
              error:
                "Account created but login session failed."
            });
          }

          req.session.userId =
            user.id;

          req.session.save(
            saveError => {

              if (saveError) {

                console.error(
                  "Session save error:",
                  saveError
                );

                return res.status(500).json({
                  error:
                    "Registration completed but session failed."
                });
              }

              return res.json({
                success:
                  true,

                user:
                  safeUser(user)
              });
            }
          );
        }
      );

    } catch (error) {

      console.error(
        "Registration error:",
        error
      );

      res.status(500).json({
        error:
          "Registration failed."
      });
    }
  }
);

/* =====================================================
   LOGIN
===================================================== */

app.post(
  "/api/login",
  (req, res) => {

    try {

      if (
        !checkLoginRateLimit(req)
      ) {

        return res.status(429).json({
          error:
            "Too many login attempts. Please try again later."
        });
      }

      const email =
        cleanText(
          req.body.email,
          150
        ).toLowerCase();

      const password =
        String(
          req.body.password ||
          ""
        );

      if (
        !email ||
        !password
      ) {

        recordFailedLogin(req);

        return res.status(400).json({
          error:
            "Please enter email and password."
        });
      }

      const user =
        db.users.find(
          item =>
            item.email ===
            email
        );

      if (!user) {

        recordFailedLogin(req);

        return res.status(401).json({
          error:
            "Invalid email or password."
        });
      }

      let correct =
        false;

      if (
        isHashedPassword(
          user.password
        )
      ) {

        correct =
          verifyPassword(
            password,
            user.password
          );

      } else {

        /*
          OLD PASSWORD MIGRATION
          Only for existing old database.
        */

        if (
          typeof user.password ===
            "string" &&
          user.password ===
            password
        ) {

          correct =
            true;

          user.password =
            hashPassword(
              password
            );

          await saveDatabase();
        }
      }

      if (!correct) {

        recordFailedLogin(req);

        return res.status(401).json({
          error:
            "Invalid email or password."
        });
      }

      clearLoginAttempts(req);

      req.session.regenerate(
        error => {

          if (error) {

            console.error(
              "Session regeneration error:",
              error
            );

            return res.status(500).json({
              error:
                "Login session could not be created."
            });
          }

          req.session.userId =
            user.id;

          req.session.save(
            saveError => {

              if (saveError) {

                console.error(
                  "Session save error:",
                  saveError
                );

                return res.status(500).json({
                  error:
                    "Login session error."
                });
              }

              return res.json({
                success:
                  true,

                user:
                  safeUser(user)
              });
            }
          );
        }
      );

    } catch (error) {

      console.error(
        "Login error:",
        error
      );

      res.status(500).json({
        error:
          "Login failed."
      });
    }
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

          console.error(
            "Logout error:",
            error
          );

          return res.status(500).json({
            error:
              "Logout failed."
          });
        }

        res.clearCookie(
          "taskearn.sid"
        );

        return res.json({
          success:
            true,

          message:
            "Logged out successfully."
        });
      }
    );
  }
);

/* =====================================================
   USER TASKS
===================================================== */

app.get(
  "/api/tasks",
  requireUser,
  (req, res) => {

    const tasks =
      db.tasks
        .filter(
          task =>
            task.active === true
        )
        .map(task => ({
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
            ),

          active:
            task.active,

          createdAt:
            task.createdAt
        }));

    res.json(tasks);
  }
);

/* =====================================================
   SINGLE TASK
===================================================== */

app.get(
  "/api/tasks/:id",
  requireUser,
  (req, res) => {

    const id =
      Number(
        req.params.id
      );

    if (
      !Number.isSafeInteger(id)
    ) {

      return res.status(400).json({
        error:
          "Invalid task ID."
      });
    }

    const task =
      db.tasks.find(
        item =>
          item.id === id &&
          item.active === true
      );

    if (!task) {

      return res.status(404).json({
        error:
          "Task not found."
      });
    }

    res.json(task);
  }
);

/* =====================================================
   SUBMIT TASK
===================================================== */

app.post(
  "/api/tasks/:id/submit",
  requireUser,
  async (req, res) => {

    try {

      const taskId =
        Number(
          req.params.id
        );

      if (
        !Number.isSafeInteger(
          taskId
        )
      ) {

        return res.status(400).json({
          error:
            "Invalid task ID."
        });
      }

      const task =
        db.tasks.find(
          item =>
            item.id === taskId &&
            item.active === true
        );

      if (!task) {

        return res.status(404).json({
          error:
            "Task is not available."
        });
      }

      const pending =
        db.submissions.find(
          item =>
            item.userId ===
              req.user.id &&
            item.taskId ===
              task.id &&
            item.status ===
              "pending"
        );

      if (pending) {

        return res.status(400).json({
          error:
            "You already submitted this task and it is waiting for review."
        });
      }

      const approved =
        db.submissions.find(
          item =>
            item.userId ===
              req.user.id &&
            item.taskId ===
              task.id &&
            item.status ===
              "approved"
        );

      if (approved) {

        return res.status(400).json({
          error:
            "You have already completed this task."
        });
      }

      const reward =
        Number(
          task.reward
        );

      if (
        !Number.isFinite(
          reward
        ) ||
        reward <= 0
      ) {

        return res.status(500).json({
          error:
            "Invalid task reward."
        });
      }

      const submission = {

        id:
          nextId(
            db.submissions
          ),

        userId:
          req.user.id,

        taskId:
          task.id,

        taskTitle:
          task.title,

        reward,

        status:
          "pending",

        submittedAt:
          new Date().toISOString()
      };

      db.submissions.push(
        submission
      );

      await saveDatabase();

      res.json({
        success:
          true,

        message:
          "Task submitted for review."
      });

    } catch (error) {

      console.error(
        "Task submission error:",
        error
      );

      res.status(500).json({
        error:
          "Task submission failed."
      });
    }
  }
);

/* =====================================================
   MY SUBMISSIONS
===================================================== */

app.get(
  "/api/my-submissions",
  requireUser,
  (req, res) => {

    const submissions =
      db.submissions
        .filter(
          item =>
            item.userId ===
            req.user.id
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

    res.json(
      submissions
    );
  }
);

/* =====================================================
   WALLET
===================================================== */

app.get(
  "/api/wallet",
  requireUser,
  (req, res) => {

    const user =
      db.users.find(
        item =>
          item.id ===
          req.user.id
      );

    if (!user) {

      return res.status(404).json({
        error:
          "User not found."
      });
    }

    const completed =
      db.submissions.filter(
        item =>
          item.userId ===
            user.id &&
          item.status ===
            "approved"
      ).length;

    const withdrawals =
      db.withdrawals
        .filter(
          item =>
            item.userId ===
            user.id
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
          user.balance || 0
        ),

      completed,

      withdrawals
    });
  }
);

/* =====================================================
   WITHDRAW
===================================================== */

app.post(
  "/api/withdraw",
  requireUser,
  async (req, res) => {

    try {

      const amount =
        Number(
          req.body.amount
        );

      const method =
        cleanText(
          req.body.method,
          100
        );

      const MIN =
        100;

      const MAX =
        100000;

      if (
        !Number.isSafeInteger(
          amount
        )
      ) {

        return res.status(400).json({
          error:
            "Please enter a valid whole-number withdrawal amount."
        });
      }

      if (
        amount < MIN
      ) {

        return res.status(400).json({
          error:
            "Minimum withdrawal amount is ₹100."
        });
      }

      if (
        amount > MAX
      ) {

        return res.status(400).json({
          error:
            "Maximum withdrawal amount is ₹100000."
        });
      }

      if (!method) {

        return res.status(400).json({
          error:
            "Please enter a payment method."
        });
      }

      const user =
        db.users.find(
          item =>
            item.id ===
            req.user.id
        );

      if (!user) {

        return res.status(404).json({
          error:
            "User not found."
        });
      }

      const balance =
        Number(
          user.balance || 0
        );

      if (
        !Number.isFinite(
          balance
        ) ||
        balance < amount
      ) {

        return res.status(400).json({
          error:
            "Insufficient balance."
        });
      }

      const pending =
        db.withdrawals.find(
          item =>
            item.userId ===
              user.id &&
            item.status ===
              "pending"
        );

      if (pending) {

        return res.status(400).json({
          error:
            "You already have a pending withdrawal request."
        });
      }

      user.balance =
        balance - amount;

      const withdrawal = {

        id:
          nextId(
            db.withdrawals
          ),

        userId:
          user.id,

        name:
          user.name,

        amount,

        method,

        status:
          "pending",

        createdAt:
          new Date().toISOString()
      };

      db.withdrawals.push(
        withdrawal
      );

      await saveDatabase();

      res.json({
        success:
          true,

        message:
          "Withdrawal request submitted."
      });

    } catch (error) {

      console.error(
        "Withdrawal error:",
        error
      );

      res.status(500).json({
        error:
          "Withdrawal request failed."
      });
    }
  }
);

/* =====================================================
   ADMIN STATS
===================================================== */

app.get(
  "/api/admin/stats",
  requireAdmin,
  (req, res) => {

    const pendingSubmissions =
      db.submissions.filter(
        item =>
          item.status ===
          "pending"
      ).length;

    const pendingWithdrawals =
      db.withdrawals.filter(
        item =>
          item.status ===
          "pending"
      ).length;

    res.json({

      users:
        db.users.filter(
          user =>
            user.role !==
            "admin"
        ).length,

      tasks:
        db.tasks.length,

      submissions:
        pendingSubmissions,

      pending:
        pendingWithdrawals
    });
  }
);

/* =====================================================
   ADMIN TASKS
===================================================== */

app.get(
  "/api/admin/tasks",
  requireAdmin,
  (req, res) => {

    res.json(
      [...db.tasks].sort(
        (a, b) =>
          b.id - a.id
      )
    );
  }
);

/* =====================================================
   ADMIN ADD TASK
===================================================== */

app.post(
  "/api/admin/tasks",
  requireAdmin,
  async (req, res) => {

    try {

      const title =
        cleanText(
          req.body.title,
          150
        );

      const description =
        cleanText(
          req.body.description,
          1000
        );

      const type =
        cleanText(
          req.body.type,
          80
        );

      const reward =
        Number(
          req.body.reward
        );

      if (!title) {

        return res.status(400).json({
          error:
            "Task title is required."
        });
      }

      if (!description) {

        return res.status(400).json({
          error:
            "Task description is required."
        });
      }

      if (!type) {

        return res.status(400).json({
          error:
            "Task type is required."
        });
      }

      if (
        !Number.isFinite(
          reward
        ) ||
        reward <= 0 ||
        reward > 100000
      ) {

        return res.status(400).json({
          error:
            "Enter a valid reward."
        });
      }

      const task = {

        id:
          nextId(
            db.tasks
          ),

        title,

        description,

        type,

        reward,

        active:
          true,

        createdAt:
          new Date().toISOString()
      };

      db.tasks.push(task);

      await saveDatabase();

      res.json({
        success:
          true,

        task
      });

    } catch (error) {

      console.error(
        "Admin task error:",
        error
      );

      res.status(500).json({
        error:
          "Could not create task."
      });
    }
  }
);

/* =====================================================
   ADMIN UPDATE TASK
===================================================== */

app.put(
  "/api/admin/tasks/:id",
  requireAdmin,
  async (req, res) => {

    try {

      const id =
        Number(
          req.params.id
        );

      if (
        !Number.isSafeInteger(id)
      ) {

        return res.status(400).json({
          error:
            "Invalid task ID."
        });
      }

      const task =
        db.tasks.find(
          item =>
            item.id === id
        );

      if (!task) {

        return res.status(404).json({
          error:
            "Task not found."
        });
      }

      const title =
        cleanText(
          req.body.title,
          150
        );

      const description =
        cleanText(
          req.body.description,
          1000
        );

      const type =
        cleanText(
          req.body.type,
          80
        );

      const reward =
        Number(
          req.body.reward
        );

      if (
        !title ||
        !description ||
        !type
      ) {

        return res.status(400).json({
          error:
            "All task fields are required."
        });
      }

      if (
        !Number.isFinite(
          reward
        ) ||
        reward <= 0 ||
        reward > 100000
      ) {

        return res.status(400).json({
          error:
            "Invalid reward."
        });
      }

      task.title =
        title;

      task.description =
        description;

      task.type =
        type;

      task.reward =
        reward;

      task.active =
        req.body.active !== false;

      task.updatedAt =
        new Date().toISOString();

      await saveDatabase();

      res.json({
        success:
          true,

        task
      });

    } catch (error) {

      console.error(
        "Admin update task error:",
        error
      );

      res.status(500).json({
        error:
          "Could not update task."
      });
    }
  }
);

/* =====================================================
   ADMIN DISABLE TASK
===================================================== */

app.delete(
  "/api/admin/tasks/:id",
  requireAdmin,
  async (req, res) => {

    try {

      const id =
        Number(
          req.params.id
        );

      if (
        !Number.isSafeInteger(id)
      ) {

        return res.status(400).json({
          error:
            "Invalid task ID."
        });
      }

      const task =
        db.tasks.find(
          item =>
            item.id === id
        );

      if (!task) {

        return res.status(404).json({
          error:
            "Task not found."
        });
      }

      task.active =
        false;

      task.updatedAt =
        new Date().toISOString();

      await saveDatabase();

      res.json({
        success:
          true,

        message:
          "Task disabled."
      });

    } catch (error) {

      console.error(
        "Disable task error:",
        error
      );

      res.status(500).json({
        error:
          "Could not disable task."
      });
    }
  }
);

/* =====================================================
   ADMIN SUBMISSIONS
===================================================== */

app.get(
  "/api/admin/submissions",
  requireAdmin,
  (req, res) => {

    const submissions =
      db.submissions
        .map(item => {

          const user =
            db.users.find(
              u =>
                u.id ===
                item.userId
            );

          return {

            ...item,

            userName:
              user
                ? user.name
                : "Unknown User",

            userEmail:
              user
                ? user.email
                : ""
          };
        })
        .sort(
          (a, b) =>
            new Date(
              b.submittedAt
            ) -
            new Date(
              a.submittedAt
            )
        );

    res.json(
      submissions
    );
  }
);

/* =====================================================
   ADMIN REVIEW SUBMISSION
===================================================== */

app.post(
  "/api/admin/submissions/:id",
  requireAdmin,
  async (req, res) => {

    try {

      const id =
        Number(
          req.params.id
        );

      const status =
        cleanText(
          req.body.status,
          20
        );

      if (
        !Number.isSafeInteger(id)
      ) {

        return res.status(400).json({
          error:
            "Invalid submission ID."
        });
      }

      if (
        status !== "approved" &&
        status !== "rejected"
      ) {

        return res.status(400).json({
          error:
            "Invalid review status."
        });
      }

      const submission =
        db.submissions.find(
          item =>
            item.id === id
        );

      if (!submission) {

        return res.status(404).json({
          error:
            "Submission not found."
        });
      }

      if (
        submission.status !==
        "pending"
      ) {

        return res.status(400).json({
          error:
            "This submission has already been reviewed."
        });
      }

      const user =
        db.users.find(
          item =>
            item.id ===
            submission.userId
        );

      if (!user) {

        return res.status(404).json({
          error:
            "User not found."
        });
      }

      if (
        status === "approved"
      ) {

        const reward =
          Number(
            submission.reward
          );

        if (
          !Number.isFinite(
            reward
          ) ||
          reward <= 0
        ) {

          return res.status(400).json({
            error:
              "Invalid reward."
          });
        }

        user.balance =
          Number(
            user.balance || 0
          ) + reward;
      }

      submission.status =
        status;

      submission.reviewedAt =
        new Date().toISOString();

      submission.reviewedBy =
        req.user.id;

      await saveDatabase();

      res.json({
        success:
          true,

        message:
          status === "approved"
            ? "Submission approved."
            : "Submission rejected."
      });

    } catch (error) {

      console.error(
        "Review submission error:",
        error
      );

      res.status(500).json({
        error:
          "Could not review submission."
      });
    }
  }
);

/* =====================================================
   ADMIN WITHDRAWALS
===================================================== */

app.get(
  "/api/admin/withdrawals",
  requireAdmin,
  (req, res) => {

    const withdrawals =
      db.withdrawals
        .map(item => {

          const user =
            db.users.find(
              u =>
                u.id ===
                item.userId
            );

          return {

            ...item,

            name:
              user
                ? user.name
                : item.name,

            email:
              user
                ? user.email
                : ""
          };
        })
        .sort(
          (a, b) =>
            new Date(
              b.createdAt
            ) -
            new Date(
              a.createdAt
            )
        );

    res.json(
      withdrawals
    );
  }
);

/* =====================================================
   ADMIN REVIEW WITHDRAWAL
===================================================== */

app.post(
  "/api/admin/withdrawals/:id",
  requireAdmin,
  async (req, res) => {

    try {

      const id =
        Number(
          req.params.id
        );

      const status =
        cleanText(
          req.body.status,
          20
        );

      if (
        !Number.isSafeInteger(id)
      ) {

        return res.status(400).json({
          error:
            "Invalid withdrawal ID."
        });
      }

      if (
        status !== "approved" &&
        status !== "rejected"
      ) {

        return res.status(400).json({
          error:
            "Invalid withdrawal status."
        });
      }

      const withdrawal =
        db.withdrawals.find(
          item =>
            item.id === id
        );

      if (!withdrawal) {

        return res.status(404).json({
          error:
            "Withdrawal not found."
        });
      }

      if (
        withdrawal.status !==
        "pending"
      ) {

        return res.status(400).json({
          error:
            "This withdrawal has already been reviewed."
        });
      }

      const user =
        db.users.find(
          item =>
            item.id ===
            withdrawal.userId
        );

      if (!user) {

        return res.status(404).json({
          error:
            "User not found."
        });
      }

      if (
        status === "rejected"
      ) {

        const amount =
          Number(
            withdrawal.amount
          );

        if (
          !Number.isFinite(
            amount
          ) ||
          amount <= 0
        ) {

          return res.status(400).json({
            error:
              "Invalid withdrawal amount."
          });
        }

        user.balance =
          Number(
            user.balance || 0
          ) + amount;
      }

      withdrawal.status =
        status;

      withdrawal.reviewedAt =
        new Date().toISOString();

      withdrawal.reviewedBy =
        req.user.id;

      await saveDatabase();

      res.json({

        success:
          true,

        message:
          status === "approved"
            ? "Withdrawal approved."
            : "Withdrawal rejected and balance returned."
      });

    } catch (error) {

      console.error(
        "Review withdrawal error:",
        error
      );

      res.status(500).json({
        error:
          "Could not review withdrawal."
      });
    }
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
   FRONTEND FALLBACK
===================================================== */

app.use(
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

/* =====================================================
   ERROR HANDLER
===================================================== */

app.use(
  (err, req, res, next) => {

    console.error(
      "Unhandled server error:",
      err
    );

    if (
      res.headersSent
    ) {
      return next(err);
    }

    res.status(500).json({
      error:
        "Something went wrong on the server."
    });
  }
);

/* =====================================================
   SERVER
===================================================== */

const PORT =
  Number(
    process.env.PORT || 3000
  );

app.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(
      `TaskEarn server running on port ${PORT}`
    );

    console.log(
      `Environment: ${
        process.env.NODE_ENV ||
        "development"
      }`
    );
  }
);
