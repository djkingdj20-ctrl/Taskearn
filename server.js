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
  console.error(
    "CRITICAL ERROR: SESSION_SECRET environment variable is required in production."
  );
  process.exit(1);
}

const FINAL_SESSION_SECRET =
  SESSION_SECRET || crypto.randomBytes(48).toString("hex");

/* =====================================================
   BODY LIMITS
===================================================== */

app.use(express.json({ limit: "50kb" }));
app.use(express.urlencoded({ extended: false, limit: "50kb" }));

app.disable("x-powered-by");

/* =====================================================
   SECURITY HEADERS
===================================================== */

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

  res.setHeader(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=()"
  );

  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");

  /*
    IMPORTANT:
    index.html currently uses inline JavaScript
    such as onclick="" and <script>.
    Therefore unsafe-inline is required here.
  */
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
  );

  if (IS_PRODUCTION) {
    res.setHeader(
      "Strict-Transport-Security",
      "max-age=31536000; includeSubDomains; preload"
    );
  }

  next();
});

/* =====================================================
   DATABASE
===================================================== */

const DATA_DIR = path.join(__dirname, "data");
const DATA_FILE = path.join(DATA_DIR, "database.json");

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

/* =====================================================
   PASSWORD HASHING
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

  const derivedKey = await scryptAsync(
    password,
    salt,
    PASSWORD_KEY_LENGTH,
    SCRYPT_OPTIONS
  );

  return `scrypt:${salt}:${derivedKey.toString("hex")}`;
}

function isHashedPassword(password) {
  return (
    typeof password === "string" &&
    password.startsWith("scrypt:")
  );
}

async function verifyPassword(password, storedPassword) {
  try {
    if (!isHashedPassword(storedPassword)) {
      return false;
    }

    const parts = storedPassword.split(":");

    if (parts.length !== 3) {
      return false;
    }

    const salt = parts[1];
    const storedHash = parts[2];

    if (
      !/^[a-f0-9]{32}$/i.test(salt) ||
      !/^[a-f0-9]{128}$/i.test(storedHash)
    ) {
      return false;
    }

    const calculatedHash = await scryptAsync(
      password,
      salt,
      PASSWORD_KEY_LENGTH,
      SCRYPT_OPTIONS
    );

    const storedBuffer = Buffer.from(storedHash, "hex");

    if (calculatedHash.length !== storedBuffer.length) {
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
      reward: 25,
      active: true,
      createdAt: new Date().toISOString()
    },
    {
      id: 2,
      title: "Website Feedback",
      description:
        "Review the website and provide useful feedback about your experience.",
      type: "Feedback",
      reward: 50,
      active: true,
      createdAt: new Date().toISOString()
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
      const initial = JSON.parse(
        JSON.stringify(defaultDatabase)
      );

      fs.writeFileSync(
        DATA_FILE,
        JSON.stringify(initial, null, 2),
        {
          encoding: "utf8",
          flag: "wx"
        }
      );

      return initial;
    }

    const raw = fs.readFileSync(DATA_FILE, "utf8");
    const data = JSON.parse(raw);

    return {
      users: Array.isArray(data.users)
        ? data.users
        : [],

      tasks: Array.isArray(data.tasks)
        ? data.tasks
        : [],

      submissions: Array.isArray(data.submissions)
        ? data.submissions
        : [],

      withdrawals: Array.isArray(data.withdrawals)
        ? data.withdrawals
        : []
    };
  } catch (error) {
    console.error("Database load error:", error);
    process.exit(1);
  }
}

let db = loadDatabase();

let databaseWriteQueue = Promise.resolve();

/* =====================================================
   DATABASE SAVE
===================================================== */

function saveDatabase() {
  databaseWriteQueue = databaseWriteQueue.then(
    async () => {
      const tempFile = `${DATA_FILE}.${process.pid}.${Date.now()}.tmp`;

      await fs.promises.writeFile(
        tempFile,
        JSON.stringify(db, null, 2),
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
   ID GENERATOR
===================================================== */

function nextId(array) {
  if (!array.length) {
    return 1;
  }

  return (
    Math.max(
      ...array.map(
        item => Number(item.id) || 0
      )
    ) + 1
  );
}

/* =====================================================
   SESSION
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
  express.static(
    path.join(__dirname, "public")
  )
);

/* =====================================================
   USER HELPERS
===================================================== */

function getCurrentUser(req) {
  if (!req.session || !req.session.userId) {
    return null;
  }

  return (
    db.users.find(
      user => user.id === req.session.userId
    ) || null
  );
}

function safeUser(user) {
  if (!user) {
    return null;
  }

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
  if (typeof value !== "string") {
    return "";
  }

  return value
    .normalize("NFKC")
    .trim()
    .slice(0, maxLength);
}

function validEmail(email) {
  return (
    typeof email === "string" &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  );
}

function requireUser(req, res, next) {
  const user = getCurrentUser(req);

  if (!user) {
    return res
      .status(401)
      .json({
        error: "Please login first."
      });
  }

  req.user = user;

  next();
}

/* =====================================================
   HEALTH
===================================================== */

app.get("/health", (req, res) => {
  res.json({
    success: true,
    status: "OK"
  });
});

/* =====================================================
   CURRENT USER
===================================================== */

app.get("/api/me", (req, res) => {
  res.json(
    safeUser(
      getCurrentUser(req)
    )
  );
});

/* =====================================================
   REGISTER
===================================================== */

app.post("/api/register", async (req, res) => {
  try {
    const name = cleanText(
      req.body.name,
      80
    );

    const email = cleanText(
      req.body.email,
      150
    ).toLowerCase();

    const password = String(
      req.body.password || ""
    );

    if (!name || !email || !password) {
      return res
        .status(400)
        .json({
          error:
            "Please complete all fields."
        });
    }

    if (!validEmail(email)) {
      return res
        .status(400)
        .json({
          error:
            "Invalid email address."
        });
    }

    if (password.length < 6) {
      return res
        .status(400)
        .json({
          error:
            "Password must contain at least 6 characters."
        });
    }

    if (
      db.users.some(
        u => u.email === email
      )
    ) {
      return res
        .status(400)
        .json({
          error:
            "Account with this email already exists."
        });
    }

    const hashedPassword =
      await hashPassword(password);

    const user = {
      id: nextId(db.users),
      name,
      email,
      password: hashedPassword,
      role: "user",
      balance: 0,
      createdAt:
        new Date().toISOString()
    };

    db.users.push(user);

    await saveDatabase();

    req.session.regenerate(err => {
      if (err) {
        console.error(
          "Session regeneration error:",
          err
        );

        return res
          .status(500)
          .json({
            error:
              "Session creation failed."
          });
      }

      req.session.userId =
        user.id;

      req.session.save(err2 => {
        if (err2) {
          return res
            .status(500)
            .json({
              error:
                "Session save failed."
            });
        }

        res.json(
          safeUser(user)
        );
      });
    });
  } catch (error) {
    console.error(
      "Registration error:",
      error
    );

    res
      .status(500)
      .json({
        error:
          "Registration failed."
      });
  }
});

/* =====================================================
   LOGIN
===================================================== */

app.post("/api/login", async (req, res) => {
  try {
    const email = cleanText(
      req.body.email,
      150
    ).toLowerCase();

    const password = String(
      req.body.password || ""
    );

    const user = db.users.find(
      u => u.email === email
    );

    if (!user) {
      return res
        .status(401)
        .json({
          error:
            "Invalid email or password."
        });
    }

    const correct =
      await verifyPassword(
        password,
        user.password
      );

    if (!correct) {
      return res
        .status(401)
        .json({
          error:
            "Invalid email or password."
        });
    }

    req.session.regenerate(err => {
      if (err) {
        return res
          .status(500)
          .json({
            error:
              "Login failed."
          });
      }

      req.session.userId =
        user.id;

      req.session.save(err2 => {
        if (err2) {
          return res
            .status(500)
            .json({
              error:
                "Session save failed."
            });
        }

        res.json(
          safeUser(user)
        );
      });
    });
  } catch (error) {
    console.error(
      "Login error:",
      error
    );

    res
      .status(500)
      .json({
        error:
          "Login error."
      });
  }
});

/* =====================================================
   LOGOUT
===================================================== */

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie(
      "taskearn.sid"
    );

    res.json({
      success: true
    });
  });
});

/* =====================================================
   TASKS
===================================================== */

app.get(
  "/api/tasks",
  requireUser,
  (req, res) => {
    const tasks =
      db.tasks
        .filter(t => t.active)
        .map(t => ({
          ...t,
          reward:
            Number(t.reward)
        }));

    res.json(tasks);
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
        Number(req.params.id);

      const task =
        db.tasks.find(
          t =>
            t.id === taskId &&
            t.active
        );

      if (!task) {
        return res
          .status(404)
          .json({
            error:
              "Task not found."
          });
      }

      const existing =
        db.submissions.find(
          s =>
            s.userId ===
              req.user.id &&
            s.taskId ===
              task.id &&
            s.status ===
              "pending"
        );

      if (existing) {
        return res
          .status(400)
          .json({
            error:
              "You already submitted this task."
          });
      }

      const submission = {
        id: nextId(
          db.submissions
        ),

        userId:
          req.user.id,

        taskId:
          task.id,

        taskTitle:
          task.title,

        reward:
          Number(task.reward),

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
        success: true,
        message:
          "Task submitted for review."
      });
    } catch (error) {
      console.error(
        "Submission error:",
        error
      );

      res
        .status(500)
        .json({
          error:
            "Submission failed."
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
    const userSubmissions =
      db.submissions.filter(
        s =>
          s.userId ===
          req.user.id
      );

    res.json(
      userSubmissions
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
    const userSubmissions =
      db.submissions.filter(
        s =>
          s.userId ===
            req.user.id &&
          s.status ===
            "approved"
      );

    const userWithdrawals =
      db.withdrawals.filter(
        w =>
          w.userId ===
          req.user.id
      );

    res.json({
      balance:
        Number(
          req.user.balance ||
            0
        ),

      completed:
        userSubmissions.length,

      withdrawals:
        userWithdrawals
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

      if (
        !Number.isFinite(
          amount
        ) ||
        amount < 100
      ) {
        return res
          .status(400)
          .json({
            error:
              "Minimum withdrawal is ₹100."
          });
      }

      if (!method) {
        return res
          .status(400)
          .json({
            error:
              "Please select a payment method."
          });
      }

      const user =
        db.users.find(
          u =>
            u.id ===
            req.user.id
        );

      if (
        !user ||
        Number(user.balance || 0) <
          amount
      ) {
        return res
          .status(400)
          .json({
            error:
              "Insufficient balance."
          });
      }

      user.balance =
        Number(
          user.balance || 0
        ) - amount;

      db.withdrawals.push({
        id: nextId(
          db.withdrawals
        ),

        userId:
          user.id,

        amount,

        method,

        status:
          "pending",

        createdAt:
          new Date().toISOString()
      });

      await saveDatabase();

      res.json({
        success: true,
        message:
          "Withdrawal request submitted."
      });
    } catch (error) {
      console.error(
        "Withdrawal error:",
        error
      );

      res
        .status(500)
        .json({
          error:
            "Withdrawal failed."
        });
    }
  }
);

/* =====================================================
   FALLBACK
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
   SERVER START
===================================================== */

const PORT = Number(
  process.env.PORT || 3000
);

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `TaskEarn server running on port ${PORT}`
    );
  }
);
