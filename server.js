const express = require("express");
const session = require("express-session");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");

const app = express();

app.set("trust proxy", 1);

/* =====================================================
   CONFIGURATION
===================================================== */

const PORT = process.env.PORT || 10000;

const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  crypto.randomBytes(32).toString("hex");

const DATA_DIR = path.join(__dirname, "data");

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const DB_FILE = path.join(DATA_DIR, "taskearn.db");

/* =====================================================
   DATABASE
===================================================== */

const db = new Database(DB_FILE);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'Member',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'General',
    reward REAL NOT NULL DEFAULT 0,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    task_id INTEGER NOT NULL,
    task_title TEXT NOT NULL,
    reward REAL NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending',
    submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reviewed_at TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS wallets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    balance REAL NOT NULL DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS withdrawals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    amount REAL NOT NULL,
    method TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

/* =====================================================
   DEFAULT TASKS
===================================================== */

const taskCount =
  db.prepare(
    "SELECT COUNT(*) AS count FROM tasks"
  ).get().count;

if (taskCount === 0) {

  const insertTask =
    db.prepare(`
      INSERT INTO tasks
      (title, description, type, reward)
      VALUES (?, ?, ?, ?)
    `);

  const addTasks = db.transaction(() => {

    insertTask.run(
      "Social Media Task",
      "Complete the social media activity according to the task requirements.",
      "Social",
      10
    );

    insertTask.run(
      "Website Visit",
      "Visit the required website and complete the instructions.",
      "Website",
      5
    );

    insertTask.run(
      "Simple Research",
      "Complete the research task and submit it for review.",
      "Research",
      15
    );

  });

  addTasks();
}

/* =====================================================
   EXPRESS MIDDLEWARE
===================================================== */

app.use(
  express.json({
    limit: "100kb"
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: "100kb"
  })
);

/* =====================================================
   SESSION
===================================================== */

app.use(
  session({
    name: "taskearn.sid",

    secret: SESSION_SECRET,

    resave: false,

    saveUninitialized: false,

    rolling: true,

    cookie: {
      httpOnly: true,

      secure:
        process.env.NODE_ENV === "production",

      sameSite: "lax",

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
   STATIC FILES
===================================================== */

app.use(
  express.static(
    path.join(__dirname, "public")
  )
);

/* =====================================================
   SECURITY HELPERS
===================================================== */

function normalizeEmail(email) {

  return String(email || "")
    .trim()
    .toLowerCase();

}


function cleanName(name) {

  return String(name || "")
    .trim()
    .replace(/\s+/g, " ");

}


function isValidEmail(email) {

  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    .test(email);

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
    createdAt: user.created_at
  };

}

/* =====================================================
   AUTH MIDDLEWARE
===================================================== */

function requireLogin(req, res, next) {

  if (!req.session.userId) {

    return res.status(401).json({
      error: "Please login first."
    });

  }

  next();

}


/* =====================================================
   USER WALLET
===================================================== */

function ensureWallet(userId) {

  db.prepare(`
    INSERT OR IGNORE INTO wallets
    (user_id, balance)
    VALUES (?, 0)
  `).run(userId);

}


/* =====================================================
   REGISTER
===================================================== */

app.post(
  "/api/register",
  async (req, res) => {

    try {

      const name =
        cleanName(req.body.name);

      const email =
        normalizeEmail(req.body.email);

      const password =
        String(req.body.password || "");

      if (!name) {

        return res.status(400).json({
          error: "Please enter your name."
        });

      }

      if (name.length > 100) {

        return res.status(400).json({
          error: "Name is too long."
        });

      }

      if (!isValidEmail(email)) {

        return res.status(400).json({
          error: "Please enter a valid email address."
        });

      }

      if (password.length < 6) {

        return res.status(400).json({
          error:
            "Password must be at least 6 characters."
        });

      }

      if (password.length > 100) {

        return res.status(400).json({
          error: "Password is too long."
        });

      }

      const existing =
        db.prepare(`
          SELECT id
          FROM users
          WHERE email = ?
        `).get(email);

      if (existing) {

        return res.status(409).json({
          error:
            "An account with this email already exists."
        });

      }

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      const result =
        db.prepare(`
          INSERT INTO users
          (name, email, password_hash, role)
          VALUES (?, ?, ?, 'Member')
        `).run(
          name,
          email,
          passwordHash
        );

      const userId =
        result.lastInsertRowid;

      ensureWallet(userId);

      req.session.userId =
        userId;

      const user =
        db.prepare(`
          SELECT
            id,
            name,
            email,
            role,
            created_at
          FROM users
          WHERE id = ?
        `).get(userId);

      req.session.save(() => {

        res.json(
          safeUser(user)
        );

      });

    }

    catch (error) {

      console.error(
        "REGISTER ERROR:",
        error
      );

      res.status(500).json({
        error:
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

      if (!email || !password) {

        return res.status(400).json({
          error:
            "Please enter email and password."
        });

      }

      const user =
        db.prepare(`
          SELECT *
          FROM users
          WHERE email = ?
        `).get(email);

      if (!user) {

        return res.status(401).json({
          error:
            "Invalid email or password."
        });

      }

      const passwordValid =
        await bcrypt.compare(
          password,
          user.password_hash
        );

      if (!passwordValid) {

        return res.status(401).json({
          error:
            "Invalid email or password."
        });

      }

      ensureWallet(user.id);

      req.session.regenerate(
        err => {

          if (err) {

            console.error(
              "SESSION ERROR:",
              err
            );

            return res.status(500).json({
              error:
                "Unable to create secure session."
            });

          }

          req.session.userId =
            user.id;

          req.session.save(
            saveError => {

              if (saveError) {

                console.error(
                  "SESSION SAVE ERROR:",
                  saveError
                );

                return res.status(500).json({
                  error:
                    "Unable to save session."
                });

              }

              res.json(
                safeUser(user)
              );

            }
          );

        }
      );

    }

    catch (error) {

      console.error(
        "LOGIN ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to login."
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

    if (!req.session.userId) {

      return res.json(null);

    }

    const user =
      db.prepare(`
        SELECT
          id,
          name,
          email,
          role,
          created_at
        FROM users
        WHERE id = ?
      `).get(
        req.session.userId
      );

    if (!user) {

      req.session.destroy(
        () => {}
      );

      return res.json(null);

    }

    res.json(
      safeUser(user)
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
      err => {

        if (err) {

          console.error(
            "LOGOUT ERROR:",
            err
          );

          return res.status(500).json({
            error:
              "Unable to logout."
          });

        }

        res.clearCookie(
          "taskearn.sid"
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
   TASKS
===================================================== */

app.get(
  "/api/tasks",
  requireLogin,
  (req, res) => {

    try {

      const tasks =
        db.prepare(`
          SELECT
            id,
            title,
            description,
            type,
            reward,
            created_at
          FROM tasks
          WHERE active = 1
          ORDER BY id DESC
        `).all();

      res.json(tasks);

    }

    catch (error) {

      console.error(
        "TASKS ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load tasks."
      });

    }

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

      if (
        !Number.isInteger(taskId) ||
        taskId <= 0
      ) {

        return res.status(400).json({
          error:
            "Invalid task."
        });

      }

      const task =
        db.prepare(`
          SELECT *
          FROM tasks
          WHERE id = ?
          AND active = 1
        `).get(taskId);

      if (!task) {

        return res.status(404).json({
          error:
            "Task not found."
        });

      }

      const alreadySubmitted =
        db.prepare(`
          SELECT id
          FROM submissions
          WHERE user_id = ?
          AND task_id = ?
          AND status = 'pending'
        `).get(
          req.session.userId,
          taskId
        );

      if (alreadySubmitted) {

        return res.status(409).json({
          error:
            "You already submitted this task and it is under review."
        });

      }

      db.prepare(`
        INSERT INTO submissions
        (
          user_id,
          task_id,
          task_title,
          reward,
          status
        )
        VALUES (?, ?, ?, ?, 'pending')
      `).run(
        req.session.userId,
        task.id,
        task.title,
        Number(task.reward)
      );

      res.json({
        message:
          "Task submitted for review!"
      });

    }

    catch (error) {

      console.error(
        "TASK SUBMISSION ERROR:",
        error
      );

      res.status(500).json({
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

    try {

      const submissions =
        db.prepare(`
          SELECT
            id,
            task_id AS taskId,
            task_title AS taskTitle,
            reward,
            status,
            submitted_at AS submittedAt,
            reviewed_at AS reviewedAt
          FROM submissions
          WHERE user_id = ?
          ORDER BY id DESC
        `).all(
          req.session.userId
        );

      res.json(
        submissions
      );

    }

    catch (error) {

      console.error(
        "SUBMISSIONS ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load submissions."
      });

    }

  }
);


/* =====================================================
   WALLET
===================================================== */

app.get(
  "/api/wallet",
  requireLogin,
  (req, res) => {

    try {

      ensureWallet(
        req.session.userId
      );

      const wallet =
        db.prepare(`
          SELECT
            balance
          FROM wallets
          WHERE user_id = ?
        `).get(
          req.session.userId
        );

      const completed =
        db.prepare(`
          SELECT COUNT(*) AS count
          FROM submissions
          WHERE user_id = ?
          AND status = 'approved'
        `).get(
          req.session.userId
        );

      const withdrawals =
        db.prepare(`
          SELECT
            id,
            amount,
            method,
            status,
            created_at AS createdAt
          FROM withdrawals
          WHERE user_id = ?
          ORDER BY id DESC
        `).all(
          req.session.userId
        );

      res.json({

        balance:
          Number(
            wallet?.balance || 0
          ),

        completed:
          Number(
            completed?.count || 0
          ),

        withdrawals

      });

    }

    catch (error) {

      console.error(
        "WALLET ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load wallet."
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

      const amount =
        Number(
          req.body.amount
        );

      const method =
        String(
          req.body.method || ""
        )
        .trim();

      if (
        !Number.isFinite(amount) ||
        amount < 100
      ) {

        return res.status(400).json({
          error:
            "Minimum withdrawal amount is ₹100."
        });

      }

      if (amount > 1000000) {

        return res.status(400).json({
          error:
            "Invalid withdrawal amount."
        });

      }

      if (!method) {

        return res.status(400).json({
          error:
            "Please enter payment method."
        });

      }

      if (method.length > 100) {

        return res.status(400).json({
          error:
            "Payment method is too long."
        });

      }

      ensureWallet(
        req.session.userId
      );

      const wallet =
        db.prepare(`
          SELECT balance
          FROM wallets
          WHERE user_id = ?
        `).get(
          req.session.userId
        );

      const balance =
        Number(
          wallet?.balance || 0
        );

      if (amount > balance) {

        return res.status(400).json({
          error:
            "Insufficient wallet balance."
        });

      }

      const transaction =
        db.transaction(() => {

          db.prepare(`
            UPDATE wallets
            SET balance = balance - ?
            WHERE user_id = ?
          `).run(
            amount,
            req.session.userId
          );

          db.prepare(`
            INSERT INTO withdrawals
            (
              user_id,
              amount,
              method,
              status
            )
            VALUES (?, ?, ?, 'pending')
          `).run(
            req.session.userId,
            amount,
            method
          );

        });

      transaction();

      res.json({
        message:
          "Withdrawal request submitted successfully."
      });

    }

    catch (error) {

      console.error(
        "WITHDRAW ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to submit withdrawal request."
      });

    }

  }
);


/* =====================================================
   ACCOUNT DETAILS
===================================================== */

app.get(
  "/api/account",
  requireLogin,
  (req, res) => {

    try {

      const user =
        db.prepare(`
          SELECT
            id,
            name,
            email,
            role,
            created_at
          FROM users
          WHERE id = ?
        `).get(
          req.session.userId
        );

      if (!user) {

        return res.status(404).json({
          error:
            "Account not found."
        });

      }

      res.json({
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        createdAt: user.created_at
      });

    }

    catch (error) {

      console.error(
        "ACCOUNT ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load account details."
      });

    }

  }
);


/* =====================================================
   HEALTH CHECK
===================================================== */

app.get(
  "/health",
  (req, res) => {

    res.json({
      status: "ok",
      service: "TaskEarn",
      time: new Date().toISOString()
    });

  }
);


/* =====================================================
   FRONTEND FALLBACK
===================================================== */

app.get(
  "*",
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
      "SERVER ERROR:",
      err
    );

    if (res.headersSent) {

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

  }
);


/* =====================================================
   SAFE SHUTDOWN
===================================================== */

function shutdown() {

  console.log(
    "Shutting down TaskEarn..."
  );

  try {

    db.close();

  }

  catch (e) {

    console.error(e);

  }

  process.exit(0);

}

process.on(
  "SIGTERM",
  shutdown
);

process.on(
  "SIGINT",
  shutdown
);
