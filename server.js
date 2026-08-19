const express = require("express");
const session = require("express-session");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");

const app = express();

/* =====================================================
   BASIC CONFIG
===================================================== */

app.set("trust proxy", 1);

const PORT = process.env.PORT || 10000;

const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  "taskearn-change-this-session-secret";

/* =====================================================
   MIDDLEWARE
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

app.use(
  session({
    secret: SESSION_SECRET,

    resave: false,

    saveUninitialized: false,

    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 7 * 24 * 60 * 60 * 1000
    }
  })
);

/* =====================================================
   DATABASE
===================================================== */

const DATA_DIR = path.join(
  __dirname,
  "data"
);

const DB_FILE = path.join(
  DATA_DIR,
  "taskearn.json"
);

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, {
    recursive: true
  });
}

function createEmptyDatabase() {
  return {
    users: [],
    tasks: [],
    submissions: [],
    withdrawals: []
  };
}

function loadDatabase() {
  try {
    if (!fs.existsSync(DB_FILE)) {
      const db = createEmptyDatabase();
      saveDatabase(db);
      return db;
    }

    const raw = fs.readFileSync(
      DB_FILE,
      "utf8"
    );

    const db = JSON.parse(raw);

    return {
      users: Array.isArray(db.users)
        ? db.users
        : [],

      tasks: Array.isArray(db.tasks)
        ? db.tasks
        : [],

      submissions: Array.isArray(db.submissions)
        ? db.submissions
        : [],

      withdrawals: Array.isArray(db.withdrawals)
        ? db.withdrawals
        : []
    };

  } catch (error) {

    console.error(
      "Database load error:",
      error
    );

    return createEmptyDatabase();
  }
}

function saveDatabase(db) {

  const tempFile =
    DB_FILE + ".tmp";

  fs.writeFileSync(
    tempFile,
    JSON.stringify(
      db,
      null,
      2
    ),
    "utf8"
  );

  fs.renameSync(
    tempFile,
    DB_FILE
  );
}

let db = loadDatabase();

/* =====================================================
   DEFAULT ADMIN
===================================================== */

async function createDefaultAdmin() {

  const adminEmail =
    process.env.ADMIN_EMAIL ||
    "admin@taskearn.com";

  const adminPassword =
    process.env.ADMIN_PASSWORD ||
    "Admin@12345";

  const existingAdmin =
    db.users.find(
      user =>
        user.email.toLowerCase() ===
        adminEmail.toLowerCase()
    );

  if (existingAdmin) {

    if (existingAdmin.role !== "admin") {

      existingAdmin.role =
        "admin";

      saveDatabase(db);
    }

    return;
  }

  const passwordHash =
    await bcrypt.hash(
      adminPassword,
      12
    );

  db.users.push({

    id: crypto
      .randomUUID(),

    name: "TaskEarn Admin",

    email:
      adminEmail.toLowerCase(),

    passwordHash,

    role: "admin",

    balance: 0,

    createdAt:
      new Date().toISOString()

  });

  saveDatabase(db);

  console.log(
    "Default admin created:"
  );

  console.log(
    "Email:",
    adminEmail
  );

  console.log(
    "Password:",
    adminPassword
  );
}

/* =====================================================
   HELPERS
===================================================== */

function cleanUser(user) {

  if (!user) {
    return null;
  }

  return {
    id: user.id,

    name: user.name,

    email: user.email,

    role:
      user.role || "member",

    balance:
      Number(user.balance || 0),

    createdAt:
      user.createdAt || null
  };
}

function findUserById(id) {

  return db.users.find(
    user =>
      user.id === id
  );
}

function findUserByEmail(email) {

  return db.users.find(
    user =>
      user.email.toLowerCase() ===
      email.toLowerCase()
  );
}

function requireLogin(
  req,
  res,
  next
) {

  if (!req.session.userId) {

    return res.status(401).json({
      error:
        "Please login first."
    });

  }

  const user =
    findUserById(
      req.session.userId
    );

  if (!user) {

    req.session.destroy(
      () => {}
    );

    return res.status(401).json({
      error:
        "Session expired. Please login again."
    });
  }

  req.user = user;

  next();
}

function requireAdmin(
  req,
  res,
  next
) {

  if (!req.session.userId) {

    return res.status(401).json({
      error:
        "Please login first."
    });
  }

  const user =
    findUserById(
      req.session.userId
    );

  if (!user) {

    return res.status(401).json({
      error:
        "Invalid session."
    });
  }

  if (user.role !== "admin") {

    return res.status(403).json({
      error:
        "Admin access required."
    });
  }

  req.user = user;

  next();
}

function safeNumber(
  value,
  fallback = 0
) {

  const number =
    Number(value);

  if (
    !Number.isFinite(number)
  ) {
    return fallback;
  }

  return number;
}

/* =====================================================
   HEALTH
===================================================== */

app.get(
  "/health",
  (req, res) => {

    res.json({
      ok: true,
      service: "TaskEarn",
      time:
        new Date().toISOString()
    });

  }
);

/* =====================================================
   SESSION / CURRENT USER
===================================================== */

app.get(
  "/api/me",
  (req, res) => {

    if (!req.session.userId) {

      return res.json(null);
    }

    const user =
      findUserById(
        req.session.userId
      );

    if (!user) {

      return res.json(null);
    }

    res.json(
      cleanUser(user)
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
        String(
          req.body.name || ""
        ).trim();

      const email =
        String(
          req.body.email || ""
        )
          .trim()
          .toLowerCase();

      const password =
        String(
          req.body.password || ""
        );

      if (!name) {

        return res.status(400).json({
          error:
            "Please enter your name."
        });

      }

      if (!email) {

        return res.status(400).json({
          error:
            "Please enter your email."
        });

      }

      if (!email.includes("@")) {

        return res.status(400).json({
          error:
            "Please enter a valid email address."
        });

      }

      if (password.length < 6) {

        return res.status(400).json({
          error:
            "Password must contain at least 6 characters."
        });

      }

      const existing =
        findUserByEmail(
          email
        );

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

      const user = {

        id:
          crypto.randomUUID(),

        name,

        email,

        passwordHash,

        role: "member",

        balance: 0,

        createdAt:
          new Date().toISOString()

      };

      db.users.push(
        user
      );

      saveDatabase(db);

      req.session.userId =
        user.id;

      res.json(
        cleanUser(user)
      );

    }

    catch (error) {

      console.error(
        "Register error:",
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
        String(
          req.body.email || ""
        )
          .trim()
          .toLowerCase();

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
        findUserByEmail(
          email
        );

      if (!user) {

        return res.status(401).json({
          error:
            "Invalid email or password."
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

      req.session.userId =
        user.id;

      res.json(
        cleanUser(user)
      );

    }

    catch (error) {

      console.error(
        "Login error:",
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
          success: true
        });

      }
    );

  }
);

/* =====================================================
   ACCOUNT DETAILS
===================================================== */

app.get(
  "/api/account",
  requireLogin,
  (req, res) => {

    const user =
      req.user;

    const submissions =
      db.submissions.filter(
        item =>
          item.userId ===
          user.id
      );

    const withdrawals =
      db.withdrawals.filter(
        item =>
          item.userId ===
          user.id
      );

    const completed =
      submissions.filter(
        item =>
          item.status ===
          "approved"
      ).length;

    res.json({

      id:
        user.id,

      name:
        user.name,

      email:
        user.email,

      role:
        user.role || "member",

      balance:
        Number(
          user.balance || 0
        ),

      completed,

      totalSubmissions:
        submissions.length,

      totalWithdrawals:
        withdrawals.length,

      createdAt:
        user.createdAt

    });

  }
);

/* =====================================================
   UPDATE ACCOUNT DETAILS
===================================================== */

app.put(
  "/api/account",
  requireLogin,
  (req, res) => {

    const name =
      String(
        req.body.name || ""
      ).trim();

    if (!name) {

      return res.status(400).json({
        error:
          "Name cannot be empty."
      });

    }

    req.user.name =
      name;

    saveDatabase(db);

    res.json(
      cleanUser(
        req.user
      )
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

    const tasks =
      db.tasks
        .filter(
          task =>
            task.active !== false
        )
        .map(task => ({

          id:
            task.id,

          title:
            task.title,

          description:
            task.description,

          type:
            task.type || "General",

          reward:
            Number(
              task.reward || 0
            ),

          createdAt:
            task.createdAt

        }));

    res.json(
      tasks
    );

  }
);

/* =====================================================
   TASK DETAILS
===================================================== */

app.get(
  "/api/tasks/:id",
  requireLogin,
  (req, res) => {

    const task =
      db.tasks.find(
        item =>
          String(item.id) ===
          String(req.params.id)
      );

    if (!task) {

      return res.status(404).json({
        error:
          "Task not found."
      });

    }

    res.json(
      task
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

    const task =
      db.tasks.find(
        item =>
          String(item.id) ===
          String(req.params.id)
      );

    if (!task) {

      return res.status(404).json({
        error:
          "Task not found."
      });

    }

    if (task.active === false) {

      return res.status(400).json({
        error:
          "This task is no longer available."
      });

    }

    const existing =
      db.submissions.find(
        item =>
          item.userId ===
            req.user.id &&
          String(item.taskId) ===
            String(task.id) &&
          item.status ===
            "pending"
      );

    if (existing) {

      return res.status(400).json({
        error:
          "You already submitted this task."
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
          task.reward || 0
        ),

      status:
        "pending",

      submittedAt:
        new Date().toISOString(),

      reviewedAt:
        null

    };

    db.submissions.push(
      submission
    );

    saveDatabase(db);

    res.json({

      success: true,

      message:
        "Task submitted for review!",

      submission

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

    const submissions =
      db.submissions
        .filter(
          item =>
            item.userId ===
            req.user.id
        )
        .sort(
          (a, b) =>
            new Date(b.submittedAt) -
            new Date(a.submittedAt)
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
  requireLogin,
  (req, res) => {

    const submissions =
      db.submissions.filter(
        item =>
          item.userId ===
          req.user.id
      );

    const completed =
      submissions.filter(
        item =>
          item.status ===
          "approved"
      ).length;

    const withdrawals =
      db.withdrawals
        .filter(
          item =>
            item.userId ===
            req.user.id
        )
        .sort(
          (a, b) =>
            new Date(b.createdAt) -
            new Date(a.createdAt)
        );

    res.json({

      balance:
        Number(
          req.user.balance || 0
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

    const amount =
      safeNumber(
        req.body.amount
      );

    const method =
      String(
        req.body.method || ""
      ).trim();

    if (
      !Number.isFinite(amount) ||
      amount < 100
    ) {

      return res.status(400).json({
        error:
          "Minimum withdrawal amount is ₹100."
      });

    }

    if (!method) {

      return res.status(400).json({
        error:
          "Please enter payment method."
      });

    }

    if (
      amount >
      Number(req.user.balance || 0)
    ) {

      return res.status(400).json({
        error:
          "Insufficient wallet balance."
      });

    }

    const withdrawal = {

      id:
        crypto.randomUUID(),

      userId:
        req.user.id,

      amount:

        Math.round(
          amount * 100
        ) / 100,

      method,

      status:
        "pending",

      createdAt:
        new Date().toISOString(),

      reviewedAt:
        null

    };

    /*
      Reserve the requested amount
      immediately so the user cannot
      request the same money twice.
    */

    req.user.balance =
      Math.round(
        (
          Number(
            req.user.balance || 0
          ) - amount
        ) * 100
      ) / 100;

    db.withdrawals.push(
      withdrawal
    );

    saveDatabase(db);

    res.json({

      success: true,

      message:
        "Withdrawal request submitted.",

      withdrawal,

      balance:
        req.user.balance

    });

  }
);

/* =====================================================
   ADMIN - STATS
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
        db.users.length,

      tasks:
        db.tasks.length,

      submissions:
        db.submissions.length,

      pendingSubmissions,

      withdrawals:
        db.withdrawals.length,

      pendingWithdrawals

    });

  }
);

/* =====================================================
   ADMIN - USERS
===================================================== */

app.get(
  "/api/admin/users",
  requireAdmin,
  (req, res) => {

    res.json(
      db.users.map(
        cleanUser
      )
    );

  }
);

/* =====================================================
   ADMIN - TASKS
===================================================== */

app.get(
  "/api/admin/tasks",
  requireAdmin,
  (req, res) => {

    res.json(
      db.tasks
    );

  }
);

/* =====================================================
   ADMIN - CREATE TASK
===================================================== */

app.post(
  "/api/admin/tasks",
  requireAdmin,
  (req, res) => {

    const title =
      String(
        req.body.title || ""
      ).trim();

    const description =
      String(
        req.body.description || ""
      ).trim();

    const type =
      String(
        req.body.type || "General"
      ).trim();

    const reward =
      safeNumber(
        req.body.reward
      );

    if (!title) {

      return res.status(400).json({
        error:
          "Task title is required."
      });

    }

    if (reward <= 0) {

      return res.status(400).json({
        error:
          "Reward must be greater than zero."
      });

    }

    const task = {

      id:
        Date.now(),

      title,

      description,

      type,

      reward:

        Math.round(
          reward * 100
        ) / 100,

      active:
        true,

      createdAt:
        new Date().toISOString()

    };

    db.tasks.push(
      task
    );

    saveDatabase(db);

    res.json(
      task
    );

  }
);

/* =====================================================
   ADMIN - UPDATE TASK
===================================================== */

app.put(
  "/api/admin/tasks/:id",
  requireAdmin,
  (req, res) => {

    const task =
      db.tasks.find(
        item =>
          String(item.id) ===
          String(req.params.id)
      );

    if (!task) {

      return res.status(404).json({
        error:
          "Task not found."
      });

    }

    if (
      req.body.title !==
      undefined
    ) {

      task.title =
        String(
          req.body.title
        ).trim();

    }

    if (
      req.body.description !==
      undefined
    ) {

      task.description =
        String(
          req.body.description
        ).trim();

    }

    if (
      req.body.type !==
      undefined
    ) {

      task.type =
        String(
          req.body.type
        ).trim();

    }

    if (
      req.body.reward !==
      undefined
    ) {

      const reward =
        safeNumber(
          req.body.reward
        );

      if (reward <= 0) {

        return res.status(400).json({
          error:
            "Invalid reward."
        });

      }

      task.reward =
        Math.round(
          reward * 100
        ) / 100;

    }

    if (
      req.body.active !==
      undefined
    ) {

      task.active =
        Boolean(
          req.body.active
        );

    }

    saveDatabase(db);

    res.json(
      task
    );

  }
);

/* =====================================================
   ADMIN - DELETE TASK
===================================================== */

app.delete(
  "/api/admin/tasks/:id",
  requireAdmin,
  (req, res) => {

    const index =
      db.tasks.findIndex(
        item =>
          String(item.id) ===
          String(req.params.id)
      );

    if (index === -1) {

      return res.status(404).json({
        error:
          "Task not found."
      });

    }

    db.tasks.splice(
      index,
      1
    );

    saveDatabase(db);

    res.json({
      success: true
    });

  }
);

/* =====================================================
   ADMIN - SUBMISSIONS
===================================================== */

app.get(
  "/api/admin/submissions",
  requireAdmin,
  (req, res) => {

    const list =
      db.submissions.map(
        item => {

          const user =
            findUserById(
              item.userId
            );

          return {

            ...item,

            userName:
              user
                ? user.name
                : "Unknown",

            userEmail:
              user
                ? user.email
                : "Unknown"

          };

        }
      );

    res.json(
      list
    );

  }
);

/* =====================================================
   ADMIN - REVIEW SUBMISSION
===================================================== */

app.post(
  "/api/admin/submissions/:id/review",
  requireAdmin,
  (req, res) => {

    const submission =
      db.submissions.find(
        item =>
          String(item.id) ===
          String(req.params.id)
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

    const decision =
      String(
        req.body.status || ""
      ).toLowerCase();

    if (
      decision !== "approved" &&
      decision !== "rejected"
    ) {

      return res.status(400).json({
        error:
          "Status must be approved or rejected."
      });

    }

    const user =
      findUserById(
        submission.userId
      );

    if (!user) {

      return res.status(404).json({
        error:
          "User not found."
      });

    }

    submission.status =
      decision;

    submission.reviewedAt =
      new Date().toISOString();

    /*
      Add reward only once
      when approved.
    */

    if (
      decision ===
      "approved"
    ) {

      user.balance =
        Math.round(
          (
            Number(
              user.balance || 0
            ) +
            Number(
              submission.reward || 0
            )
          ) * 100
        ) / 100;

    }

    saveDatabase(db);

    res.json({

      success: true,

      submission,

      user:
        cleanUser(user)

    });

  }
);

/* =====================================================
   ADMIN - WITHDRAWALS
===================================================== */

app.get(
  "/api/admin/withdrawals",
  requireAdmin,
  (req, res) => {

    const list =
      db.withdrawals.map(
        item => {

          const user =
            findUserById(
              item.userId
            );

          return {

            ...item,

            userName:
              user
                ? user.name
                : "Unknown",

            userEmail:
              user
                ? user.email
                : "Unknown"

          };

        }
      );

    res.json(
      list
    );

  }
);

/* =====================================================
   ADMIN - REVIEW WITHDRAWAL
===================================================== */

app.post(
  "/api/admin/withdrawals/:id/review",
  requireAdmin,
  (req, res) => {

    const withdrawal =
      db.withdrawals.find(
        item =>
          String(item.id) ===
          String(req.params.id)
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

    const decision =
      String(
        req.body.status || ""
      ).toLowerCase();

    if (
      decision !== "approved" &&
      decision !== "rejected"
    ) {

      return res.status(400).json({
        error:
          "Status must be approved or rejected."
      });

    }

    const user =
      findUserById(
        withdrawal.userId
      );

    if (!user) {

      return res.status(404).json({
        error:
          "User not found."
      });

    }

    withdrawal.status =
      decision;

    withdrawal.reviewedAt =
      new Date().toISOString();

    /*
      We already reserved the money
      when the withdrawal was created.

      If admin rejects the withdrawal,
      return the money to the wallet.
    */

    if (
      decision ===
      "rejected"
    ) {

      user.balance =
        Math.round(
          (
            Number(
              user.balance || 0
            ) +
            Number(
              withdrawal.amount || 0
            )
          ) * 100
        ) / 100;

    }

    saveDatabase(db);

    res.json({

      success: true,

      withdrawal,

      user:
        cleanUser(user)

    });

  }
);

/* =====================================================
   PUBLIC INFORMATION APIs
===================================================== */

app.get(
  "/api/about",
  (req, res) => {

    res.json({
      title:
        "About TaskEarn",

      content:
        "TaskEarn is an online task and reward platform designed to provide users with access to eligible tasks, task submissions, reward tracking and account management features."
    });

  }
);

app.get(
  "/api/terms",
  (req, res) => {

    res.json({
      title:
        "Terms & Conditions",

      content:
        "Users must use TaskEarn honestly and lawfully. Task submissions are subject to review and approval. TaskEarn does not guarantee fixed income or continuous task availability."
    });

  }
);

app.get(
  "/api/privacy",
  (req, res) => {

    res.json({
      title:
        "Privacy Policy",

      content:
        "TaskEarn may collect account, task and transaction information required to provide and secure the service."
    });

  }
);

app.get(
  "/api/contact",
  (req, res) => {

    res.json({
      title:
        "Contact Us",

      email:
        "support@taskearn.demo"
    });

  }
);

/* =====================================================
   STATIC WEBSITE
===================================================== */

const PUBLIC_DIR =
  path.join(
    __dirname,
    "public"
  );

app.use(
  express.static(
    PUBLIC_DIR
  )
);

/* =====================================================
   SPA FALLBACK
===================================================== */

app.get(
  "/{*splat}",
  (req, res) => {

    const indexFile = path.join(
      PUBLIC_DIR,
      "index.html"
    );

    if (fs.existsSync(indexFile)) {
      return res.sendFile(indexFile);
    }

    return res.status(404).send(
      "TaskEarn website is not configured correctly."
    );
  }
);

/* =====================================================
   ERROR HANDLER
===================================================== */

app.use(
  (
    error,
    req,
    res,
    next
  ) => {

    console.error(
      "Server error:",
      error
    );

    if (
      res.headersSent
    ) {

      return next(error);

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

createDefaultAdmin()
  .then(() => {

    app.listen(
      PORT,
      "0.0.0.0",
      () => {

        console.log(
          "================================="
        );

        console.log(
          "TaskEarn server started"
        );

        console.log(
          "Port:",
          PORT
        );

        console.log(
          "================================="
        );

      }
    );

  })
  .catch(
    error => {

      console.error(
        "Startup error:",
        error
      );

      process.exit(1);

    }
  );
