const express = require("express");
const session = require("express-session");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");

const app = express();

app.set("trust proxy", 1);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* =====================================================
   DATABASE FILE
===================================================== */

const DATA_DIR = path.join(__dirname, "data");
const DATA_FILE = path.join(DATA_DIR, "database.json");

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

/* =====================================================
   DEFAULT DATABASE
===================================================== */

const defaultDatabase = {
  users: [
    {
      id: 1,
      name: "Demo User",
      email: "user@taskearn.demo",
      password: "123456",
      role: "user",
      balance: 0,
      createdAt: new Date().toISOString()
    },
    {
      id: 2,
      name: "TaskEarn Admin",
      email: "admin@taskearn.demo",
      password: "admin123",
      role: "admin",
      balance: 0,
      createdAt: new Date().toISOString()
    }
  ],

  tasks: [
    {
      id: 1,
      title: "Welcome Task",
      description:
        "Complete the basic TaskEarn welcome activity and submit it for review.",
      type: "Welcome",
      reward: 5,
      active: true,
      createdAt: new Date().toISOString()
    },
    {
      id: 2,
      title: "Website Feedback",
      description:
        "Review the website and provide useful feedback about your experience.",
      type: "Feedback",
      reward: 10,
      active: true,
      createdAt: new Date().toISOString()
    }
  ],

  submissions: [],

  withdrawals: []
};

/* =====================================================
   DATABASE HELPERS
===================================================== */

function loadDatabase() {
  try {
    if (!fs.existsSync(DATA_FILE)) {
      fs.writeFileSync(
        DATA_FILE,
        JSON.stringify(defaultDatabase, null, 2)
      );

      return defaultDatabase;
    }

    const data = JSON.parse(
      fs.readFileSync(DATA_FILE, "utf8")
    );

    return {
      users: Array.isArray(data.users) ? data.users : [],
      tasks: Array.isArray(data.tasks) ? data.tasks : [],
      submissions: Array.isArray(data.submissions)
        ? data.submissions
        : [],
      withdrawals: Array.isArray(data.withdrawals)
        ? data.withdrawals
        : []
    };
  } catch (error) {
    console.error("Database load error:", error);

    return JSON.parse(
      JSON.stringify(defaultDatabase)
    );
  }
}

let db = loadDatabase();

function saveDatabase() {
  fs.writeFileSync(
    DATA_FILE,
    JSON.stringify(db, null, 2)
  );
}

/* =====================================================
   SESSION
===================================================== */

app.use(
  session({
    secret:
      process.env.SESSION_SECRET ||
      "taskearn-change-this-secret",

    resave: false,

    saveUninitialized: false,

    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 24 * 7
    }
  })
);

/* =====================================================
   STATIC WEBSITE
===================================================== */

app.use(
  express.static(
    path.join(__dirname, "public")
  )
);

/* =====================================================
   HELPERS
===================================================== */

function getCurrentUser(req) {
  if (!req.session.userId) {
    return null;
  }

  return db.users.find(
    user => user.id === req.session.userId
  ) || null;
}

function requireLogin(req, res, next) {
  const user = getCurrentUser(req);

  if (!user) {
    return res.status(401).json({
      error: "Please login first."
    });
  }

  req.user = user;

  next();
}

function requireAdmin(req, res, next) {
  const user = getCurrentUser(req);

  if (!user) {
    return res.status(401).json({
      error: "Please login first."
    });
  }

  if (user.role !== "admin") {
    return res.status(403).json({
      error: "Admin access required."
    });
  }

  req.user = user;

  next();
}

function nextId(array) {
  if (!array.length) {
    return 1;
  }

  return (
    Math.max(
      ...array.map(item => Number(item.id) || 0)
    ) + 1
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

/* =====================================================
   HEALTH CHECK
===================================================== */

app.get("/health", (req, res) => {
  res.json({
    success: true,
    message: "TaskEarn server is running.",
    time: new Date().toISOString()
  });
});

/* =====================================================
   CURRENT USER
===================================================== */

app.get("/api/me", (req, res) => {
  const user = getCurrentUser(req);

  if (!user) {
    return res.json(null);
  }

  res.json(
    safeUser(user)
  );
});

/* =====================================================
   REGISTER
===================================================== */

app.post("/api/register", (req, res) => {
  try {
    const name =
      String(req.body.name || "").trim();

    const email =
      String(req.body.email || "")
        .trim()
        .toLowerCase();

    const password =
      String(req.body.password || "");

    if (!name || !email || !password) {
      return res.status(400).json({
        error:
          "Please complete all fields."
      });
    }

    if (name.length < 2) {
      return res.status(400).json({
        error:
          "Please enter a valid name."
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error:
          "Password must contain at least 6 characters."
      });
    }

    const existingUser =
      db.users.find(
        user => user.email === email
      );

    if (existingUser) {
      return res.status(400).json({
        error:
          "An account with this email already exists."
      });
    }

    const user = {
      id: nextId(db.users),
      name,
      email,
      password,
      role: "user",
      balance: 0,
      createdAt: new Date().toISOString()
    };

    db.users.push(user);

    saveDatabase();

    req.session.userId = user.id;

    res.json({
      success: true,
      user: safeUser(user)
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error:
        "Registration failed."
    });
  }
});

/* =====================================================
   LOGIN
===================================================== */

app.post("/api/login", (req, res) => {
  try {
    const email =
      String(req.body.email || "")
        .trim()
        .toLowerCase();

    const password =
      String(req.body.password || "");

    if (!email || !password) {
      return res.status(400).json({
        error:
          "Please enter email and password."
      });
    }

    const user =
      db.users.find(
        item =>
          item.email === email &&
          item.password === password
      );

    if (!user) {
      return res.status(401).json({
        error:
          "Invalid email or password."
      });
    }

    req.session.userId = user.id;

    res.json({
      success: true,
      user: safeUser(user)
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error:
        "Login failed."
    });
  }
});

/* =====================================================
   LOGOUT
===================================================== */

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({
      success: true,
      message: "Logged out successfully."
    });
  });
});

/* =====================================================
   GET TASKS
===================================================== */

app.get(
  "/api/tasks",
  requireLogin,
  (req, res) => {

    const tasks =
      db.tasks.filter(
        task => task.active
      );

    res.json(tasks);
  }
);

/* =====================================================
   GET SINGLE TASK
===================================================== */

app.get(
  "/api/tasks/:id",
  requireLogin,
  (req, res) => {

    const id =
      Number(req.params.id);

    const task =
      db.tasks.find(
        item => item.id === id
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
  requireLogin,
  (req, res) => {

    const taskId =
      Number(req.params.id);

    const task =
      db.tasks.find(
        item =>
          item.id === taskId &&
          item.active
      );

    if (!task) {
      return res.status(404).json({
        error:
          "Task is not available."
      });
    }

    const alreadySubmitted =
      db.submissions.find(
        item =>
          item.userId === req.user.id &&
          item.taskId === task.id &&
          item.status === "pending"
      );

    if (alreadySubmitted) {
      return res.status(400).json({
        error:
          "You already submitted this task and it is waiting for review."
      });
    }

    const submission = {
      id: nextId(db.submissions),

      userId: req.user.id,

      taskId: task.id,

      taskTitle: task.title,

      reward: Number(task.reward),

      status: "pending",

      submittedAt:
        new Date().toISOString()
    };

    db.submissions.push(
      submission
    );

    saveDatabase();

    res.json({
      success: true,
      message:
        "Task submitted for review."
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

    res.json(submissions);
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
      db.users.find(
        item =>
          item.id === req.user.id
      );

    const completed =
      db.submissions.filter(
        item =>
          item.userId === user.id &&
          item.status === "approved"
      ).length;

    const withdrawals =
      db.withdrawals
        .filter(
          item =>
            item.userId === user.id
        )
        .sort(
          (a, b) =>
            new Date(b.createdAt) -
            new Date(a.createdAt)
        );

    res.json({
      balance:
        Number(user.balance || 0),

      completed,

      withdrawals
    });
  }
);

/* =====================================================
   WITHDRAWAL REQUEST
===================================================== */

app.post(
  "/api/withdraw",
  requireLogin,
  (req, res) => {

    const amount =
      Number(req.body.amount);

    const method =
      String(
        req.body.method || ""
      ).trim();

    const MIN_WITHDRAWAL = 100;

    if (
      !Number.isFinite(amount) ||
      amount <= 0
    ) {
      return res.status(400).json({
        error:
          "Please enter a valid withdrawal amount."
      });
    }

    if (amount < MIN_WITHDRAWAL) {
      return res.status(400).json({
        error:
          "Minimum withdrawal amount is ₹100."
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
          item.id === req.user.id
      );

    if (!user) {
      return res.status(404).json({
        error:
          "User not found."
      });
    }

    if (
      Number(user.balance || 0) <
      amount
    ) {
      return res.status(400).json({
        error:
          "Insufficient balance."
      });
    }

    const pending =
      db.withdrawals.find(
        item =>
          item.userId === user.id &&
          item.status === "pending"
      );

    if (pending) {
      return res.status(400).json({
        error:
          "You already have a pending withdrawal request."
      });
    }

    user.balance =
      Number(user.balance || 0) -
      amount;

    const withdrawal = {
      id:
        nextId(db.withdrawals),

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

    saveDatabase();

    res.json({
      success: true,

      message:
        "Withdrawal request submitted."
    });
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
            user.role !== "admin"
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
   ADMIN GET TASKS
===================================================== */

app.get(
  "/api/admin/tasks",
  requireAdmin,
  (req, res) => {

    res.json(
      db.tasks.sort(
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
        req.body.type || ""
      ).trim();

    const reward =
      Number(req.body.reward);

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
      !Number.isFinite(reward) ||
      reward <= 0
    ) {
      return res.status(400).json({
        error:
          "Enter a valid reward."
      });
    }

    const task = {
      id:
        nextId(db.tasks),

      title,

      description,

      type,

      reward,

      active: true,

      createdAt:
        new Date().toISOString()
    };

    db.tasks.push(task);

    saveDatabase();

    res.json({
      success: true,
      task
    });
  }
);

/* =====================================================
   ADMIN UPDATE TASK
===================================================== */

app.put(
  "/api/admin/tasks/:id",
  requireAdmin,
  (req, res) => {

    const id =
      Number(req.params.id);

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
      String(
        req.body.title || ""
      ).trim();

    const description =
      String(
        req.body.description || ""
      ).trim();

    const type =
      String(
        req.body.type || ""
      ).trim();

    const reward =
      Number(req.body.reward);

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
      !Number.isFinite(reward) ||
      reward <= 0
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

    saveDatabase();

    res.json({
      success: true,
      task
    });
  }
);

/* =====================================================
   ADMIN DISABLE TASK
===================================================== */

app.delete(
  "/api/admin/tasks/:id",
  requireAdmin,
  (req, res) => {

    const id =
      Number(req.params.id);

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

    saveDatabase();

    res.json({
      success: true,
      message:
        "Task disabled."
    });
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
            new Date(b.submittedAt) -
            new Date(a.submittedAt)
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
  (req, res) => {

    const id =
      Number(req.params.id);

    const status =
      String(
        req.body.status || ""
      ).trim();

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

      user.balance =
        Number(user.balance || 0) +
        Number(submission.reward || 0);

    }

    submission.status =
      status;

    submission.reviewedAt =
      new Date().toISOString();

    submission.reviewedBy =
      req.user.id;

    saveDatabase();

    res.json({
      success: true,

      message:
        status === "approved"
          ? "Submission approved."
          : "Submission rejected."
    });
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
            new Date(b.createdAt) -
            new Date(a.createdAt)
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
  (req, res) => {

    const id =
      Number(req.params.id);

    const status =
      String(
        req.body.status || ""
      ).trim();

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

      user.balance =
        Number(user.balance || 0) +
        Number(withdrawal.amount || 0);

    }

    withdrawal.status =
      status;

    withdrawal.reviewedAt =
      new Date().toISOString();

    withdrawal.reviewedBy =
      req.user.id;

    saveDatabase();

    res.json({
      success: true,

      message:
        status === "approved"
          ? "Withdrawal approved."
          : "Withdrawal rejected and balance returned."
    });
  }
);

/* =====================================================
   FRONTEND FALLBACK
===================================================== */

app.use((req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      "public",
      "index.html"
    )
  );
});

/* =====================================================
   SERVER
===================================================== */

const PORT =
  process.env.PORT || 3000;

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
