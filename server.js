const express = require("express");
const session = require("express-session");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");

const app = express();

app.set("trust proxy", 1);

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
        description: "Complete the instructions carefully and submit the task for review.",
        type: "General",
        reward: 10,
        active: true
      },
      {
        id: 2,
        title: "Social Media Engagement",
        description: "Complete the specified social media activity and submit your task.",
        type: "Social",
        reward: 15,
        active: true
      },
      {
        id: 3,
        title: "Website Visit Task",
        description: "Visit the required website and complete the provided instructions.",
        type: "Website",
        reward: 20,
        active: true
      }
    ],
    submissions: [],
    withdrawals: []
  };
}

function loadDB() {
  try {
    if (!fs.existsSync(DB_FILE)) {
      const db = defaultDatabase();
      saveDB(db);
      return db;
    }

    const raw = fs.readFileSync(DB_FILE, "utf8");

    if (!raw.trim()) {
      const db = defaultDatabase();
      saveDB(db);
      return db;
    }

    const db = JSON.parse(raw);

    db.users ||= [];
    db.tasks ||= [];
    db.submissions ||= [];
    db.withdrawals ||= [];

    return db;
  } catch (error) {
    console.error("Database load error:", error);

    const db = defaultDatabase();

    try {
      saveDB(db);
    } catch (e) {}

    return db;
  }
}

function saveDB(db) {
  const temp = DB_FILE + ".tmp";

  fs.writeFileSync(
    temp,
    JSON.stringify(db, null, 2),
    "utf8"
  );

  fs.renameSync(temp, DB_FILE);
}

let db = loadDB();


/* =====================================================
   SESSION
===================================================== */

app.use(
  session({
    secret:
      process.env.SESSION_SECRET ||
      "CHANGE_THIS_TASKEARN_SECRET_2026",

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
   SECURITY HELPERS
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

function publicUser(user) {
  if (!user) return null;

  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role || "Member",
    mobile: user.mobile || "",
    city: user.city || "",
    profileImage: user.profileImage || "",
    createdAt: user.createdAt
  };
}

function findUserById(id) {
  return db.users.find(
    u => String(u.id) === String(id)
  );
}

function currentUser(req) {
  if (!req.session.userId) {
    return null;
  }

  return findUserById(req.session.userId);
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
   BASIC ROUTES
===================================================== */

app.get("/", (req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "index.html")
  );
});

app.use(
  express.static(
    path.join(__dirname, "public")
  )
);


/* =====================================================
   REGISTER
===================================================== */

app.post("/api/register", async (req, res) => {
  try {
    const name = cleanText(req.body.name, 80);
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");

    if (!name || !email || !password) {
      return res.status(400).json({
        error: "Please complete all fields."
      });
    }

    if (!validEmail(email)) {
      return res.status(400).json({
        error: "Please enter a valid email address."
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: "Password must contain at least 6 characters."
      });
    }

    const existing = db.users.find(
      u => u.email === email
    );

    if (existing) {
      return res.status(409).json({
        error: "An account with this email already exists."
      });
    }

    const passwordHash =
      await bcrypt.hash(password, 12);

    const user = {
      id: crypto.randomUUID(),
      name,
      email,
      passwordHash,
      role: "Member",
      mobile: "",
      city: "",
      profileImage: "",
      balance: 0,
      createdAt: new Date().toISOString()
    };

    db.users.push(user);

    saveDB(db);

    req.session.userId = user.id;

    return res.json(publicUser(user));
  } catch (error) {
    console.error("Register error:", error);

    return res.status(500).json({
      error: "Unable to create account."
    });
  }
});


/* =====================================================
   LOGIN
===================================================== */

app.post("/api/login", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");

    if (!email || !password) {
      return res.status(400).json({
        error: "Please enter email and password."
      });
    }

    const user = db.users.find(
      u => u.email === email
    );

    if (!user) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    const valid =
      await bcrypt.compare(
        password,
        user.passwordHash
      );

    if (!valid) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    req.session.userId = user.id;

    return res.json(publicUser(user));
  } catch (error) {
    console.error("Login error:", error);

    return res.status(500).json({
      error: "Unable to login."
    });
  }
});


/* =====================================================
   CURRENT USER
===================================================== */

app.get("/api/me", (req, res) => {
  const user = currentUser(req);

  if (!user) {
    return res.json(null);
  }

  res.json(publicUser(user));
});


/* =====================================================
   LOGOUT
===================================================== */

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");

    res.json({
      message: "Logged out successfully."
    });
  });
});


/* =====================================================
   PROFILE UPDATE
===================================================== */

app.put("/api/profile", requireLogin, (req, res) => {
  try {
    const user = req.user;

    const name =
      cleanText(req.body.name, 80);

    const mobile =
      cleanText(req.body.mobile, 30);

    const city =
      cleanText(req.body.city, 80);

    const profileImage =
      String(req.body.profileImage || "");

    if (!name) {
      return res.status(400).json({
        error: "Name cannot be empty."
      });
    }

    if (mobile.length > 30) {
      return res.status(400).json({
        error: "Invalid mobile number."
      });
    }

    if (city.length > 80) {
      return res.status(400).json({
        error: "City name is too long."
      });
    }

    /*
      Profile image is intentionally limited.
      This prevents extremely large uploads.
    */

    if (profileImage.length > 1500000) {
      return res.status(400).json({
        error: "Profile image is too large."
      });
    }

    user.name = name;
    user.mobile = mobile;
    user.city = city;
    user.profileImage = profileImage;

    saveDB(db);

    res.json({
      message: "Profile saved successfully.",
      user: publicUser(user)
    });
  } catch (error) {
    console.error("Profile update error:", error);

    res.status(500).json({
      error: "Unable to save profile."
    });
  }
});


/* =====================================================
   TASKS
===================================================== */

app.get("/api/tasks", requireLogin, (req, res) => {
  const tasks = db.tasks
    .filter(t => t.active !== false)
    .map(t => ({
      id: t.id,
      title: t.title,
      description: t.description,
      type: t.type,
      reward: Number(t.reward) || 0
    }));

  res.json(tasks);
});


/* =====================================================
   SUBMIT TASK
===================================================== */

app.post(
  "/api/tasks/:id/submit",
  requireLogin,
  (req, res) => {
    try {
      const taskId =
        Number(req.params.id);

      const task =
        db.tasks.find(
          t =>
            Number(t.id) === taskId &&
            t.active !== false
        );

      if (!task) {
        return res.status(404).json({
          error: "Task not found."
        });
      }

      const alreadySubmitted =
        db.submissions.find(
          s =>
            String(s.userId) === String(req.user.id) &&
            Number(s.taskId) === taskId &&
            s.status === "pending"
        );

      if (alreadySubmitted) {
        return res.status(409).json({
          error: "You already submitted this task and it is under review."
        });
      }

      const submission = {
        id: crypto.randomUUID(),
        userId: req.user.id,
        taskId: task.id,
        taskTitle: task.title,
        reward: Number(task.reward) || 0,
        status: "pending",
        submittedAt: new Date().toISOString()
      };

      db.submissions.push(submission);

      saveDB(db);

      res.json({
        message:
          "Task submitted for review successfully."
      });
    } catch (error) {
      console.error("Submit task error:", error);

      res.status(500).json({
        error: "Unable to submit task."
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
          s =>
            String(s.userId) ===
            String(req.user.id)
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
    const user = req.user;

    const completed =
      db.submissions.filter(
        s =>
          String(s.userId) ===
            String(user.id) &&
          s.status === "approved"
      ).length;

    const withdrawals =
      db.withdrawals
        .filter(
          w =>
            String(w.userId) ===
            String(user.id)
        )
        .sort(
          (a, b) =>
            new Date(b.createdAt) -
            new Date(a.createdAt)
        );

    res.json({
      balance: Number(user.balance || 0),
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
        Number(req.body.amount);

      const method =
        cleanText(req.body.method, 100);

      if (!Number.isFinite(amount)) {
        return res.status(400).json({
          error: "Invalid amount."
        });
      }

      if (amount < 100) {
        return res.status(400).json({
          error: "Minimum withdrawal amount is ₹100."
        });
      }

      if (!method) {
        return res.status(400).json({
          error: "Please enter payment method."
        });
      }

      if (amount > Number(req.user.balance || 0)) {
        return res.status(400).json({
          error: "Insufficient wallet balance."
        });
      }

      req.user.balance =
        Number(req.user.balance || 0) -
        amount;

      const withdrawal = {
        id: crypto.randomUUID(),
        userId: req.user.id,
        amount,
        method,
        status: "pending",
        createdAt: new Date().toISOString()
      };

      db.withdrawals.push(withdrawal);

      saveDB(db);

      res.json({
        message:
          "Withdrawal request submitted successfully."
      });
    } catch (error) {
      console.error("Withdrawal error:", error);

      res.status(500).json({
        error: "Unable to submit withdrawal."
      });
    }
  }
);


/* =====================================================
   ERROR HANDLER
===================================================== */

app.use((err, req, res, next) => {
  console.error("Server error:", err);

  res.status(500).json({
    error: "Internal server error."
  });
});


/* =====================================================
   SERVER
===================================================== */

const PORT =
  process.env.PORT || 10000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(
    `TaskEarn server running on port ${PORT}`
  );
});
