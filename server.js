const express = require("express");
const session = require("express-session");

const app = express();

/* Render / HTTPS session fix */
app.set("trust proxy", 1);

app.use(express.json());
app.use(express.static("public"));

app.use(
  session({
    secret:
      process.env.SESSION_SECRET ||
      "taskearn-demo-secret-change-this",

    resave: false,

    saveUninitialized: false,

    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production"
    }
  })
);


/* =========================
   USERS
========================= */

const users = [
  {
    id: 1,
    name: "Demo User",
    email: "user@taskearn.demo",
    password: "123456",
    role: "user",
    balance: 0,
    completed: 0
  },

  {
    id: 2,
    name: "Admin",
    email: "admin@taskearn.demo",
    password: "admin123",
    role: "admin",
    balance: 0,
    completed: 0
  }
];


/* =========================
   TASKS
========================= */

let tasks = [
  {
    id: 1,
    title: "Read a short description",
    description:
      "Read a short product description and submit the correct category.",
    type: "Content",
    reward: 6,
    active: true
  },

  {
    id: 2,
    title: "Test a mobile website",
    description:
      "Test two buttons and submit your result.",
    type: "Testing",
    reward: 20,
    active: true
  },

  {
    id: 3,
    title: "Daily check-in",
    description:
      "Complete the daily check-in and submit it for review.",
    type: "Check-in",
    reward: 2,
    active: true
  },

  {
    id: 4,
    title: "Visit a sponsor page",
    description:
      "Open the sponsor page and confirm one simple detail.",
    type: "Visit",
    reward: 5,
    active: true
  }
];


let submissions = [];
let withdrawals = [];

let nextUserId = 3;
let nextTaskId = 5;
let nextSubmissionId = 1;
let nextWithdrawalId = 1;


/* =========================
   HELPERS
========================= */

function getUser(id) {
  return users.find(
    user => user.id === Number(id)
  );
}


function getTask(id) {
  return tasks.find(
    task => task.id === Number(id)
  );
}


function publicUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role
  };
}


/* =========================
   AUTH
========================= */

function auth(req, res, next) {

  if (!req.session.user) {

    return res.status(401).json({
      error: "Login required"
    });
  }

  next();
}


function admin(req, res, next) {

  if (
    !req.session.user ||
    req.session.user.role !== "admin"
  ) {

    return res.status(403).json({
      error: "Admin only"
    });
  }

  next();
}


/* =========================
   HEALTH
========================= */

app.get("/health", (req, res) => {

  res.json({
    ok: true,
    service: "TaskEarn"
  });

});


/* =========================
   CURRENT USER
========================= */

app.get("/api/me", (req, res) => {

  res.json(
    req.session.user || null
  );

});


/* =========================
   LOGIN
========================= */

app.post("/api/login", (req, res) => {

  const email =
    String(req.body.email || "")
      .trim()
      .toLowerCase();

  const password =
    String(req.body.password || "");

  const user =
    users.find(
      item =>
        item.email.toLowerCase() === email &&
        item.password === password
    );

  if (!user) {

    return res.status(401).json({
      error: "Invalid login"
    });

  }

  req.session.user =
    publicUser(user);

  req.session.save(err => {

    if (err) {

      console.error(
        "Session save error:",
        err
      );

      return res.status(500).json({
        error:
          "Login session could not be saved"
      });

    }

    res.json(
      req.session.user
    );

  });

});


/* =========================
   REGISTER
========================= */

app.post("/api/register", (req, res) => {

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

  if (
    !name ||
    !email ||
    !password
  ) {

    return res.status(400).json({
      error:
        "All fields are required"
    });

  }

  if (password.length < 6) {

    return res.status(400).json({
      error:
        "Password must be at least 6 characters"
    });

  }

  if (
    users.some(
      user =>
        user.email.toLowerCase() === email
    )
  ) {

    return res.status(400).json({
      error:
        "Email already exists"
    });

  }

  const user = {

    id: nextUserId++,

    name,

    email,

    password,

    role: "user",

    balance: 0,

    completed: 0

  };

  users.push(user);

  req.session.user =
    publicUser(user);

  req.session.save(err => {

    if (err) {

      return res.status(500).json({
        error:
          "Account created but session failed"
      });

    }

    res.json(
      req.session.user
    );

  });

});


/* =========================
   LOGOUT
========================= */

app.post("/api/logout", (req, res) => {

  req.session.destroy(err => {

    if (err) {

      return res.status(500).json({
        error:
          "Logout failed"
      });

    }

    res.json({
      ok: true
    });

  });

});


/* =========================
   TASKS
========================= */

app.get("/api/tasks", (req, res) => {

  res.json(
    tasks.filter(
      task => task.active
    )
  );

});


app.get("/api/tasks/:id", (req, res) => {

  const task =
    getTask(req.params.id);

  if (!task) {

    return res.status(404).json({
      error:
        "Task not found"
    });

  }

  res.json(task);

});


/* =========================
   SUBMIT TASK
========================= */

app.post(
  "/api/tasks/:id/submit",
  auth,
  (req, res) => {

    const user =
      getUser(
        req.session.user.id
      );

    const task =
      getTask(
        req.params.id
      );

    if (!user) {

      return res.status(404).json({
        error:
          "User not found"
      });

    }

    if (
      !task ||
      !task.active
    ) {

      return res.status(404).json({
        error:
          "Task not available"
      });

    }

    const existing =
      submissions.find(
        item =>
          item.userId === user.id &&
          item.taskId === task.id &&
          (
            item.status === "pending" ||
            item.status === "approved"
          )
      );

    if (existing) {

      return res.status(400).json({
        error:
          existing.status === "approved"
            ? "Task already approved"
            : "Task already submitted"
      });

    }

    const submission = {

      id: nextSubmissionId++,

      userId: user.id,

      userName: user.name,

      taskId: task.id,

      taskTitle: task.title,

      reward:
        Number(task.reward),

      status:
        "pending",

      submittedAt:
        new Date().toISOString()

    };

    submissions.push(
      submission
    );

    res.json({

      ok: true,

      message:
        "Task submitted for review."

    });

  }
);


/* =========================
   USER SUBMISSIONS
========================= */

app.get(
  "/api/my-submissions",
  auth,
  (req, res) => {

    res.json(
      submissions.filter(
        item =>
          item.userId ===
          req.session.user.id
      )
    );

  }
);


/* =========================
   WALLET
========================= */

app.get(
  "/api/wallet",
  auth,
  (req, res) => {

    const user =
      getUser(
        req.session.user.id
      );

    if (!user) {

      return res.status(404).json({
        error:
          "User not found"
      });

    }

    res.json({

      balance:
        Number(user.balance),

      completed:
        Number(user.completed),

      withdrawals:
        withdrawals.filter(
          item =>
            item.userId ===
            user.id
        )

    });

  }
);


/* =========================
   WITHDRAW
========================= */

app.post(
  "/api/withdraw",
  auth,
  (req, res) => {

    const user =
      getUser(
        req.session.user.id
      );

    const amount =
      Number(
        req.body.amount
      );

    const method =
      String(
        req.body.method ||
        "UPI"
      ).trim();

    if (
      !Number.isFinite(amount)
    ) {

      return res.status(400).json({
        error:
          "Invalid amount"
      });

    }

    if (amount < 100) {

      return res.status(400).json({
        error:
          "Minimum withdrawal is ₹100"
      });

    }

    if (
      amount > user.balance
    ) {

      return res.status(400).json({
        error:
          "Insufficient balance"
      });

    }

    user.balance -=
      amount;

    withdrawals.push({

      id:
        nextWithdrawalId++,

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

    });

    res.json({
      ok: true
    });

  }
);


/* =========================
   ADMIN STATS
========================= */

app.get(
  "/api/admin/stats",
  admin,
  (req, res) => {

    res.json({

      users:
        users.length,

      tasks:
        tasks.length,

      submissions:
        submissions.filter(
          item =>
            item.status ===
            "pending"
        ).length,

      pending:
        withdrawals.filter(
          item =>
            item.status ===
            "pending"
        ).length

    });

  }
);


/* =========================
   ADMIN TASKS
========================= */

app.get(
  "/api/admin/tasks",
  admin,
  (req, res) => {

    res.json(tasks);

  }
);


app.post(
  "/api/admin/tasks",
  admin,
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
          "Title, description and type are required"
      });

    }

    if (
      !Number.isFinite(reward) ||
      reward <= 0
    ) {

      return res.status(400).json({
        error:
          "Invalid reward"
      });

    }

    const task = {

      id:
        nextTaskId++,

      title,

      description,

      type,

      reward,

      active:
        true

    };

    tasks.push(task);

    res.json(task);

  }
);


app.put(
  "/api/admin/tasks/:id",
  admin,
  (req, res) => {

    const task =
      getTask(
        req.params.id
      );

    if (!task) {

      return res.status(404).json({
        error:
          "Task not found"
      });

    }

    task.title =
      String(
        req.body.title ||
        task.title
      ).trim();

    task.description =
      String(
        req.body.description ||
        task.description
      ).trim();

    task.type =
      String(
        req.body.type ||
        task.type
      ).trim();

    const reward =
      Number(
        req.body.reward
      );

    if (
      !Number.isFinite(reward) ||
      reward <= 0
    ) {

      return res.status(400).json({
        error:
          "Invalid reward"
      });

    }

    task.reward =
      reward;

    if (
      typeof req.body.active ===
      "boolean"
    ) {

      task.active =
        req.body.active;

    }

    res.json(task);

  }
);


app.delete(
  "/api/admin/tasks/:id",
  admin,
  (req, res) => {

    const task =
      getTask(
        req.params.id
      );

    if (!task) {

      return res.status(404).json({
        error:
          "Task not found"
      });

    }

    task.active =
      false;

    res.json({
      ok: true
    });

  }
);


/* =========================
   ADMIN SUBMISSIONS
========================= */

app.get(
  "/api/admin/submissions",
  admin,
  (req, res) => {

    res.json(
      submissions
    );

  }
);


app.post(
  "/api/admin/submissions/:id",
  admin,
  (req, res) => {

    const submission =
      submissions.find(
        item =>
          item.id ===
          Number(
            req.params.id
          )
      );

    if (!submission) {

      return res.status(404).json({
        error:
          "Submission not found"
      });

    }

    if (
      submission.status !==
      "pending"
    ) {

      return res.status(400).json({
        error:
          "Submission already reviewed"
      });

    }

    const status =
      String(
        req.body.status || ""
      ).toLowerCase();

    if (
      status !== "approved" &&
      status !== "rejected"
    ) {

      return res.status(400).json({
        error:
          "Invalid status"
      });

    }

    const user =
      getUser(
        submission.userId
      );

    if (!user) {

      return res.status(404).json({
        error:
          "User not found"
      });

    }

    submission.status =
      status;

    if (
      status === "approved"
    ) {

      user.balance +=
        Number(
          submission.reward
        );

      user.completed +=
        1;

    }

    res.json({
      ok: true,
      status
    });

  }
);


/* =========================
   ADMIN WITHDRAWALS
========================= */

app.get(
  "/api/admin/withdrawals",
  admin,
  (req, res) => {

    res.json(
      withdrawals
    );

  }
);


app.post(
  "/api/admin/withdrawals/:id",
  admin,
  (req, res) => {

    const withdrawal =
      withdrawals.find(
        item =>
          item.id ===
          Number(
            req.params.id
          )
      );

    if (!withdrawal) {

      return res.status(404).json({
        error:
          "Withdrawal not found"
      });

    }

    if (
      withdrawal.status !==
      "pending"
    ) {

      return res.status(400).json({
        error:
          "Withdrawal already reviewed"
      });

    }

    const status =
      String(
        req.body.status || ""
      ).toLowerCase();

    if (
      status !== "approved" &&
      status !== "rejected"
    ) {

      return res.status(400).json({
        error:
          "Invalid status"
      });

    }

    const user =
      getUser(
        withdrawal.userId
      );

    if (!user) {

      return res.status(404).json({
        error:
          "User not found"
      });

    }

    withdrawal.status =
      status;

    if (
      status === "rejected"
    ) {

      user.balance +=
        Number(
          withdrawal.amount
        );

    }

    res.json({
      ok: true,
      status
    });

  }
);


/* =========================
   SERVER
========================= */

const PORT =
  process.env.PORT || 3000;

app.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(
      `TaskEarn running on port ${PORT}`
    );

  }
);
