const express = require("express");
const session = require("express-session");

const app = express();

app.use(express.json());
app.use(express.static("public"));

app.use(
  session({
    secret:
      process.env.SESSION_SECRET ||
      "change-this-secret-in-production",

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
   IN-MEMORY DATA
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


/*
  IMPORTANT:
  No default/demo tasks.

  Admin creates tasks from the
  Admin Dashboard.
*/

const tasks = [];

const submissions = [];

const withdrawals = [];


/* =========================
   ID HELPERS
========================= */

function nextId(list) {

  if (!list.length) {
    return 1;
  }

  return Math.max(
    ...list.map(x => Number(x.id) || 0)
  ) + 1;
}


/* =========================
   AUTH MIDDLEWARE
========================= */

function auth(req, res, next) {

  if (!req.session.user) {

    return res.status(401).json({
      error: "Login required"
    });

  }

  next();
}


/* =========================
   ADMIN MIDDLEWARE
========================= */

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
   GET CURRENT USER
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

  const user = users.find(
    x =>
      x.email.toLowerCase() === email &&
      x.password === password
  );


  if (!user) {

    return res.status(401).json({
      error: "Invalid login"
    });

  }


  req.session.user = {

    id: user.id,

    name: user.name,

    email: user.email,

    role: user.role

  };


  res.json(req.session.user);

});


/* =========================
   REGISTER
========================= */

app.post("/api/register", (req, res) => {

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
      error: "All fields are required"
    });

  }


  if (password.length < 6) {

    return res.status(400).json({
      error: "Password must be at least 6 characters"
    });

  }


  if (
    users.some(
      x =>
        x.email.toLowerCase() === email
    )
  ) {

    return res.status(400).json({
      error: "Email already exists"
    });

  }


  const user = {

    id: nextId(users),

    name,

    email,

    password,

    role: "user",

    balance: 0,

    completed: 0

  };


  users.push(user);


  req.session.user = {

    id: user.id,

    name: user.name,

    email: user.email,

    role: user.role

  };


  res.json(req.session.user);

});


/* =========================
   LOGOUT
========================= */

app.post("/api/logout", (req, res) => {

  req.session.destroy(() => {

    res.json({
      ok: true
    });

  });

});


/* =========================
   USER TASK LIST
========================= */

app.get("/api/tasks", auth, (req, res) => {

  res.json(
    tasks.filter(
      task => task.active !== false
    )
  );

});


/* =========================
   GET SINGLE TASK
========================= */

app.get("/api/tasks/:id", auth, (req, res) => {

  const id =
    Number(req.params.id);

  const task =
    tasks.find(
      x => x.id === id
    );


  if (!task) {

    return res.status(404).json({
      error: "Task not found"
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

    const taskId =
      Number(req.params.id);

    const userId =
      req.session.user.id;


    const task =
      tasks.find(
        x =>
          x.id === taskId &&
          x.active !== false
      );


    if (!task) {

      return res.status(404).json({
        error: "Task not found or disabled"
      });

    }


    const existing =
      submissions.find(
        x =>
          x.userId === userId &&
          x.taskId === taskId &&
          x.status === "pending"
      );


    if (existing) {

      return res.status(400).json({
        error:
          "You already submitted this task and it is waiting for review."
      });

    }


    const alreadyApproved =
      submissions.find(
        x =>
          x.userId === userId &&
          x.taskId === taskId &&
          x.status === "approved"
      );


    if (alreadyApproved) {

      return res.status(400).json({
        error:
          "You have already completed this task."
      });

    }


    const submission = {

      id: nextId(submissions),

      userId,

      userName:
        req.session.user.name,

      taskId,

      taskTitle:
        task.title,

      reward:
        Number(task.reward),

      status: "pending",

      submittedAt:
        new Date().toISOString(),

      reviewedAt: null

    };


    submissions.push(submission);


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
        x =>
          x.userId ===
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
      users.find(
        x =>
          x.id ===
          req.session.user.id
      );


    if (!user) {

      return res.status(404).json({
        error: "User not found"
      });

    }


    res.json({

      balance:
        Number(user.balance || 0),

      completed:
        Number(user.completed || 0),

      withdrawals:
        withdrawals.filter(
          x =>
            x.userId ===
            user.id
        )

    });

  }
);


/* =========================
   WITHDRAWAL REQUEST
========================= */

app.post(
  "/api/withdraw",
  auth,
  (req, res) => {

    const user =
      users.find(
        x =>
          x.id ===
          req.session.user.id
      );


    if (!user) {

      return res.status(404).json({
        error: "User not found"
      });

    }


    const amount =
      Number(req.body.amount);


    const method =
      String(
        req.body.method || "UPI"
      ).trim();


    if (
      !Number.isFinite(amount) ||
      amount < 100
    ) {

      return res.status(400).json({
        error:
          "Minimum withdrawal is ₹100"
      });

    }


    if (amount > user.balance) {

      return res.status(400).json({
        error:
          "Insufficient balance"
      });

    }


    if (!method) {

      return res.status(400).json({
        error:
          "Payment method is required"
      });

    }


    /*
      Reserve the amount while
      withdrawal is pending.
    */

    user.balance -= amount;


    withdrawals.push({

      id:
        nextId(withdrawals),

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
          x =>
            x.status ===
            "pending"
        ).length,

      pending:
        withdrawals.filter(
          x =>
            x.status ===
            "pending"
        ).length

    });

  }
);


/* =========================
   ADMIN TASK LIST
========================= */

app.get(
  "/api/admin/tasks",
  admin,
  (req, res) => {

    res.json(tasks);

  }
);


/* =========================
   ADMIN ADD TASK
========================= */

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
      Number(req.body.reward);


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
          "Reward must be greater than zero"
      });

    }


    const task = {

      id:
        nextId(tasks),

      title,

      description,

      type,

      reward,

      active:
        true,

      createdAt:
        new Date().toISOString(),

      createdBy:
        req.session.user.id

    };


    tasks.push(task);


    res.json(task);

  }
);


/* =========================
   ADMIN EDIT TASK
========================= */

app.put(
  "/api/admin/tasks/:id",
  admin,
  (req, res) => {

    const id =
      Number(req.params.id);

    const task =
      tasks.find(
        x =>
          x.id === id
      );


    if (!task) {

      return res.status(404).json({
        error:
          "Task not found"
      });

    }


    const title =
      String(
        req.body.title ??
        task.title
      ).trim();

    const description =
      String(
        req.body.description ??
        task.description
      ).trim();

    const type =
      String(
        req.body.type ??
        task.type
      ).trim();

    const reward =
      Number(
        req.body.reward ??
        task.reward
      );


    if (
      !title ||
      !description ||
      !type
    ) {

      return res.status(400).json({
        error:
          "Task details are required"
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


    task.title =
      title;

    task.description =
      description;

    task.type =
      type;

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


/* =========================
   ADMIN DISABLE TASK
========================= */

app.delete(
  "/api/admin/tasks/:id",
  admin,
  (req, res) => {

    const id =
      Number(req.params.id);

    const task =
      tasks.find(
        x =>
          x.id === id
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


/* =========================
   ADMIN REVIEW SUBMISSION
========================= */

app.post(
  "/api/admin/submissions/:id",
  admin,
  (req, res) => {

    const id =
      Number(req.params.id);

    const status =
      req.body.status;


    if (
      status !== "approved" &&
      status !== "rejected"
    ) {

      return res.status(400).json({
        error:
          "Invalid status"
      });

    }


    const submission =
      submissions.find(
        x =>
          x.id === id
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


    const user =
      users.find(
        x =>
          x.id ===
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

    submission.reviewedAt =
      new Date().toISOString();


    /*
      Reward is credited ONLY
      after admin approval.
    */

    if (status === "approved") {

      user.balance +=
        Number(
          submission.reward
        );

      user.completed++;

    }


    res.json({
      ok: true
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


/* =========================
   ADMIN REVIEW WITHDRAWAL
========================= */

app.post(
  "/api/admin/withdrawals/:id",
  admin,
  (req, res) => {

    const id =
      Number(req.params.id);

    const status =
      req.body.status;


    if (
      status !== "approved" &&
      status !== "rejected"
    ) {

      return res.status(400).json({
        error:
          "Invalid withdrawal status"
      });

    }


    const withdrawal =
      withdrawals.find(
        x =>
          x.id === id
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


    const user =
      users.find(
        x =>
          x.id ===
          withdrawal.userId
      );


    if (!user) {

      return res.status(404).json({
        error:
          "User not found"
      });

    }


    /*
      If rejected, return the
      reserved balance to user.
    */

    if (status === "rejected") {

      user.balance +=
        Number(
          withdrawal.amount
        );

    }


    withdrawal.status =
      status;

    withdrawal.reviewedAt =
      new Date().toISOString();


    res.json({
      ok: true
    });

  }
);


/* =========================
   HEALTH CHECK
========================= */

app.get("/health", (req, res) => {

  res.json({
    ok: true,
    service: "TaskEarn"
  });

});


/* =========================
   START SERVER
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
