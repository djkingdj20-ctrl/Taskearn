const express = require("express");
const session = require("express-session");

const app = express();

app.use(express.json());
app.use(express.static("public"));

/* =========================
   SESSION
========================= */

app.use(
  session({
    secret:
      process.env.SESSION_SECRET ||
      "taskearn-secret-2026",

    resave: false,

    saveUninitialized: false,

    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: false
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
   DATA
========================= */

/*
   NO DEFAULT TASKS

   Admin creates tasks.
*/

const tasks = [];

const submissions = [];

const withdrawals = [];


/* =========================
   ID
========================= */

function nextId(list) {

  if (list.length === 0) {
    return 1;
  }

  return (
    Math.max(
      ...list.map(
        item => Number(item.id) || 0
      )
    ) + 1
  );
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


/* =========================
   ADMIN AUTH
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
    String(
      req.body.email || ""
    )
      .trim()
      .toLowerCase();

  const password =
    String(
      req.body.password || ""
    );


  const user =
    users.find(
      x =>
        x.email.toLowerCase() ===
          email &&
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


  req.session.save(
    err => {

      if (err) {

        console.error(
          "SESSION SAVE ERROR:",
          err
        );

        return res.status(500).json({
          error:
            "Could not create login session"
        });

      }


      res.json({

        ok: true,

        user:
          req.session.user

      });

    }
  );

});


/* =========================
   REGISTER
========================= */

app.post(
  "/api/register",
  (req, res) => {

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
        x =>
          x.email.toLowerCase() ===
          email
      )
    ) {

      return res.status(400).json({
        error:
          "Email already exists"
      });

    }


    const user = {

      id:
        nextId(users),

      name,

      email,

      password,

      role:
        "user",

      balance:
        0,

      completed:
        0

    };


    users.push(user);


    req.session.user = {

      id:
        user.id,

      name:
        user.name,

      email:
        user.email,

      role:
        user.role

    };


    req.session.save(
      err => {

        if (err) {

          console.error(
            "SESSION SAVE ERROR:",
            err
          );

          return res.status(500).json({
            error:
              "Could not create account session"
          });

        }


        res.json({

          ok: true,

          user:
            req.session.user

        });

      }
    );

  }
);


/* =========================
   LOGOUT
========================= */

app.post(
  "/api/logout",
  (req, res) => {

    req.session.destroy(
      () => {

        res.json({
          ok: true
        });

      }
    );

  }
);


/* =========================
   USER TASKS
========================= */

app.get(
  "/api/tasks",
  auth,
  (req, res) => {

    res.json(
      tasks.filter(
        task =>
          task.active !== false
      )
    );

  }
);


/* =========================
   SINGLE TASK
========================= */

app.get(
  "/api/tasks/:id",
  auth,
  (req, res) => {

    const task =
      tasks.find(
        x =>
          x.id ===
          Number(req.params.id)
      );


    if (!task) {

      return res.status(404).json({
        error:
          "Task not found"
      });

    }


    res.json(task);

  }
);


/* =========================
   SUBMIT TASK
========================= */

app.post(
  "/api/tasks/:id/submit",
  auth,
  (req, res) => {

    const taskId =
      Number(
        req.params.id
      );

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
        error:
          "Task not found or disabled"
      });

    }


    const pending =
      submissions.find(
        x =>
          x.userId === userId &&
          x.taskId === taskId &&
          x.status === "pending"
      );


    if (pending) {

      return res.status(400).json({
        error:
          "This task is already submitted and waiting for review."
      });

    }


    const approved =
      submissions.find(
        x =>
          x.userId === userId &&
          x.taskId === taskId &&
          x.status === "approved"
      );


    if (approved) {

      return res.status(400).json({
        error:
          "You have already completed this task."
      });

    }


    const submission = {

      id:
        nextId(submissions),

      userId,

      userName:
        req.session.user.name,

      taskId,

      taskTitle:
        task.title,

      reward:
        Number(task.reward),

      status:
        "pending",

      submittedAt:
        new Date().toISOString(),

      reviewedAt:
        null

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
        error:
          "User not found"
      });

    }


    res.json({

      balance:
        Number(
          user.balance || 0
        ),

      completed:
        Number(
          user.completed || 0
        ),

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
   WITHDRAW
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
        error:
          "User not found"
      });

    }


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
      !Number.isFinite(amount) ||
      amount < 100
    ) {

      return res.status(400).json({
        error:
          "Minimum withdrawal is ₹100"
      });

    }


    if (
      amount >
      user.balance
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
        nextId(
          withdrawals
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
   ADMIN TASKS
========================= */

app.get(
  "/api/admin/tasks",
  admin,
  (req, res) => {

    res.json(
      tasks
    );

  }
);


/* =========================
   ADMIN CREATE TASK
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
        req.body.description ||
          ""
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
      !Number.isFinite(
        reward
      ) ||
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

    const task =
      tasks.find(
        x =>
          x.id ===
          Number(
            req.params.id
          )
      );


    if (!task) {

      return res.status(404).json({
        error:
          "Task not found"
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
        Number(
          req.body.reward
        );


      if (
        !Number.isFinite(
          reward
        ) ||
        reward <= 0
      ) {

        return res.status(400).json({
          error:
            "Invalid reward"
        });

      }


      task.reward =
        reward;

    }


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
   DISABLE TASK
========================= */

app.delete(
  "/api/admin/tasks/:id",
  admin,
  (req, res) => {

    const task =
      tasks.find(
        x =>
          x.id ===
          Number(
            req.params.id
          )
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
   REVIEW SUBMISSION
========================= */

app.post(
  "/api/admin/submissions/:id",
  admin,
  (req, res) => {

    const status =
      req.body.status;


    if (
      status !==
        "approved" &&
      status !==
        "rejected"
    ) {

      return res.status(400).json({
        error:
          "Invalid status"
      });

    }


    const submission =
      submissions.find(
        x =>
          x.id ===
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


    if (
      status ===
      "approved"
    ) {

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
   REVIEW WITHDRAWAL
========================= */

app.post(
  "/api/admin/withdrawals/:id",
  admin,
  (req, res) => {

    const status =
      req.body.status;


    if (
      status !==
        "approved" &&
      status !==
        "rejected"
    ) {

      return res.status(400).json({
        error:
          "Invalid withdrawal status"
      });

    }


    const withdrawal =
      withdrawals.find(
        x =>
          x.id ===
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


    if (
      status ===
      "rejected"
    ) {

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

app.get(
  "/health",
  (req, res) => {

    res.json({
      ok: true,
      service:
        "TaskEarn"
    });

  }
);


/* =========================
   SERVER
========================= */

const PORT =
  process.env.PORT ||
  3000;


app.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(
      `TaskEarn running on port ${PORT}`
    );

  }
);
