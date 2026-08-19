const express = require("express");
const session = require("express-session");

const app = express();

app.set("trust proxy", 1);

app.use(express.json());
app.use(express.static("public"));

/* =========================
   SESSION
========================= */

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

let nextUserId = 3;


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

let nextTaskId = 5;


/* =========================
   SUBMISSIONS
========================= */

let submissions = [];
let nextSubmissionId = 1;


/* =========================
   WITHDRAWALS
========================= */

let withdrawals = [];
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


/* =========================================================
   INFORMATION PAGES
   Privacy / Terms / About / Contact
========================================================= */


/* =========================
   PRIVACY POLICY
========================= */

app.get("/privacy", (req, res) => {

  res.send(`
<!DOCTYPE html>
<html lang="en">

<head>

  <meta charset="UTF-8">

  <meta
    name="viewport"
    content="width=device-width,initial-scale=1"
  >

  <meta
    name="description"
    content="TaskEarn Privacy Policy"
  >

  <title>Privacy Policy - TaskEarn</title>

  <style>

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      font-family: Arial, sans-serif;
      background: #f4f6fb;
      color: #172033;
      line-height: 1.7;
    }

    .header {
      background:
        linear-gradient(
          135deg,
          #5b45f5,
          #795cff
        );

      color: white;
      padding: 20px;
    }

    .header h1 {
      max-width: 850px;
      margin: auto;
    }

    .container {
      max-width: 850px;
      margin: auto;
      padding: 20px;
    }

    .card {
      background: white;
      padding: 25px;
      border-radius: 18px;
      box-shadow:
        0 5px 22px rgba(0,0,0,.06);
    }

    a {
      color: #5b45f5;
      font-weight: bold;
      text-decoration: none;
    }

    h2 {
      margin-top: 28px;
    }

    .back {
      margin-top: 25px;
    }

  </style>

</head>

<body>

  <header class="header">

    <h1>
      TaskEarn - Privacy Policy
    </h1>

  </header>

  <main class="container">

    <div class="card">

      <p>
        Welcome to TaskEarn. We respect your privacy
        and are committed to protecting information
        provided by users of our website.
      </p>

      <h2>Information We Collect</h2>

      <p>
        TaskEarn may collect information such as your
        name, email address, account information,
        task submissions and withdrawal requests.
      </p>

      <h2>How We Use Information</h2>

      <p>
        Information may be used to provide account
        services, manage tasks, process submissions,
        maintain platform security and improve the
        website.
      </p>

      <h2>Advertising</h2>

      <p>
        TaskEarn may display advertisements from
        third-party advertising providers such as
        Google AdSense.
      </p>

      <p>
        Advertising providers may use cookies or
        similar technologies according to their
        own policies.
      </p>

      <h2>Cookies</h2>

      <p>
        TaskEarn may use cookies to maintain login
        sessions and support website functionality.
      </p>

      <h2>Third-Party Services</h2>

      <p>
        Some services used by the website may be
        provided by third parties. Their use of
        information is governed by their respective
        privacy policies.
      </p>

      <h2>Data Security</h2>

      <p>
        We take reasonable steps to protect
        information associated with user accounts.
        However, no internet service can guarantee
        absolute security.
      </p>

      <h2>Changes to This Policy</h2>

      <p>
        This Privacy Policy may be updated from
        time to time. Updated versions will be
        published on this page.
      </p>

      <div class="back">

        <a href="/">
          ← Back to TaskEarn
        </a>

      </div>

    </div>

  </main>

</body>

</html>
  `);

});


/* =========================
   TERMS
========================= */

app.get("/terms", (req, res) => {

  res.send(`
<!DOCTYPE html>
<html lang="en">

<head>

  <meta charset="UTF-8">

  <meta
    name="viewport"
    content="width=device-width,initial-scale=1"
  >

  <title>Terms & Conditions - TaskEarn</title>

  <style>

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      font-family: Arial, sans-serif;
      background: #f4f6fb;
      color: #172033;
      line-height: 1.7;
    }

    .header {
      background:
        linear-gradient(
          135deg,
          #5b45f5,
          #795cff
        );

      color: white;
      padding: 20px;
    }

    .header h1 {
      max-width: 850px;
      margin: auto;
    }

    .container {
      max-width: 850px;
      margin: auto;
      padding: 20px;
    }

    .card {
      background: white;
      padding: 25px;
      border-radius: 18px;
      box-shadow:
        0 5px 22px rgba(0,0,0,.06);
    }

    a {
      color: #5b45f5;
      font-weight: bold;
      text-decoration: none;
    }

    h2 {
      margin-top: 28px;
    }

    .back {
      margin-top: 25px;
    }

  </style>

</head>

<body>

  <header class="header">

    <h1>
      TaskEarn - Terms & Conditions
    </h1>

  </header>

  <main class="container">

    <div class="card">

      <p>
        By using TaskEarn, you agree to these
        Terms and Conditions.
      </p>

      <h2>Accounts</h2>

      <p>
        Users are responsible for providing
        accurate account information and protecting
        their login credentials.
      </p>

      <h2>Tasks</h2>

      <p>
        Users must complete tasks according to
        the requirements displayed on the platform.
      </p>

      <p>
        Task availability and rewards may change
        at any time.
      </p>

      <h2>Task Submissions</h2>

      <p>
        Submitting a task does not automatically
        guarantee a reward. Submissions may be
        reviewed before rewards are credited.
      </p>

      <h2>Rewards</h2>

      <p>
        Rewards are subject to task eligibility,
        platform rules and approval.
      </p>

      <h2>Withdrawals</h2>

      <p>
        Withdrawal requests are subject to the
        applicable minimum withdrawal amount and
        platform review.
      </p>

      <h2>Prohibited Activity</h2>

      <p>
        Fraud, fake submissions, automated abuse,
        manipulation, multiple-account abuse and
        attempts to exploit the platform are
        prohibited.
      </p>

      <h2>Changes</h2>

      <p>
        TaskEarn may update these Terms and
        Conditions when necessary. Updated terms
        will be published on this page.
      </p>

      <div class="back">

        <a href="/">
          ← Back to TaskEarn
        </a>

      </div>

    </div>

  </main>

</body>

</html>
  `);

});


/* =========================
   ABOUT
========================= */

app.get("/about", (req, res) => {

  res.send(`
<!DOCTYPE html>
<html lang="en">

<head>

  <meta charset="UTF-8">

  <meta
    name="viewport"
    content="width=device-width,initial-scale=1"
  >

  <title>About TaskEarn</title>

  <style>

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      font-family: Arial, sans-serif;
      background: #f4f6fb;
      color: #172033;
      line-height: 1.7;
    }

    .header {
      background:
        linear-gradient(
          135deg,
          #5b45f5,
          #795cff
        );

      color: white;
      padding: 20px;
    }

    .header h1 {
      max-width: 850px;
      margin: auto;
    }

    .container {
      max-width: 850px;
      margin: auto;
      padding: 20px;
    }

    .card {
      background: white;
      padding: 25px;
      border-radius: 18px;
      box-shadow:
        0 5px 22px rgba(0,0,0,.06);
    }

    a {
      color: #5b45f5;
      font-weight: bold;
      text-decoration: none;
    }

    h2 {
      margin-top: 28px;
    }

    .back {
      margin-top: 25px;
    }

  </style>

</head>

<body>

  <header class="header">

    <h1>
      About TaskEarn
    </h1>

  </header>

  <main class="container">

    <div class="card">

      <h2>What is TaskEarn?</h2>

      <p>
        TaskEarn is an online platform designed
        to provide a simple interface for discovering
        eligible tasks, submitting completed work
        and managing approved task-related rewards.
      </p>

      <h2>Our Goal</h2>

      <p>
        Our goal is to provide users with a simple
        and transparent task discovery and submission
        experience.
      </p>

      <h2>How It Works</h2>

      <p>
        Users can create an account, browse available
        tasks, complete eligible tasks according to
        their requirements and submit them for review.
      </p>

      <p>
        Approved rewards can be reflected in the
        user's TaskEarn wallet according to the
        platform's applicable rules.
      </p>

      <h2>Important Information</h2>

      <p>
        Task availability and rewards can change.
        Earnings are not guaranteed and depend on
        available tasks, eligibility and applicable
        conditions.
      </p>

      <div class="back">

        <a href="/">
          ← Back to TaskEarn
        </a>

      </div>

    </div>

  </main>

</body>

</html>
  `);

});


/* =========================
   CONTACT
========================= */

app.get("/contact", (req, res) => {

  res.send(`
<!DOCTYPE html>
<html lang="en">

<head>

  <meta charset="UTF-8">

  <meta
    name="viewport"
    content="width=device-width,initial-scale=1"
  >

  <title>Contact TaskEarn</title>

  <style>

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      font-family: Arial, sans-serif;
      background: #f4f6fb;
      color: #172033;
      line-height: 1.7;
    }

    .header {
      background:
        linear-gradient(
          135deg,
          #5b45f5,
          #795cff
        );

      color: white;
      padding: 20px;
    }

    .header h1 {
      max-width: 850px;
      margin: auto;
    }

    .container {
      max-width: 850px;
      margin: auto;
      padding: 20px;
    }

    .card {
      background: white;
      padding: 25px;
      border-radius: 18px;
      box-shadow:
        0 5px 22px rgba(0,0,0,.06);
    }

    a {
      color: #5b45f5;
      font-weight: bold;
      text-decoration: none;
    }

    h2 {
      margin-top: 28px;
    }

    .back {
      margin-top: 25px;
    }

  </style>

</head>

<body>

  <header class="header">

    <h1>
      Contact TaskEarn
    </h1>

  </header>

  <main class="container">

    <div class="card">

      <h2>Get in Touch</h2>

      <p>
        If you have questions, feedback or need
        support regarding TaskEarn, please contact
        the TaskEarn support team using the official
        contact method provided by the platform.
      </p>

      <h2>Support</h2>

      <p>
        For account, task or withdrawal questions,
        please provide enough information for the
        support team to understand your request.
      </p>

      <h2>Important</h2>

      <p>
        Never share your password, payment PIN,
        OTP or other confidential security
        information with anyone.
      </p>

      <div class="back">

        <a href="/">
          ← Back to TaskEarn
        </a>

      </div>

    </div>

  </main>

</body>

</html>
  `);

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

      id:
        nextSubmissionId++,

      userId:
        user.id,

      userName:
        user.name,

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
   MY SUBMISSIONS
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
