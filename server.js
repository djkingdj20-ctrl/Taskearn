const express = require("express");
const session = require("express-session");

const app = express();

app.set("trust proxy", 1);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
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
      secure:
        process.env.NODE_ENV === "production",
      maxAge:
        7 * 24 * 60 * 60 * 1000
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
   HOME
========================= */

app.get("/", (req, res) => {

  res.sendFile(
    __dirname + "/public/index.html"
  );

});


/* =========================
   LOGIN PAGE
========================= */

app.get("/login", (req, res) => {

  res.send(`

<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1.0">

<title>Login - TaskEarn</title>

<style>

*{
box-sizing:border-box;
}

body{

margin:0;

font-family:
-apple-system,
BlinkMacSystemFont,
"Segoe UI",
Roboto,
Arial,
sans-serif;

background:
linear-gradient(
135deg,
#fff7ed,
#e8f4ff
);

min-height:100vh;

display:flex;

align-items:center;

justify-content:center;

padding:20px;

color:#172033;

}

.card{

background:#ffffff;

width:100%;

max-width:430px;

padding:30px;

border-radius:25px;

box-shadow:
0 15px 40px
rgba(0,0,0,.10);

}

.logo{

text-align:center;

font-size:30px;

font-weight:800;

margin-bottom:8px;

}

.logo span{

color:#ff6b35;

}

.subtitle{

text-align:center;

color:#687386;

margin-bottom:25px;

}

.form{

display:grid;

gap:13px;

}

input{

width:100%;

padding:15px;

border:1px solid #ddd;

border-radius:13px;

font-size:16px;

outline:none;

}

input:focus{

border-color:#ff6b35;

box-shadow:
0 0 0 3px
rgba(255,107,53,.10);

}

button{

width:100%;

padding:15px;

border:0;

border-radius:13px;

background:#ff6b35;

color:white;

font-size:16px;

font-weight:bold;

cursor:pointer;

}

button:hover{

background:#f25822;

}

.demo{

margin-top:20px;

padding:14px;

background:#fff7ed;

border-radius:13px;

font-size:13px;

color:#687386;

line-height:1.6;

}

.links{

text-align:center;

margin-top:20px;

line-height:2;

}

a{

color:#ff6b35;

font-weight:bold;

text-decoration:none;

}

.back{

display:block;

text-align:center;

margin-top:20px;

color:#687386;

}

</style>

</head>

<body>

<div class="card">

<div class="logo">
Task<span>Earn</span>
</div>

<div class="subtitle">
Login to your TaskEarn account
</div>

<form
class="form"
onsubmit="login(event)">

<input
id="email"
type="email"
placeholder="Email"
autocomplete="email"
required>

<input
id="password"
type="password"
placeholder="Password"
autocomplete="current-password"
required>

<button type="submit">
Login
</button>

</form>

<div class="demo">

<strong>Demo User</strong><br>

user@taskearn.demo<br>

Password: 123456

<br><br>

<strong>Admin</strong><br>

admin@taskearn.demo<br>

Password: admin123

</div>

<div class="links">

Don't have an account?

<a href="/register">
Create Account
</a>

</div>

<a
class="back"
href="/">

← Back to TaskEarn

</a>

</div>


<script>

async function login(event){

event.preventDefault();

const email =
document.getElementById("email").value.trim();

const password =
document.getElementById("password").value;

try{

const response =
await fetch("/api/login",{

method:"POST",

headers:{
"Content-Type":
"application/json"
},

body:JSON.stringify({
email,
password
})

});

const data =
await response.json();

if(!response.ok){

throw new Error(
data.error ||
"Login failed"
);

}

window.location.href="/";

}catch(error){

alert(error.message);

}

}

</script>

</body>

</html>

  `);

});


/* =========================
   REGISTER PAGE
========================= */

app.get("/register", (req, res) => {

  res.send(`

<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1.0">

<title>Create Account - TaskEarn</title>

<style>

*{
box-sizing:border-box;
}

body{

margin:0;

font-family:
-apple-system,
BlinkMacSystemFont,
"Segoe UI",
Roboto,
Arial,
sans-serif;

background:
linear-gradient(
135deg,
#fff7ed,
#e8f4ff
);

min-height:100vh;

display:flex;

align-items:center;

justify-content:center;

padding:20px;

color:#172033;

}

.card{

background:#ffffff;

width:100%;

max-width:430px;

padding:30px;

border-radius:25px;

box-shadow:
0 15px 40px
rgba(0,0,0,.10);

}

.logo{

text-align:center;

font-size:30px;

font-weight:800;

margin-bottom:8px;

}

.logo span{

color:#ff6b35;

}

.subtitle{

text-align:center;

color:#687386;

margin-bottom:25px;

}

.form{

display:grid;

gap:13px;

}

input{

width:100%;

padding:15px;

border:1px solid #ddd;

border-radius:13px;

font-size:16px;

outline:none;

}

input:focus{

border-color:#ff6b35;

box-shadow:
0 0 0 3px
rgba(255,107,53,.10);

}

button{

width:100%;

padding:15px;

border:0;

border-radius:13px;

background:#ff6b35;

color:white;

font-size:16px;

font-weight:bold;

cursor:pointer;

}

button:hover{

background:#f25822;

}

.note{

margin-top:15px;

font-size:12px;

color:#687386;

line-height:1.6;

}

.links{

text-align:center;

margin-top:20px;

line-height:2;

}

a{

color:#ff6b35;

font-weight:bold;

text-decoration:none;

}

.back{

display:block;

text-align:center;

margin-top:20px;

color:#687386;

}

</style>

</head>

<body>

<div class="card">

<div class="logo">
Task<span>Earn</span>
</div>

<div class="subtitle">
Create your TaskEarn account
</div>

<form
class="form"
onsubmit="registerUser(event)">

<input
id="name"
type="text"
placeholder="Your name"
autocomplete="name"
maxlength="60"
required>

<input
id="email"
type="email"
placeholder="Email"
autocomplete="email"
required>

<input
id="password"
type="password"
placeholder="Password - minimum 6 characters"
autocomplete="new-password"
minlength="6"
required>

<button type="submit">
Create Account
</button>

</form>

<div class="note">

By creating an account, you agree to the
TaskEarn

<a href="/terms">
Terms & Conditions
</a>

and

<a href="/privacy">
Privacy Policy
</a>.

</div>

<div class="links">

Already have an account?

<a href="/login">
Login
</a>

</div>

<a
class="back"
href="/">

← Back to TaskEarn

</a>

</div>


<script>

async function registerUser(event){

event.preventDefault();

const name =
document.getElementById("name").value.trim();

const email =
document.getElementById("email").value.trim();

const password =
document.getElementById("password").value;

try{

const response =
await fetch("/api/register",{

method:"POST",

headers:{
"Content-Type":
"application/json"
},

body:JSON.stringify({
name,
email,
password
})

});

const data =
await response.json();

if(!response.ok){

throw new Error(
data.error ||
"Registration failed"
);

}

alert(
"Account created successfully!"
);

window.location.href="/";

}catch(error){

alert(error.message);

}

}

</script>

</body>

</html>

  `);

});


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
   CURRENT USER
========================= */

app.get("/api/me", (req, res) => {

  res.json(
    req.session.user || null
  );

});


/* =========================
   LOGIN API
========================= */

app.post("/api/login", (req, res) => {

  const email =
    String(req.body.email || "")
      .trim()
      .toLowerCase();

  const password =
    String(req.body.password || "");

  if (!email || !password) {

    return res.status(400).json({
      error:
        "Email and password are required"
    });

  }

  const user =
    users.find(
      item =>
        item.email.toLowerCase() === email &&
        item.password === password
    );

  if (!user) {

    return res.status(401).json({
      error:
        "Invalid email or password"
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

    res.json({

      ok: true,

      user:
        req.session.user

    });

  });

});


/* =========================
   REGISTER API
========================= */

app.post("/api/register", (req, res) => {

  const name =
    String(req.body.name || "")
      .trim();

  const email =
    String(req.body.email || "")
      .trim()
      .toLowerCase();

  const password =
    String(req.body.password || "");

  if (!name || !email || !password) {

    return res.status(400).json({
      error:
        "All fields are required"
    });

  }

  if (name.length < 2) {

    return res.status(400).json({
      error:
        "Name must be at least 2 characters"
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

      console.error(
        "Registration session error:",
        err
      );

      return res.status(500).json({
        error:
          "Account created but login session failed"
      });

    }

    res.json({

      ok: true,

      user:
        req.session.user

    });

  });

});


/* =========================
   LOGOUT
========================= */

app.post("/api/logout", (req, res) => {

  req.session.destroy(err => {

    if (err) {

      return res.status(500).json({
        error: "Logout failed"
      });

    }

    res.clearCookie("connect.sid");

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

    const user =
      getUser(req.session.user.id);

    const task =
      getTask(req.params.id);

    if (!user) {

      return res.status(404).json({
        error: "User not found"
      });

    }

    if (!task || !task.active) {

      return res.status(404).json({
        error: "Task not available"
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

    submissions.push({

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

    });

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
      getUser(req.session.user.id);

    if (!user) {

      return res.status(404).json({
        error: "User not found"
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
            item.userId === user.id
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
      getUser(req.session.user.id);

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

    if (!Number.isFinite(amount)) {

      return res.status(400).json({
        error: "Invalid amount"
      });

    }

    if (amount < 100) {

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

    user.balance -= amount;

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

      ok: true,

      message:
        "Withdrawal request submitted"

    });

  }
);
