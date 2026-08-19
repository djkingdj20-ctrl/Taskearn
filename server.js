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
   PAGE ROUTES
========================= */


/*
   HOME
*/

app.get("/", (req, res) => {

  res.sendFile(
    __dirname + "/public/index.html"
  );

});


/*
   LOGIN PAGE
*/

app.get("/login", (req, res) => {

  res.send(`

<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
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

background:white;

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

font-size:28px;

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

gap:12px;

}

input{

width:100%;

padding:14px;

border:1px solid #ddd;

border-radius:12px;

font-size:16px;

outline:none;

}

input:focus{

border-color:#ff6b35;

}

button{

width:100%;

padding:14px;

border:0;

border-radius:12px;

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

border-radius:12px;

font-size:13px;

color:#687386;

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


<a class="back" href="/">
← Back to TaskEarn
</a>

</div>


<script>

async function login(event){

event.preventDefault();

const email =
document.getElementById("email").value;

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


/*
   REGISTER PAGE
*/

app.get("/register", (req, res) => {

  res.send(`

<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
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

background:white;

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

font-size:28px;

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

gap:12px;

}

input{

width:100%;

padding:14px;

border:1px solid #ddd;

border-radius:12px;

font-size:16px;

outline:none;

}

input:focus{

border-color:#ff6b35;

}

button{

width:100%;

padding:14px;

border:0;

border-radius:12px;

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

line-height:1.5;

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

By creating an account, you agree to
the TaskEarn
<a href="/terms">Terms & Conditions</a>
and
<a href="/privacy">Privacy Policy</a>.

</div>


<div class="links">

Already have an account?

<a href="/login">
Login
</a>

</div>


<a class="back" href="/">
← Back to TaskEarn
</a>

</div>


<script>

async function registerUser(event){

event.preventDefault();


const name =
document.getElementById("name").value;

const email =
document.getElementById("email").value;

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
   HEALTH
========================= */

app.get("/health", (req,res)=>{

  res.json({
    ok:true,
    service:"TaskEarn"
  });

});


/* =========================
   CURRENT USER
========================= */

app.get("/api/me",(req,res)=>{

  res.json(
    req.session.user || null
  );

});


/* =========================
   LOGIN API
========================= */

app.post("/api/login",(req,res)=>{

  const email =
    String(req.body.email || "")
      .trim()
      .toLowerCase();

  const password =
    String(req.body.password || "");


  if(!email || !password){

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


  if(!user){

    return res.status(401).json({
      error:
        "Invalid email or password"
    });

  }


  req.session.user =
    publicUser(user);


  req.session.save(err=>{

    if(err){

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

      ok:true,

      user:
        req.session.user

    });

  });

});


/* =========================
   REGISTER API
========================= */

app.post("/api/register",(req,res)=>{

  const name =
    String(req.body.name || "")
      .trim();

  const email =
    String(req.body.email || "")
      .trim()
      .toLowerCase();

  const password =
    String(req.body.password || "");


  if(!name || !email || !password){

    return res.status(400).json({
      error:
        "All fields are required"
    });

  }


  if(password.length < 6){

    return res.status(400).json({
      error:
        "Password must be at least 6 characters"
    });

  }


  if(
    users.some(
      user =>
        user.email.toLowerCase() === email
    )
  ){

    return res.status(400).json({
      error:
        "Email already exists"
    });

  }


  const user={

    id:nextUserId++,

    name,

    email,

    password,

    role:"user",

    balance:0,

    completed:0

  };


  users.push(user);


  req.session.user =
    publicUser(user);


  req.session.save(err=>{

    if(err){

      return res.status(500).json({
        error:
          "Account created but login session failed"
      });

    }


    res.json({

      ok:true,

      user:req.session.user

    });

  });

});


/* =========================
   LOGOUT
========================= */

app.post("/api/logout",(req,res)=>{

  req.session.destroy(err=>{

    if(err){

      return res.status(500).json({
        error:"Logout failed"
      });

    }


    res.clearCookie("connect.sid");


    res.json({
      ok:true
    });

  });

});


/* =========================
   TASKS
========================= */

app.get("/api/tasks",(req,res)=>{

  res.json(
    tasks.filter(
      task=>task.active
    )
  );

});


app.get("/api/tasks/:id",(req,res)=>{

  const task =
    getTask(req.params.id);


  if(!task){

    return res.status(404).json({
      error:"Task not found"
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
  (req,res)=>{

    const user =
      getUser(req.session.user.id);

    const task =
      getTask(req.params.id);


    if(!user){

      return res.status(404).json({
        error:"User not found"
      });

    }


    if(!task || !task.active){

      return res.status(404).json({
        error:"Task not available"
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


    if(existing){

      return res.status(400).json({

        error:
          existing.status === "approved"
          ?
          "Task already approved"
          :
          "Task already submitted"

      });

    }


    submissions.push({

      id:nextSubmissionId++,

      userId:user.id,

      userName:user.name,

      taskId:task.id,

      taskTitle:task.title,

      reward:Number(task.reward),

      status:"pending",

      submittedAt:
        new Date().toISOString()

    });


    res.json({

      ok:true,

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
  (req,res)=>{

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
  (req,res)=>{

    const user =
      getUser(req.session.user.id);


    if(!user){

      return res.status(404).json({
        error:"User not found"
      });

    }


    res.json({

      balance:Number(user.balance),

      completed:Number(user.completed),

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
  (req,res)=>{

    const user =
      getUser(req.session.user.id);


    if(!user){

      return res.status(404).json({
        error:"User not found"
      });

    }


    const amount =
      Number(req.body.amount);


    const method =
      String(
        req.body.method || "UPI"
      ).trim();


    if(!Number.isFinite(amount)){

      return res.status(400).json({
        error:"Invalid amount"
      });

    }


    if(amount < 100){

      return res.status(400).json({
        error:
          "Minimum withdrawal is ₹100"
      });

    }


    if(amount > user.balance){

      return res.status(400).json({
        error:
          "Insufficient balance"
      });

    }


    user.balance -= amount;


    withdrawals.push({

      id:nextWithdrawalId++,

      userId:user.id,

      name:user.name,

      amount,

      method,

      status:"pending",

      createdAt:
        new Date().toISOString()

    });


    res.json({

      ok:true,

      message:
        "Withdrawal request submitted"

    });

  }
);


/* =========================
   ADMIN STATS
========================= */

app.get(
  "/api/admin/stats",
  admin,
  (req,res)=>{

    res.json({

      users:users.length,

      tasks:tasks.length,

      submissions:
        submissions.filter(
          item =>
            item.status === "pending"
        ).length,

      pending:
        withdrawals.filter(
          item =>
            item.status === "pending"
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
  (req,res)=>{

    res.json(tasks);

  }
);


/* =========================
   ADD TASK
========================= */

app.post(
  "/api/admin/tasks",
  admin,
  (req,res)=>{

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


    if(
      !title ||
      !description ||
      !type
    ){

      return res.status(400).json({
        error:
          "Title, description and type are required"
      });

    }


    if(
      !Number.isFinite(reward) ||
      reward <= 0
    ){

      return res.status(400).json({
        error:"Invalid reward"
      });

    }


    const task={

      id:nextTaskId++,

      title,

      description,

      type,

      reward,

      active:true

    };


    tasks.push(task);


    res.json(task);

  }
);


/* =========================
   EDIT TASK
========================= */

app.put(
  "/api/admin/tasks/:id",
  admin,
  (req,res)=>{

    const task =
      getTask(req.params.id);


    if(!task){

      return res.status(404).json({
        error:"Task not found"
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


    if(
      !title ||
      !description ||
      !type
    ){

      return res.status(400).json({
        error:
          "Title, description and type are required"
      });

    }


    if(
      !Number.isFinite(reward) ||
      reward <= 0
    ){

      return res.status(400).json({
        error:"Invalid reward"
      });

    }


    task.title = title;

    task.description = description;

    task.type = type;

    task.reward = reward;


    if(
      typeof req.body.active ===
      "boolean"
    ){

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
  (req,res)=>{

    const task =
      getTask(req.params.id);


    if(!task){

      return res.status(404).json({
        error:"Task not found"
      });

    }


    task.active=false;


    res.json({
      ok:true
    });

  }
);


/* =========================
   ADMIN SUBMISSIONS
========================= */

app.get(
  "/api/admin/submissions",
  admin,
  (req,res)=>{

    res.json(submissions);

  }
);


/* =========================
   REVIEW SUBMISSION
========================= */

app.post(
  "/api/admin/submissions/:id",
  admin,
  (req,res)=>{

    const submission =
      submissions.find(
        item =>
          item.id ===
          Number(req.params.id)
      );


    if(!submission){

      return res.status(404).json({
        error:
          "Submission not found"
      });

    }


    if(
      submission.status !==
      "pending"
    ){

      return res.status(400).json({
        error:
          "Submission already reviewed"
      });

    }


    const status =
      String(
        req.body.status || ""
      ).toLowerCase();


    if(
      status !== "approved" &&
      status !== "rejected"
    ){

      return res.status(400).json({
        error:"Invalid status"
      });

    }


    const user =
      getUser(
        submission.userId
      );


    if(!user){

      return res.status(404).json({
        error:"User not found"
      });

    }


    submission.status =
      status;


    if(status === "approved"){

      user.balance +=
        Number(
          submission.reward
        );

      user.completed += 1;

    }


    res.json({

      ok:true,

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
  (req,res)=>{

    res.json(withdrawals);

  }
);


/* =========================
   REVIEW WITHDRAWAL
========================= */

app.post(
  "/api/admin/withdrawals/:id",
  admin,
  (req,res)=>{

    const withdrawal =
      withdrawals.find(
        item =>
          item.id ===
          Number(req.params.id)
      );


    if(!withdrawal){

      return res.status(404).json({
        error:
          "Withdrawal not found"
      });

    }


    if(
      withdrawal.status !==
      "pending"
    ){

      return res.status(400).json({
        error:
          "Withdrawal already reviewed"
      });

    }


    const status =
      String(
        req.body.status || ""
      ).toLowerCase();


    if(
      status !== "approved" &&
      status !== "rejected"
    ){

      return res.status(400).json({
        error:"Invalid status"
      });

    }


    const user =
      getUser(
        withdrawal.userId
      );


    if(!user){

      return res.status(404).json({
        error:"User not found"
      });

    }


    withdrawal.status =
      status;


    if(status === "rejected"){

      user.balance +=
        Number(
          withdrawal.amount
        );

    }


    res.json({

      ok:true,

      status

    });

  }
);


/* =========================
   PRIVACY
========================= */

app.get("/privacy",(req,res)=>{

res.send(`

<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width,initial-scale=1">

<title>Privacy Policy - TaskEarn</title>

<style>

body{
margin:0;
font-family:Arial,sans-serif;
background:#f4f6fb;
color:#172033;
line-height:1.7;
}

.header{
background:#ff6b35;
color:white;
padding:25px;
}

.header h1{
max-width:850px;
margin:auto;
}

.container{
max-width:850px;
margin:auto;
padding:20px;
}

.card{
background:white;
padding:25px;
border-radius:20px;
box-shadow:0 5px 22px rgba(0,0,0,.06);
}

a{
color:#ff6b35;
font-weight:bold;
text-decoration:none;
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

<h2>1. Information We Collect</h2>

<p>
TaskEarn may collect information such as
your name, email address, account information,
task submissions and withdrawal requests.
</p>


<h2>2. How We Use Information</h2>

<p>
Information may be used to provide account
services, manage tasks, process submissions,
maintain platform security and improve the
website.
</p>


<h2>3. Advertising</h2>

<p>
TaskEarn may display advertisements from
third-party advertising providers such as
Google AdSense.
</p>


<h2>4. Cookies</h2>

<p>
TaskEarn may use cookies to maintain login
sessions and support website functionality.
</p>


<h2>5. Data Security</h2>

<p>
We take reasonable steps to protect information
associated with user accounts.
</p>


<h2>6. Data Retention</h2>

<p>
Information may be retained for as long as
reasonably necessary for account operation,
security, legal requirements and platform
administration.
</p>


<h2>7. Third-Party Services</h2>

<p>
TaskEarn may use third-party services for
advertising, hosting, analytics or other
website functionality.
</p>


<h2>8. Changes</h2>

<p>
This Privacy Policy may be updated from time
to time. Users should review this page for
future changes.
</p>


<p>
<a href="/">
← Back to TaskEarn
</a>
</p>

</div>

</main>

</body>

</html>

`);

});


/* =========================
   TERMS
========================= */

app.get("/terms",(req,res)=>{

res.send(`

<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width,initial-scale=1">

<title>Terms & Conditions - TaskEarn</title>

<style>

body{
margin:0;
font-family:Arial,sans-serif;
background:#f4f6fb;
color:#172033;
line-height:1.7;
}

.header{
background:#ff6b35;
color:white;
padding:25px;
}

.header h1{
max-width:850px;
margin:auto;
}

.container{
max-width:850px;
margin:auto;
padding:20px;
}

.card{
background:white;
padding:25px;
border-radius:20px;
box-shadow:0 5px 22px rgba(0,0,0,.06);
}

a{
color:#ff6b35;
font-weight:bold;
text-decoration:none;
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


<h2>1. Acceptance of Terms</h2>

<p>
By accessing or using TaskEarn, you agree
to follow these Terms & Conditions and all
applicable laws and regulations.
</p>


<h2>2. Account Registration</h2>

<p>
Users must provide accurate information when
creating an account and are responsible for
protecting their login credentials.
</p>


<h2>3. Account Security</h2>

<p>
Users should not share their password, OTP,
payment PIN or other confidential security
information.
</p>


<h2>4. Tasks</h2>

<p>
Users must complete tasks according to the
requirements displayed on the platform.
</p>


<h2>5. Task Submissions</h2>

<p>
Submitting a task does not automatically
guarantee a reward. Submissions may be
reviewed before rewards are credited.
</p>


<h2>6. Rewards</h2>

<p>
Rewards are subject to task eligibility,
platform rules and approval.
</p>


<h2>7. Withdrawals</h2>

<p>
Withdrawal requests are subject to the
applicable minimum withdrawal amount,
available balance and platform review.
</p>


<h2>8. Prohibited Activities</h2>

<p>
Fraud, fake submissions, automated abuse,
manipulation, multiple-account abuse,
misleading activity and attempts to exploit
the platform are prohibited.
</p>


<h2>9. Account Suspension</h2>

<p>
TaskEarn may restrict, suspend or terminate
accounts where there is reasonable evidence
of abuse, fraud, manipulation or violation
of these terms.
</p>


<h2>10. No Guaranteed Income</h2>

<p>
Task availability and rewards may change.
TaskEarn does not guarantee a specific level
of income or earnings.
</p>


<h2>11. Changes to the Platform</h2>

<p>
TaskEarn may modify tasks, features,
requirements or platform functionality from
time to time.
</p>


<h2>12. Changes to Terms</h2>

<p>
These Terms & Conditions may be updated from
time to time.
</p>


<p>
<a href="/">
← Back to TaskEarn
</a>
</p>

</div>

</main>

</body>

</html>

`);

});


/* =========================
   ABOUT
========================= */

app.get("/about",(req,res)=>{

res.send(`

<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width,initial-scale=1">

<title>About TaskEarn</title>

<style>

body{
margin:0;
font-family:Arial,sans-serif;
background:#f4f6fb;
color:#172033;
line-height:1.7;
}

.header{
background:#ff6b35;
color:white;
padding:25px;
}

.header h1{
max-width:850px;
margin:auto;
}

.container{
max-width:850px;
margin:auto;
padding:20px;
}

.card{
background:white;
padding:25px;
border-radius:20px;
box-shadow:0 5px 22px rgba(0,0,0,.06);
}

a{
color:#ff6b35;
font-weight:bold;
text-decoration:none;
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
TaskEarn is an online platform designed to
provide a simple interface for discovering
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
tasks, complete eligible tasks and submit
them for review.
</p>


<h2>Task Availability</h2>

<p>
Task availability and rewards can change
depending on the tasks available on the
platform.
</p>


<h2>Important Information</h2>

<p>
Earnings are not guaranteed and depend on
available tasks, eligibility and applicable
conditions.
</p>


<p>
<a href="/">
← Back to TaskEarn
</a>
</p>

</div>

</main>

</body>

</html>

`);

});


/* =========================
   CONTACT
========================= */

app.get("/contact",(req,res)=>{

res.send(`

<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width,initial-scale=1">

<title>Contact TaskEarn</title>

<style>

body{
margin:0;
font-family:Arial,sans-serif;
background:#f4f6fb;
color:#172033;
line-height:1.7;
}

.header{
background:#ff6b35;
color:white;
padding:25px;
}

.header h1{
max-width:850px;
margin:auto;
}

.container{
max-width:850px;
margin:auto;
padding:20px;
}

.card{
background:white;
padding:25px;
border-radius:20px;
box-shadow:0 5px 22px rgba(0,0,0,.06);
}

a{
color:#ff6b35;
font-weight:bold;
text-decoration:none;
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


<h2>Account Support</h2>

<p>
For account, task or withdrawal questions,
please provide enough information for the
support team to understand your request.
</p>


<h2>Security</h2>

<p>
Never share your password, payment PIN,
OTP or other confidential security
information with anyone.
</p>


<h2>Support Email</h2>

<p>
support@taskearn.demo
</p>


<p>
<a href="/">
← Back to TaskEarn
</a>
</p>

</div>

</main>

</body>

</html>

`);

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
