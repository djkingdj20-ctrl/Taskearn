const express = require("express");
const session = require("express-session");

const app = express();

app.set("trust proxy", 1);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

/* =====================================================
   SESSION
===================================================== */

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


/* =====================================================
   USERS
===================================================== */

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


/* =====================================================
   TASKS
===================================================== */

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


/* =====================================================
   SUBMISSIONS
===================================================== */

let submissions = [];

let nextSubmissionId = 1;


/* =====================================================
   WITHDRAWALS
===================================================== */

let withdrawals = [];

let nextWithdrawalId = 1;


/* =====================================================
   HELPERS
===================================================== */

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


/* =====================================================
   AUTH MIDDLEWARE
===================================================== */

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


/* =====================================================
   HOME
===================================================== */

app.get("/", (req, res) => {

  res.sendFile(
    __dirname + "/public/index.html"
  );

});


/* =====================================================
   LOGIN PAGE
===================================================== */

app.get("/login", (req, res) => {

  res.send(`

<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1.0"
>

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

width:100%;

max-width:430px;

background:#fff;

padding:30px;

border-radius:25px;

box-shadow:
0 15px 40px rgba(0,0,0,.10);

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

font-weight:700;

cursor:pointer;

}

button:hover{

background:#f25822;

}

.demo{

margin-top:20px;

padding:15px;

background:#fff7ed;

border-radius:13px;

font-size:13px;

line-height:1.6;

}

.links{

text-align:center;

margin-top:20px;

}

a{

color:#ff6b35;

font-weight:700;

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
onsubmit="login(event)"
>

<input
id="email"
type="email"
placeholder="Email"
autocomplete="email"
required
>

<input
id="password"
type="password"
placeholder="Password"
autocomplete="current-password"
required
>

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
href="/"
>
← Back to TaskEarn
</a>

</div>

<script>

async function login(event){

event.preventDefault();

const email =
document.getElementById("email")
.value
.trim();

const password =
document.getElementById("password")
.value;

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


/* =====================================================
   REGISTER PAGE
===================================================== */

app.get("/register", (req, res) => {

  res.send(`

<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1.0"
>

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

width:100%;

max-width:430px;

background:#fff;

padding:30px;

border-radius:25px;

box-shadow:
0 15px 40px rgba(0,0,0,.10);

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

font-weight:700;

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

}

a{

color:#ff6b35;

font-weight:700;

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
onsubmit="registerUser(event)"
>

<input
id="name"
type="text"
placeholder="Your name"
autocomplete="name"
required
>

<input
id="email"
type="email"
placeholder="Email"
autocomplete="email"
required
>

<input
id="password"
type="password"
placeholder="Password - minimum 6 characters"
autocomplete="new-password"
minlength="6"
required
>

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
href="/"
>
← Back to TaskEarn
</a>

</div>

<script>

async function registerUser(event){

event.preventDefault();

const name =
document.getElementById("name")
.value
.trim();

const email =
document.getElementById("email")
.value
.trim();

const password =
document.getElementById("password")
.value;

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


/* =====================================================
   HEALTH
===================================================== */

app.get("/health",(req,res)=>{

  res.json({

    ok:true,

    service:"TaskEarn",

    status:"running"

  });

});


/* =====================================================
   CURRENT USER
===================================================== */

app.get("/api/me",(req,res)=>{

  res.json(
    req.session.user || null
  );

});


/* =====================================================
   LOGIN API
===================================================== */

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


/* =====================================================
   REGISTER API
===================================================== */

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


  if(name.length < 2){

    return res.status(400).json({

      error:
        "Name must be at least 2 characters"

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


  const user = {

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

      ok:true,

      user:req.session.user

    });

  });

});


/* =====================================================
   LOGOUT
===================================================== */

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


/* =====================================================
   TASKS
===================================================== */

app.get("/api/tasks",(req,res)=>{

  res.json(

    tasks.filter(
      task => task.active
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


/* =====================================================
   SUBMIT TASK
===================================================== */

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


/* =====================================================
   MY SUBMISSIONS
===================================================== */

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


/* =====================================================
   WALLET
===================================================== */

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


/* =====================================================
   WITHDRAW
===================================================== */

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


    if(!method){

      return res.status(400).json({

        error:
          "Withdrawal method is required"

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


/* =====================================================
   ADMIN STATS
===================================================== */

app.get(
  "/api/admin/stats",
  admin,
  (req,res)=>{

    res.json({

      users:
        users.length,

      tasks:
        tasks.length,

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


/* =====================================================
   ADMIN TASKS
===================================================== */

app.get(
  "/api/admin/tasks",
  admin,
  (req,res)=>{

    res.json(tasks);

  }
);


/* =====================================================
   ADD TASK
===================================================== */

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


    const task = {

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


/* =====================================================
   EDIT TASK
===================================================== */

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


    task.title =
      title;

    task.description =
      description;

    task.type =
      type;

    task.reward =
      reward;


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


/* =====================================================
   DISABLE TASK
===================================================== */

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


    task.active =
      false;


    res.json({

      ok:true

    });

  }
);


/* =====================================================
   ADMIN SUBMISSIONS
===================================================== */

app.get(
  "/api/admin/submissions",
  admin,
  (req,res)=>{

    res.json(submissions);

  }
);


/* =====================================================
   REVIEW SUBMISSION
===================================================== */

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


    if(
      status === "approved"
    ){

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


/* =====================================================
   ADMIN WITHDRAWALS
===================================================== */

app.get(
  "/api/admin/withdrawals",
  admin,
  (req,res)=>{

    res.json(withdrawals);

  }
);


/* =====================================================
   REVIEW WITHDRAWAL
===================================================== */

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


    if(
      status === "rejected"
    ){

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


/* =====================================================
   PRIVACY POLICY
===================================================== */

app.get("/privacy",(req,res)=>{

res.send(`

<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1"
>

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
padding:25px 20px;
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
box-shadow:
0 5px 22px rgba(0,0,0,.06);
}

h2{
margin-top:28px;
}

a{
color:#ff6b35;
font-weight:bold;
text-decoration:none;
}

@media(max-width:600px){

.container{
padding:12px;
}

.card{
padding:20px;
}

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
Last updated: August 19, 2026
</p>


<h2>1. Information We Collect</h2>

<p>
TaskEarn may collect information that users
provide when creating or using an account,
including name, email address, account
information, task submissions and withdrawal
requests.
</p>


<h2>2. How We Use Information</h2>

<p>
Information may be used to operate user
accounts, provide task-related services,
process submissions, manage withdrawals,
maintain security, prevent abuse and improve
the website.
</p>


<h2>3. Cookies and Sessions</h2>

<p>
TaskEarn may use cookies and session
technologies to keep users logged in and
support essential website functionality.
</p>


<h2>4. Advertising</h2>

<p>
TaskEarn may display advertisements provided
by third-party advertising services, including
Google AdSense, if advertising is enabled.
</p>


<h2>5. Third-Party Services</h2>

<p>
The website may use third-party services for
hosting, analytics, advertising, security,
payment processing or other functionality.
Those services may have their own privacy
policies and terms.
</p>


<h2>6. Information Sharing</h2>

<p>
TaskEarn does not intend to sell personal
information. Information may be disclosed
when necessary to operate the service, comply
with legal requirements, protect users,
investigate abuse or protect the platform.
</p>


<h2>7. Data Security</h2>

<p>
Reasonable technical and organizational
measures may be used to protect account
information. However, no internet service
can guarantee absolute security.
</p>


<h2>8. Data Retention</h2>

<p>
Information may be retained for as long as
reasonably necessary for account operation,
security, dispute resolution, legal
requirements and platform administration.
</p>


<h2>9. Children's Privacy</h2>

<p>
TaskEarn is not intended for users who are
not legally permitted to use online earning
or task platforms under applicable law.
</p>


<h2>10. Your Choices</h2>

<p>
Users may contact TaskEarn support regarding
questions about their account information,
privacy or use of the service.
</p>


<h2>11. Policy Changes</h2>

<p>
This Privacy Policy may be updated from time
to time. The updated version will be posted
on this page.
</p>


<h2>12. Contact</h2>

<p>
For privacy-related questions, please use
the official TaskEarn contact method.
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


/* =====================================================
   TERMS & CONDITIONS
===================================================== */

app.get("/terms",(req,res)=>{

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
padding:25px 20px;
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
box-shadow:
0 5px 22px rgba(0,0,0,.06);
}

h2{
margin-top:28px;
}

a{
color:#ff6b35;
font-weight:bold;
text-decoration:none;
}

@media(max-width:600px){

.container{
padding:12px;
}

.card{
padding:20px;
}

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
Last updated: August 19, 2026
</p>


<h2>1. Acceptance of Terms</h2>

<p>
By accessing or using TaskEarn, you agree
to these Terms & Conditions and applicable
laws and regulations.
</p>


<h2>2. Eligibility</h2>

<p>
You are responsible for ensuring that you
are legally permitted to use the TaskEarn
platform in your country or region.
</p>


<h2>3. Account Registration</h2>

<p>
Users must provide accurate information when
creating an account. Users are responsible
for maintaining the confidentiality of their
login credentials.
</p>


<h2>4. One Account</h2>

<p>
Unless TaskEarn expressly permits otherwise,
users should not create or operate multiple
accounts for the purpose of obtaining
additional rewards or benefits.
</p>


<h2>5. Account Security</h2>

<p>
Users must keep passwords and other security
information confidential. TaskEarn support
will never require users to publicly disclose
their password, OTP or payment PIN.
</p>


<h2>6. Tasks</h2>

<p>
Available tasks may have specific eligibility
requirements, instructions, deadlines and
completion conditions. Users must follow the
instructions shown for each task.
</p>


<h2>7. Task Submissions</h2>

<p>
Submitting a task does not automatically
guarantee a reward. A submission may be
reviewed before any reward is credited.
</p>


<h2>8. Rewards</h2>

<p>
Rewards are subject to task eligibility,
successful completion, review and applicable
platform conditions. Task rewards may change
at any time.
</p>


<h2>9. No Guaranteed Income</h2>

<p>
TaskEarn does not guarantee a particular
amount of income, number of tasks or specific
earning level. Earnings depend on available
tasks, eligibility and successful completion.
</p>


<h2>10. Withdrawals</h2>

<p>
Withdrawal requests are subject to the
minimum withdrawal amount, available balance,
verification requirements and platform review.
</p>


<h2>11. Withdrawal Review</h2>

<p>
A withdrawal request may remain pending while
it is reviewed. A request may be rejected
where required information is incomplete,
activity is suspicious or platform rules have
been violated.
</p>


<h2>12. Prohibited Activities</h2>

<p>
Users must not engage in fraud, fake
submissions, automated abuse, manipulation,
misleading activity, multiple-account abuse,
attempts to exploit technical weaknesses,
or other activity that may harm the platform
or other users.
</p>


<h2>13. Automated Activity</h2>

<p>
Bots, scripts or automated systems must not
be used to manipulate task completion,
rewards, traffic, advertisements or other
platform systems unless expressly authorized.
</p>


<h2>14. Advertising</h2>

<p>
Where advertisements are displayed, users
must not artificially generate ad impressions
or clicks, encourage invalid clicks, or
otherwise manipulate advertising systems.
</p>


<h2>15. Account Suspension</h2>

<p>
TaskEarn may restrict, suspend or terminate
an account where there is reasonable evidence
of fraud, abuse, manipulation, security
issues or violation of these Terms.
</p>


<h2>16. Changes to the Platform</h2>

<p>
TaskEarn may change, suspend or discontinue
tasks, features, rewards or other platform
functionality from time to time.
</p>


<h2>17. Third-Party Services</h2>

<p>
TaskEarn may rely on third-party services
such as hosting, advertising, analytics,
payment or other service providers.
Third-party services may have separate
terms and policies.
</p>


<h2>18. User Responsibility</h2>

<p>
Users are responsible for reviewing task
requirements and providing accurate
information when using the platform.
</p>


<h2>19. Taxes and Legal Obligations</h2>

<p>
Users are responsible for understanding and
complying with any taxes, reporting
requirements or other legal obligations
applicable to rewards they receive.
</p>


<h2>20. Limitation of Liability</h2>

<p>
To the extent permitted by applicable law,
TaskEarn is not responsible for losses
resulting from service interruptions,
third-party services, unauthorized account
access caused by user negligence or other
events outside reasonable control.
</p>


<h2>21. Changes to Terms</h2>

<p>
These Terms & Conditions may be updated from
time to time. Continued use of the platform
after changes are posted may constitute
acceptance of the updated terms where
permitted by law.
</p>


<h2>22. Contact</h2>

<p>
For questions regarding these Terms,
please use the official TaskEarn contact
method.
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


/* =====================================================
   ABOUT
===================================================== */

app.get("/about",(req,res)=>{

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
padding:25px 20px;
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
box-shadow:
0 5px 22px rgba(0,0,0,.06);
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
TaskEarn is an online task platform designed
to provide a simple interface for discovering
eligible tasks, submitting completed work and
managing approved task-related rewards.
</p>


<h2>Our Goal</h2>

<p>
Our goal is to provide users with a simple,
clear and transparent task discovery and
submission experience.
</p>


<h2>How It Works</h2>

<p>
Users can create an account, browse available
tasks, complete eligible tasks and submit
their work for review.
</p>


<h2>Task Review</h2>

<p>
Task submissions may be reviewed before
rewards are credited to a user's account.
</p>


<h2>Task Availability</h2>

<p>
Task availability, requirements and rewards
can change depending on the tasks available
on the platform.
</p>


<h2>Important Information</h2>

<p>
Earnings are not guaranteed and depend on
available tasks, eligibility, successful
completion and applicable conditions.
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


/* =====================================================
   CONTACT
===================================================== */

app.get("/contact",(req,res)=>{

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
padding:25px 20px;
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
box-shadow:
0 5px 22px rgba(0,0,0,.06);
}

a{
color:#ff6b35;
font-weight:bold;
text-decoration:none;
}

.email{
background:#fff7ed;
padding:15px;
border-radius:12px;
font-weight:bold;
word-break:break-word;
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
the TaskEarn support team.
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

<p class="email">
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


/* =====================================================
   404 API HANDLER
===================================================== */

app.use("/api",(req,res)=>{

  res.status(404).json({

    error:"API endpoint not found"

  });

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
      `TaskEarn running on port ${PORT}`
    );

  }
);
