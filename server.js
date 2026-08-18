const express = require('express');
const session = require('express-session');

const app = express();

app.use(express.json());
app.use(express.static('public'));

app.use(session({
  secret: process.env.SESSION_SECRET || 'change-this-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax'
  }
}));

/* =========================
   USERS
========================= */

const users = [
  {
    id: 1,
    name: 'Demo User',
    email: 'user@taskearn.demo',
    password: '123456',
    role: 'user',
    balance: 0,
    completed: 0
  },
  {
    id: 2,
    name: 'Admin',
    email: 'admin@taskearn.demo',
    password: 'admin123',
    role: 'admin',
    balance: 0,
    completed: 0
  }
];

/* =========================
   TASKS
========================= */

const tasks = [
  {
    id: 1,
    title: 'Watch a sponsored video',
    description: 'Watch the complete licensed sponsor video and submit confirmation.',
    type: 'Watch',
    reward: 8
  },
  {
    id: 2,
    title: 'Visit a sponsor page',
    description: 'Open the sponsor page and confirm one simple detail.',
    type: 'Visit',
    reward: 5
  },
  {
    id: 3,
    title: 'Daily check-in',
    description: 'Open the task and submit your daily check-in.',
    type: 'Check-in',
    reward: 2
  },
  {
    id: 4,
    title: 'Test a mobile website',
    description: 'Test two buttons and submit your result.',
    type: 'Testing',
    reward: 20
  },
  {
    id: 5,
    title: 'Read a short description',
    description: 'Read the description and submit the correct category.',
    type: 'Content',
    reward: 6
  }
];

/* =========================
   DATA STORAGE
========================= */

const submissions = [];
const withdrawals = [];

/* =========================
   AUTH MIDDLEWARE
========================= */

function auth(req, res, next) {

  if (!req.session.user) {
    return res.status(401).json({
      error: 'Login required'
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
    req.session.user.role !== 'admin'
  ) {
    return res.status(403).json({
      error: 'Admin only'
    });
  }

  next();
}

/* =========================
   CURRENT USER
========================= */

app.get('/api/me', (req, res) => {

  res.json(
    req.session.user || null
  );

});

/* =========================
   LOGIN
========================= */

app.post('/api/login', (req, res) => {

  const email = req.body.email;
  const password = req.body.password;

  const user = users.find(
    u =>
      u.email === email &&
      u.password === password
  );

  if (!user) {

    return res.status(401).json({
      error: 'Invalid login'
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

app.post('/api/register', (req, res) => {

  const name = req.body.name;
  const email = req.body.email;
  const password = req.body.password;

  if (!name || !email || !password) {

    return res.status(400).json({
      error: 'All fields required'
    });

  }

  if (
    users.some(
      u => u.email === email
    )
  ) {

    return res.status(400).json({
      error: 'Email already exists'
    });

  }

  const user = {

    id: users.length + 1,

    name,

    email,

    password,

    role: 'user',

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

app.post('/api/logout', (req, res) => {

  req.session.destroy(() => {

    res.json({
      ok: true
    });

  });

});

/* =========================
   TASK LIST
========================= */

app.get('/api/tasks', auth, (req, res) => {

  res.json(tasks);

});

/* =========================
   START / SUBMIT TASK
========================= */

app.post('/api/tasks/:id/submit', auth, (req, res) => {

  const taskId = Number(req.params.id);

  const user = users.find(
    u =>
      u.id === req.session.user.id
  );

  const task = tasks.find(
    t =>
      t.id === taskId
  );

  if (!task) {

    return res.status(404).json({
      error: 'Task not found'
    });

  }

  const alreadyPending =
    submissions.find(
      s =>
        s.userId === user.id &&
        s.taskId === task.id &&
        s.status === 'pending'
    );

  if (alreadyPending) {

    return res.status(400).json({
      error: 'This task is already pending review'
    });

  }

  const alreadyApproved =
    submissions.find(
      s =>
        s.userId === user.id &&
        s.taskId === task.id &&
        s.status === 'approved'
    );

  if (alreadyApproved) {

    return res.status(400).json({
      error: 'You have already completed this task'
    });

  }

  const submission = {

    id: submissions.length + 1,

    userId: user.id,

    userName: user.name,

    taskId: task.id,

    taskTitle: task.title,

    reward: task.reward,

    status: 'pending',

    submittedAt: new Date().toISOString()

  };

  submissions.push(submission);

  res.json({

    ok: true,

    message:
      'Task submitted for review',

    submission

  });

});

/* =========================
   USER SUBMISSIONS
========================= */

app.get('/api/my-submissions', auth, (req, res) => {

  const userSubmissions =
    submissions.filter(
      s =>
        s.userId ===
        req.session.user.id
    );

  res.json(userSubmissions);

});

/* =========================
   WALLET
========================= */

app.get('/api/wallet', auth, (req, res) => {

  const user = users.find(
    u =>
      u.id === req.session.user.id
  );

  res.json({

    balance: user.balance,

    completed: user.completed,

    withdrawals:
      withdrawals.filter(
        w =>
          w.userId === user.id
      )

  });

});

/* =========================
   WITHDRAWAL
========================= */

app.post('/api/withdraw', auth, (req, res) => {

  const user = users.find(
    u =>
      u.id === req.session.user.id
  );

  const amount =
    Number(req.body.amount);

  const method =
    req.body.method || 'UPI';

  if (
    !Number.isFinite(amount) ||
    amount <= 0
  ) {

    return res.status(400).json({
      error: 'Enter a valid amount'
    });

  }

  if (amount < 100) {

    return res.status(400).json({
      error: 'Minimum withdrawal is ₹100'
    });

  }

  if (amount > user.balance) {

    return res.status(400).json({
      error: 'Insufficient balance'
    });

  }

  user.balance -= amount;

  withdrawals.push({

    id: withdrawals.length + 1,

    userId: user.id,

    name: user.name,

    amount,

    method,

    status: 'pending'

  });

  res.json({
    ok: true
  });

});

/* =========================
   ADMIN STATS
========================= */

app.get('/api/admin/stats', admin, (req, res) => {

  res.json({

    users: users.length,

    tasks: tasks.length,

    pending:
      withdrawals.filter(
        w =>
          w.status === 'pending'
      ).length,

    submissions:
      submissions.filter(
        s =>
          s.status === 'pending'
      ).length

  });

});

/* =========================
   ADMIN TASK SUBMISSIONS
========================= */

app.get(
  '/api/admin/submissions',
  admin,
  (req, res) => {

    res.json(submissions);

  }
);

/* =========================
   ADMIN APPROVE / REJECT TASK
========================= */

app.post(
  '/api/admin/submissions/:id',
  admin,
  (req, res) => {

    const submission =
      submissions.find(
        s =>
          s.id ===
          Number(req.params.id)
      );

    if (!submission) {

      return res.status(404).json({
        error: 'Submission not found'
      });

    }

    if (
      submission.status !==
      'pending'
    ) {

      return res.status(400).json({
        error: 'Submission already reviewed'
      });

    }

    const newStatus =
      req.body.status;

    if (
      newStatus !== 'approved' &&
      newStatus !== 'rejected'
    ) {

      return res.status(400).json({
        error: 'Invalid status'
      });

    }

    submission.status =
      newStatus;

    if (
      newStatus === 'approved'
    ) {

      const user =
        users.find(
          u =>
            u.id ===
            submission.userId
        );

      if (user) {

        user.balance +=
          submission.reward;

        user.completed++;

      }

    }

    res.json({
      ok: true,
      submission
    });

  }
);

/* =========================
   ADMIN WITHDRAWALS
========================= */

app.get(
  '/api/admin/withdrawals',
  admin,
  (req, res) => {

    res.json(withdrawals);

  }
);

/* =========================
   ADMIN WITHDRAWAL UPDATE
========================= */

app.post(
  '/api/admin/withdrawals/:id',
  admin,
  (req, res) => {

    const withdrawal =
      withdrawals.find(
        w =>
          w.id ===
          Number(req.params.id)
      );

    if (!withdrawal) {

      return res.status(404).json({
        error: 'Withdrawal not found'
      });

    }

    const status =
      req.body.status;

    if (
      status !== 'approved' &&
      status !== 'rejected'
    ) {

      return res.status(400).json({
        error: 'Invalid status'
      });

    }

    withdrawal.status =
      status;

    res.json({
      ok: true
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
  '0.0.0.0',
  () => {

    console.log(
      `TaskEarn running on port ${PORT}`
    );

  }
);
