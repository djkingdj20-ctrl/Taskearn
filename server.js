const express = require('express');
const session = require('express-session');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();

/* =========================
   BASIC CONFIGURATION
========================= */

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

/* =========================
   SESSION
========================= */

app.use(
  session({
    secret:
      process.env.SESSION_SECRET ||
      'change-this-secret-before-production',

    resave: false,

    saveUninitialized: false,

    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: false
    }
  })
);

/* =========================
   DATABASE
========================= */

const dbPath = path.join(__dirname, 'taskearn.db');

const db = new Database(dbPath);

db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    balance REAL NOT NULL DEFAULT 0,
    completed INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    type TEXT NOT NULL,
    reward REAL NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    user_name TEXT NOT NULL,
    task_id INTEGER NOT NULL,
    task_title TEXT NOT NULL,
    reward REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reviewed_at TEXT
  );

  CREATE TABLE IF NOT EXISTS withdrawals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    amount REAL NOT NULL,
    method TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

/* =========================
   DEFAULT DATA
========================= */

const userCount = db
  .prepare('SELECT COUNT(*) AS count FROM users')
  .get().count;

if (userCount === 0) {

  const insertUser = db.prepare(`
    INSERT INTO users
    (name, email, password, role, balance, completed)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  insertUser.run(
    'Demo User',
    'user@taskearn.demo',
    '123456',
    'user',
    0,
    0
  );

  insertUser.run(
    'Admin',
    'admin@taskearn.demo',
    'admin123',
    'admin',
    0,
    0
  );
}


const taskCount = db
  .prepare('SELECT COUNT(*) AS count FROM tasks')
  .get().count;

if (taskCount === 0) {

  const insertTask = db.prepare(`
    INSERT INTO tasks
    (title, description, type, reward)
    VALUES (?, ?, ?, ?)
  `);

  insertTask.run(
    'Watch a sponsored video',
    'Watch the complete licensed sponsor video and submit confirmation.',
    'Watch',
    8
  );

  insertTask.run(
    'Visit a sponsor page',
    'Open the sponsor page and confirm one simple detail.',
    'Visit',
    5
  );

  insertTask.run(
    'Daily check-in',
    'Complete the daily check-in and submit it for review.',
    'Check-in',
    2
  );

  insertTask.run(
    'Test a mobile website',
    'Test two buttons and submit your result.',
    'Testing',
    20
  );

  insertTask.run(
    'Read a short description',
    'Read a short product description and submit the correct category.',
    'Content',
    6
  );
}

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
   GET CURRENT USER
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

  const email =
    String(req.body.email || '')
      .trim()
      .toLowerCase();

  const password =
    String(req.body.password || '');

  const user = db
    .prepare(`
      SELECT
        id,
        name,
        email,
        password,
        role
      FROM users
      WHERE email = ?
    `)
    .get(email);

  if (
    !user ||
    user.password !== password
  ) {

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

  const name =
    String(req.body.name || '').trim();

  const email =
    String(req.body.email || '')
      .trim()
      .toLowerCase();

  const password =
    String(req.body.password || '');

  if (
    !name ||
    !email ||
    !password
  ) {

    return res.status(400).json({
      error: 'All fields required'
    });
  }

  if (password.length < 6) {

    return res.status(400).json({
      error: 'Password must be at least 6 characters'
    });
  }

  const existing = db
    .prepare(
      'SELECT id FROM users WHERE email = ?'
    )
    .get(email);

  if (existing) {

    return res.status(400).json({
      error: 'Email already exists'
    });
  }

  try {

    const result = db
      .prepare(`
        INSERT INTO users
        (name, email, password, role, balance, completed)
        VALUES (?, ?, ?, 'user', 0, 0)
      `)
      .run(
        name,
        email,
        password
      );

    req.session.user = {

      id: result.lastInsertRowid,

      name,

      email,

      role: 'user'

    };

    res.json(req.session.user);

  } catch (error) {

    res.status(500).json({
      error: 'Could not create account'
    });

  }

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
   GET ACTIVE TASKS
========================= */

app.get('/api/tasks', auth, (req, res) => {

  const tasks = db
    .prepare(`
      SELECT
        id,
        title,
        description,
        type,
        reward
      FROM tasks
      WHERE active = 1
      ORDER BY id DESC
    `)
    .all();

  res.json(tasks);

});

/* =========================
   GET ONE TASK
========================= */

app.get('/api/tasks/:id', auth, (req, res) => {

  const id =
    Number(req.params.id);

  const task = db
    .prepare(`
      SELECT
        id,
        title,
        description,
        type,
        reward
      FROM tasks
      WHERE id = ?
    `)
    .get(id);

  if (!task) {

    return res.status(404).json({
      error: 'Task not found'
    });
  }

  res.json(task);

});

/* =========================
   SUBMIT TASK
========================= */

app.post('/api/tasks/:id/submit', auth, (req, res) => {

  const taskId =
    Number(req.params.id);

  const userId =
    req.session.user.id;

  const task = db
    .prepare(`
      SELECT
        id,
        title,
        description,
        type,
        reward
      FROM tasks
      WHERE id = ?
      AND active = 1
    `)
    .get(taskId);

  if (!task) {

    return res.status(404).json({
      error: 'Task not found'
    });
  }

  const user = db
    .prepare(`
      SELECT
        id,
        name
      FROM users
      WHERE id = ?
    `)
    .get(userId);

  if (!user) {

    return res.status(401).json({
      error: 'User not found'
    });
  }

  const existing = db
    .prepare(`
      SELECT id
      FROM submissions
      WHERE user_id = ?
      AND task_id = ?
      AND status IN ('pending', 'approved')
      LIMIT 1
    `)
    .get(
      userId,
      taskId
    );

  if (existing) {

    return res.status(400).json({
      error:
        'You already have a pending or approved submission for this task'
    });
  }

  const result = db
    .prepare(`
      INSERT INTO submissions
      (
        user_id,
        user_name,
        task_id,
        task_title,
        reward,
        status
      )
      VALUES (?, ?, ?, ?, ?, 'pending')
    `)
    .run(
      user.id,
      user.name,
      task.id,
      task.title,
      task.reward
    );

  const submission = db
    .prepare(`
      SELECT *
      FROM submissions
      WHERE id = ?
    `)
    .get(
      result.lastInsertRowid
    );

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

app.get(
  '/api/my-submissions',
  auth,
  (req, res) => {

    const submissions = db
      .prepare(`
        SELECT
          id,
          task_id AS taskId,
          task_title AS taskTitle,
          reward,
          status,
          submitted_at AS submittedAt,
          reviewed_at AS reviewedAt
        FROM submissions
        WHERE user_id = ?
        ORDER BY id DESC
      `)
      .all(
        req.session.user.id
      );

    res.json(submissions);

  }
);

/* =========================
   WALLET
========================= */

app.get(
  '/api/wallet',
  auth,
  (req, res) => {

    const user = db
      .prepare(`
        SELECT
          balance,
          completed
        FROM users
        WHERE id = ?
      `)
      .get(
        req.session.user.id
      );

    if (!user) {

      return res.status(404).json({
        error: 'User not found'
      });
    }

    const withdrawals = db
      .prepare(`
        SELECT
          id,
          amount,
          method,
          status,
          created_at AS createdAt
        FROM withdrawals
        WHERE user_id = ?
        ORDER BY id DESC
      `)
      .all(
        req.session.user.id
      );

    res.json({

      balance: user.balance,

      completed: user.completed,

      withdrawals

    });

  }
);

/* =========================
   WITHDRAWAL REQUEST
========================= */

app.post(
  '/api/withdraw',
  auth,
  (req, res) => {

    const amount =
      Number(req.body.amount);

    const method =
      String(
        req.body.method || 'UPI'
      ).trim();

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

    const user = db
      .prepare(`
        SELECT
          id,
          name,
          balance
        FROM users
        WHERE id = ?
      `)
      .get(
        req.session.user.id
      );

    if (!user) {

      return res.status(404).json({
        error: 'User not found'
      });
    }

    if (amount > user.balance) {

      return res.status(400).json({
        error: 'Insufficient balance'
      });
    }

    const transaction =
      db.transaction(() => {

        db.prepare(`
          UPDATE users
          SET balance = balance - ?
          WHERE id = ?
        `).run(
          amount,
          user.id
        );

        db.prepare(`
          INSERT INTO withdrawals
          (
            user_id,
            name,
            amount,
            method,
            status
          )
          VALUES (?, ?, ?, ?, 'pending')
        `).run(
          user.id,
          user.name,
          amount,
          method
        );

      });

    transaction();

    res.json({
      ok: true
    });

  }
);

/* =========================
   ADMIN STATS
========================= */

app.get(
  '/api/admin/stats',
  admin,
  (req, res) => {

    const users =
      db.prepare(
        'SELECT COUNT(*) AS count FROM users'
      ).get().count;

    const tasks =
      db.prepare(
        'SELECT COUNT(*) AS count FROM tasks'
      ).get().count;

    const pendingSubmissions =
      db.prepare(`
        SELECT COUNT(*) AS count
        FROM submissions
        WHERE status = 'pending'
      `).get().count;

    const pendingWithdrawals =
      db.prepare(`
        SELECT COUNT(*) AS count
        FROM withdrawals
        WHERE status = 'pending'
      `).get().count;

    res.json({

      users,

      tasks,

      submissions:
        pendingSubmissions,

      pending:
        pendingWithdrawals

    });

  }
);

/* =========================
   ADMIN GET ALL TASKS
========================= */

app.get(
  '/api/admin/tasks',
  admin,
  (req, res) => {

    const tasks = db
      .prepare(`
        SELECT
          id,
          title,
          description,
          type,
          reward,
          active,
          created_at AS createdAt
        FROM tasks
        ORDER BY id DESC
      `)
      .all();

    res.json(tasks);

  }
);

/* =========================
   ADMIN ADD TASK
========================= */

app.post(
  '/api/admin/tasks',
  admin,
  (req, res) => {

    const title =
      String(req.body.title || '')
        .trim();

    const description =
      String(req.body.description || '')
        .trim();

    const type =
      String(req.body.type || 'General')
        .trim();

    const reward =
      Number(req.body.reward);

    if (
      !title ||
      !description ||
      !type
    ) {

      return res.status(400).json({
        error:
          'Title, description and type are required'
      });
    }

    if (
      !Number.isFinite(reward) ||
      reward <= 0
    ) {

      return res.status(400).json({
        error:
          'Reward must be greater than 0'
      });
    }

    const result = db
      .prepare(`
        INSERT INTO tasks
        (
          title,
          description,
          type,
          reward,
          active
        )
        VALUES (?, ?, ?, ?, 1)
      `)
      .run(
        title,
        description,
        type,
        reward
      );

    const task = db
      .prepare(`
        SELECT
          id,
          title,
          description,
          type,
          reward,
          active
        FROM tasks
        WHERE id = ?
      `)
      .get(
        result.lastInsertRowid
      );

    res.json({

      ok: true,

      task

    });

  }
);

/* =========================
   ADMIN EDIT TASK
========================= */

app.put(
  '/api/admin/tasks/:id',
  admin,
  (req, res) => {

    const id =
      Number(req.params.id);

    const title =
      String(req.body.title || '')
        .trim();

    const description =
      String(req.body.description || '')
        .trim();

    const type =
      String(req.body.type || 'General')
        .trim();

    const reward =
      Number(req.body.reward);

    const active =
      req.body.active === false
        ? 0
        : 1;

    if (
      !title ||
      !description ||
      !type
    ) {

      return res.status(400).json({
        error:
          'Title, description and type are required'
      });
    }

    if (
      !Number.isFinite(reward) ||
      reward <= 0
    ) {

      return res.status(400).json({
        error:
          'Reward must be greater than 0'
      });
    }

    const existing =
      db.prepare(`
        SELECT id
        FROM tasks
        WHERE id = ?
      `).get(id);

    if (!existing) {

      return res.status(404).json({
        error: 'Task not found'
      });
    }

    db.prepare(`
      UPDATE tasks
      SET
        title = ?,
        description = ?,
        type = ?,
        reward = ?,
        active = ?
      WHERE id = ?
    `).run(
      title,
      description,
      type,
      reward,
      active,
      id
    );

    const task =
      db.prepare(`
        SELECT
          id,
          title,
          description,
          type,
          reward,
          active
        FROM tasks
        WHERE id = ?
      `).get(id);

    res.json({

      ok: true,

      task

    });

  }
);

/* =========================
   ADMIN DELETE TASK
========================= */

app.delete(
  '/api/admin/tasks/:id',
  admin,
  (req, res) => {

    const id =
      Number(req.params.id);

    const task =
      db.prepare(`
        SELECT id
        FROM tasks
        WHERE id = ?
      `).get(id);

    if (!task) {

      return res.status(404).json({
        error: 'Task not found'
      });
    }

    db.prepare(`
      UPDATE tasks
      SET active = 0
      WHERE id = ?
    `).run(id);

    res.json({

      ok: true,

      message:
        'Task removed from active tasks'

    });

  }
);

/* =========================
   ADMIN TASK SUBMISSIONS
========================= */

app.get(
  '/api/admin/submissions',
  admin,
  (req, res) => {

    const submissions =
      db.prepare(`
        SELECT
          id,
          user_id AS userId,
          user_name AS userName,
          task_id AS taskId,
          task_title AS taskTitle,
          reward,
          status,
          submitted_at AS submittedAt,
          reviewed_at AS reviewedAt
        FROM submissions
        ORDER BY id DESC
      `).all();

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

    const id =
      Number(req.params.id);

    const status =
      req.body.status;

    if (
      status !== 'approved' &&
      status !== 'rejected'
    ) {

      return res.status(400).json({
        error:
          'Status must be approved or rejected'
      });
    }

    const submission =
      db.prepare(`
        SELECT *
        FROM submissions
        WHERE id = ?
      `).get(id);

    if (!submission) {

      return res.status(404).json({
        error:
          'Submission not found'
      });
    }

    if (
      submission.status !== 'pending'
    ) {

      return res.status(400).json({
        error:
          'Submission already reviewed'
      });
    }

    const transaction =
      db.transaction(() => {

        db.prepare(`
          UPDATE submissions
          SET
            status = ?,
            reviewed_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `).run(
          status,
          id
        );

        if (status === 'approved') {

          db.prepare(`
            UPDATE users
            SET
              balance = balance + ?,
              completed = completed + 1
            WHERE id = ?
          `).run(
            submission.reward,
            submission.user_id
          );

        }

      });

    transaction();

    res.json({
      ok: true
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

    const withdrawals =
      db.prepare(`
        SELECT
          id,
          user_id AS userId,
          name,
          amount,
          method,
          status,
          created_at AS createdAt
        FROM withdrawals
        ORDER BY id DESC
      `).all();

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

    const id =
      Number(req.params.id);

    const status =
      req.body.status;

    if (
      status !== 'approved' &&
      status !== 'rejected'
    ) {

      return res.status(400).json({
        error:
          'Status must be approved or rejected'
      });
    }

    const withdrawal =
      db.prepare(`
        SELECT *
        FROM withdrawals
        WHERE id = ?
      `).get(id);

    if (!withdrawal) {

      return res.status(404).json({
        error:
          'Withdrawal not found'
      });
    }

    if (
      withdrawal.status !== 'pending'
    ) {

      return res.status(400).json({
        error:
          'Withdrawal already reviewed'
      });
    }

    const transaction =
      db.transaction(() => {

        db.prepare(`
          UPDATE withdrawals
          SET status = ?
          WHERE id = ?
        `).run(
          status,
          id
        );

        /*
          If a withdrawal is rejected,
          return the money to the user's balance.
        */

        if (status === 'rejected') {

          db.prepare(`
            UPDATE users
            SET balance = balance + ?
            WHERE id = ?
          `).run(
            withdrawal.amount,
            withdrawal.user_id
          );

        }

      });

    transaction();

    res.json({
      ok: true
    });

  }
);

/* =========================
   HEALTH CHECK
========================= */

app.get('/api/health', (req, res) => {

  res.json({
    ok: true,
    service: 'TaskEarn'
  });

});

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
