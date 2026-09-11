const express = require("express");
const http = require("http");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const { WebSocketServer } = require("ws");

const ROOT = path.join(__dirname, "..");
const PUBLIC = path.join(ROOT, "public");
const DATA = path.join(ROOT, "data");
fs.mkdirSync(DATA, { recursive: true });

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || "dev-only-change-me";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "Admin@12345";
const ADMIN_RECOVERY_KEY = process.env.ADMIN_RECOVERY_KEY || "";

const db = new Database(path.join(DATA, "app.db"));
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','agent')),
  capacity INTEGER NOT NULL DEFAULT 5,
  active INTEGER NOT NULL DEFAULT 1,
  online INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS conversations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_name TEXT NOT NULL,
  customer_token TEXT NOT NULL,
  agent_id INTEGER,
  status TEXT NOT NULL DEFAULT 'waiting' CHECK(status IN ('waiting','active','closed')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  closed_at TEXT,
  FOREIGN KEY(agent_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  conversation_id INTEGER NOT NULL,
  sender_type TEXT NOT NULL CHECK(sender_type IN ('customer','agent')),
  sender_id INTEGER,
  message TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(conversation_id) REFERENCES conversations(id),
  FOREIGN KEY(sender_id) REFERENCES users(id)
);
`);

// Professional support-center fields
const addCol = (table, col, type) => {
  try {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${col} ${type}`);
  } catch {}
};

addCol("users","support_status","TEXT NOT NULL DEFAULT 'offline'");
addCol("users","status_since","TEXT");
addCol("users","last_online_at","TEXT");
addCol("users","last_offline_at","TEXT");
addCol("users","last_break_at","TEXT");

addCol("conversations","assigned_at","TEXT");
addCol("conversations","first_assigned_at","TEXT");
addCol("conversations","last_activity_at","TEXT");
addCol("conversations","prechat_session_id","INTEGER");

db.exec(`
CREATE TABLE IF NOT EXISTS conversation_assignments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  conversation_id INTEGER NOT NULL,
  agent_id INTEGER NOT NULL,
  started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ended_at TEXT,
  FOREIGN KEY(conversation_id) REFERENCES conversations(id),
  FOREIGN KEY(agent_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS conversation_notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  conversation_id INTEGER NOT NULL,
  agent_id INTEGER NOT NULL,
  note TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(conversation_id) REFERENCES conversations(id),
  FOREIGN KEY(agent_id) REFERENCES users(id)
);
`);

db.prepare(`
  UPDATE users
  SET support_status=CASE WHEN online=1 THEN 'online' ELSE 'offline' END
  WHERE support_status IS NULL OR support_status=''
`).run();

db.exec(`
CREATE TABLE IF NOT EXISTS prechat_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_token TEXT UNIQUE NOT NULL,
  customer_name TEXT NOT NULL DEFAULT 'Website visitor',
  status TEXT NOT NULL DEFAULT 'active'
    CHECK(status IN ('active','handed_off','closed')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_activity_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  handed_off_at TEXT
);

CREATE TABLE IF NOT EXISTS prechat_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id INTEGER NOT NULL,
  sender_type TEXT NOT NULL
    CHECK(sender_type IN ('customer','bot')),
  message TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(session_id) REFERENCES prechat_sessions(id)
);
`);

const adminExists = db
  .prepare("SELECT id FROM users WHERE username='admin' AND role='admin'")
  .get();

if (!adminExists) {
  db.prepare(`
    INSERT INTO users
      (name, username, password_hash, role, capacity)
    VALUES (?, ?, ?, 'admin', 999)
  `).run(
    "Administrator",
    "admin",
    bcrypt.hashSync(ADMIN_PASSWORD, 12)
  );
}

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept, Authorization"
  );
  res.header(
    "Access-Control-Allow-Methods",
    "GET,POST,PUT,PATCH,DELETE,OPTIONS"
  );

  if (req.method === "OPTIONS") return res.sendStatus(204);

  next();
});

app.use(express.json({ limit: "20kb" }));
app.use(express.static(PUBLIC));

app.get("/health", (req, res) =>
  res.json({
    ok: true,
    service: "abhishek-events-live-chat"
  })
);

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "12h" });
}

function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ")
      ? header.slice(7)
      : null;

    if (!token) {
      return res.status(401).json({
        error: "Login required"
      });
    }

    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({
      error: "Invalid or expired login"
    });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).json({
        error: "Access denied"
      });
    }

    next();
  };
}

function activeCount(agentId) {
  return db.prepare(`
    SELECT COUNT(*) AS count
    FROM conversations
    WHERE agent_id=? AND status='active'
  `).get(agentId).count;
}

function chooseAgent() {
  const agents = db.prepare(`
    SELECT id, name, capacity
    FROM users
    WHERE role='agent'
      AND active=1
      AND online=1
      AND support_status='online'
    ORDER BY id ASC
  `).all();

  const candidates = agents
    .map(a => ({
      ...a,
      current: activeCount(a.id)
    }))
    .filter(a => a.current < a.capacity)
    .sort(
      (a, b) =>
        (a.current - b.current) ||
        (a.id - b.id)
    );

  return candidates[0] || null;
}

function assignWaiting() {
  const waiting = db.prepare(`
    SELECT *
    FROM conversations
    WHERE status='waiting'
    ORDER BY id ASC
  `).all();

  for (const c of waiting) {
    const agent = chooseAgent();

    if (!agent) break;

    const now = new Date().toISOString();

    db.prepare(`
      UPDATE conversations
      SET
        agent_id=?,
        status='active',
        assigned_at=?,
        first_assigned_at=COALESCE(first_assigned_at,?),
        last_activity_at=?
      WHERE id=?
    `).run(
      agent.id,
      now,
      now,
      now,
      c.id
    );

    db.prepare(`
      INSERT INTO conversation_assignments
        (conversation_id,agent_id,started_at)
      VALUES (?,?,?)
    `).run(
      c.id,
      agent.id,
      now
    );

    broadcastConversation(c.id);
  }
}

const rooms = new Map();

function addSocket(conversationId, ws) {
  const key = String(conversationId);

  if (!rooms.has(key)) {
    rooms.set(key, new Set());
  }

  rooms.get(key).add(ws);
  ws.roomKey = key;
}

function removeSocket(ws) {
  if (!ws.roomKey) return;

  const room = rooms.get(ws.roomKey);

  if (!room) return;

  room.delete(ws);

  if (!room.size) {
    rooms.delete(ws.roomKey);
  }
}

function sendJson(ws, data) {
  if (ws.readyState === 1) {
    ws.send(JSON.stringify(data));
  }
}

function broadcast(conversationId, data) {
  const room = rooms.get(String(conversationId));

  if (!room) return;

  for (const ws of room) {
    sendJson(ws, data);
  }
}

function getConversation(id) {
  return db.prepare(`
    SELECT
      c.*,
      u.name AS agent_name,
      u.username AS agent_username,
      CASE
        WHEN c.status='active'
        THEN CAST(
          (julianday('now') -
           julianday(COALESCE(
             c.first_assigned_at,
             c.created_at
           ))) * 86400
          AS INTEGER
        )
        ELSE CAST(
          (julianday(COALESCE(
             c.closed_at,
             'now'
           )) -
           julianday(COALESCE(
             c.first_assigned_at,
             c.created_at
           ))) * 86400
          AS INTEGER
        )
      END AS chat_seconds
    FROM conversations c
    LEFT JOIN users u
      ON u.id=c.agent_id
    WHERE c.id=?
  `).get(id);
}

function broadcastConversation(id) {
  const c = getConversation(id);

  if (c) {
    broadcast(id, {
      type: "conversation",
      conversation: c
    });
  }
}// =========================
// ADMIN AUTH
// =========================

app.post("/api/admin/login", (req, res) => {
  const { username, password } = req.body || {};

  const user = db.prepare(`
    SELECT *
    FROM users
    WHERE username=? AND role='admin' AND active=1
  `).get(username);

  if (!user || !bcrypt.compareSync(password || "", user.password_hash)) {
    return res.status(401).json({
      error: "Invalid admin username or password"
    });
  }

  const token = signToken({
    id: user.id,
    username: user.username,
    name: user.name,
    role: user.role
  });

  res.json({
    ok: true,
    token,
    user: {
      id: user.id,
      name: user.name,
      username: user.username,
      role: user.role
    }
  });
});

// Admin password recovery
app.post("/api/admin/recover", (req, res) => {
  const {
    recoveryKey,
    newPassword
  } = req.body || {};

  if (!ADMIN_RECOVERY_KEY) {
    return res.status(503).json({
      error: "Admin recovery is not configured"
    });
  }

  if (recoveryKey !== ADMIN_RECOVERY_KEY) {
    return res.status(401).json({
      error: "Invalid recovery key"
    });
  }

  if (!newPassword || String(newPassword).length < 8) {
    return res.status(400).json({
      error: "New password must be at least 8 characters"
    });
  }

  const passwordHash = bcrypt.hashSync(
    String(newPassword),
    12
  );

  const result = db.prepare(`
    UPDATE users
    SET password_hash=?, active=1
    WHERE username='admin' AND role='admin'
  `).run(passwordHash);

  if (!result.changes) {
    return res.status(404).json({
      error: "Admin account not found"
    });
  }

  res.json({
    ok: true,
    message: "Admin password updated successfully"
  });
});

// =========================
// AGENT AUTH
// =========================

app.post("/api/agent/login", (req, res) => {
  const {
    username,
    password
  } = req.body || {};

  const user = db.prepare(`
    SELECT *
    FROM users
    WHERE username=? AND role='agent' AND active=1
  `).get(username);

  if (!user || !bcrypt.compareSync(password || "", user.password_hash)) {
    return res.status(401).json({
      error: "Invalid agent username or password"
    });
  }

  const now = new Date().toISOString();

  db.prepare(`
    UPDATE users
    SET
      online=1,
      support_status='online',
      status_since=?,
      last_online_at=?
    WHERE id=?
  `).run(now, now, user.id);

  const token = signToken({
    id: user.id,
    username: user.username,
    name: user.name,
    role: user.role
  });

  assignWaiting();

  res.json({
    ok: true,
    token,
    user: {
      id: user.id,
      name: user.name,
      username: user.username,
      role: user.role,
      capacity: user.capacity
    }
  });
});

app.post("/api/logout", auth, (req, res) => {
  if (req.user.role === "agent") {
    const now = new Date().toISOString();

    db.prepare(`
      UPDATE users
      SET
        online=0,
        support_status='offline',
        status_since=?,
        last_offline_at=?
      WHERE id=?
    `).run(now, now, req.user.id);
  }

  res.json({ ok: true });
});

// =========================
// AGENT STATUS
// =========================

app.post(
  "/api/agent/status",
  auth,
  requireRole("agent"),
  (req, res) => {
    const allowed = [
      "online",
      "break",
      "idle",
      "offline"
    ];

    const status = String(
      req.body?.status || ""
    ).toLowerCase();

    if (!allowed.includes(status)) {
      return res.status(400).json({
        error: "Invalid status"
      });
    }

    const now = new Date().toISOString();

    let online = 0;

    if (status === "online") {
      online = 1;
    }

    db.prepare(`
      UPDATE users
      SET
        online=?,
        support_status=?,
        status_since=?,
        last_online_at=
          CASE
            WHEN ?='online' THEN ?
            ELSE last_online_at
          END,
        last_offline_at=
          CASE
            WHEN ?='offline' THEN ?
            ELSE last_offline_at
          END,
        last_break_at=
          CASE
            WHEN ?='break' THEN ?
            ELSE last_break_at
          END
      WHERE id=? AND role='agent'
    `).run(
      online,
      status,
      now,
      status,
      now,
      status,
      now,
      status,
      now,
      req.user.id
    );

    if (status === "online") {
      assignWaiting();
    }

    res.json({
      ok: true,
      status
    });
  }
);

// =========================
// AGENT PASSWORD
// =========================

app.post(
  "/api/agent/password",
  auth,
  requireRole("agent"),
  (req, res) => {
    const {
      currentPassword,
      newPassword
    } = req.body || {};

    const user = db.prepare(`
      SELECT *
      FROM users
      WHERE id=? AND role='agent'
    `).get(req.user.id);

    if (
      !user ||
      !bcrypt.compareSync(
        currentPassword || "",
        user.password_hash
      )
    ) {
      return res.status(401).json({
        error: "Current password is incorrect"
      });
    }

    if (
      !newPassword ||
      String(newPassword).length < 8
    ) {
      return res.status(400).json({
        error: "New password must be at least 8 characters"
      });
    }

    db.prepare(`
      UPDATE users
      SET password_hash=?
      WHERE id=?
    `).run(
      bcrypt.hashSync(String(newPassword), 12),
      req.user.id
    );

    res.json({
      ok: true,
      message: "Password updated"
    });
  }
);

// =========================
// ADMIN AGENT MANAGEMENT
// =========================

app.get(
  "/api/admin/agents",
  auth,
  requireRole("admin"),
  (req, res) => {
    const agents = db.prepare(`
      SELECT
        id,
        name,
        username,
        capacity,
        active,
        online,
        support_status,
        status_since,
        last_online_at,
        last_offline_at,
        last_break_at,
        created_at
      FROM users
      WHERE role='agent'
      ORDER BY id ASC
    `).all();

    res.json(
      agents.map(agent => ({
        ...agent,
        current_customers: activeCount(agent.id)
      }))
    );
  }
);

app.get(
  "/api/admin/agents/live",
  auth,
  requireRole("admin"),
  (req, res) => {
    const agents = db.prepare(`
      SELECT
        id,
        name,
        username,
        capacity,
        active,
        online,
        support_status,
        status_since,
        last_online_at,
        last_offline_at,
        last_break_at
      FROM users
      WHERE role='agent'
      ORDER BY id ASC
    `).all();

    res.json(
      agents.map(agent => ({
        ...agent,
        current_customers: activeCount(agent.id)
      }))
    );
  }
);

app.post(
  "/api/admin/agents",
  auth,
  requireRole("admin"),
  (req, res) => {
    const {
      name,
      username,
      password,
      capacity
    } = req.body || {};

    if (
      !name ||
      !username ||
      !password
    ) {
      return res.status(400).json({
        error: "Name, username and password are required"
      });
    }

    if (String(password).length < 8) {
      return res.status(400).json({
        error: "Password must be at least 8 characters"
      });
    }

    try {
      const result = db.prepare(`
        INSERT INTO users
          (
            name,
            username,
            password_hash,
            role,
            capacity,
            active,
            online,
            support_status
          )
        VALUES (?,?,?,'agent',?,1,0,'offline')
      `).run(
        String(name).trim(),
        String(username).trim(),
        bcrypt.hashSync(String(password), 12),
        Math.max(1, Number(capacity || 5))
      );

      res.json({
        ok: true,
        id: result.lastInsertRowid
      });
    } catch (err) {
      res.status(400).json({
        error: "Username already exists"
      });
    }
  }
);

app.patch(
  "/api/admin/agents/:id",
  auth,
  requireRole("admin"),
  (req, res) => {
    const id = Number(req.params.id);

    const {
      name,
      capacity,
      active
    } = req.body || {};

    const agent = db.prepare(`
      SELECT *
      FROM users
      WHERE id=? AND role='agent'
    `).get(id);

    if (!agent) {
      return res.status(404).json({
        error: "Agent not found"
      });
    }

    db.prepare(`
      UPDATE users
      SET
        name=COALESCE(?,name),
        capacity=COALESCE(?,capacity),
        active=COALESCE(?,active)
      WHERE id=? AND role='agent'
    `).run(
      name ?? null,
      capacity != null
        ? Math.max(1, Number(capacity))
        : null,
      active != null
        ? (active ? 1 : 0)
        : null,
      id
    );

    assignWaiting();

    res.json({
      ok: true
    });
  }
);

app.post(
  "/api/admin/agents/:id/reset-password",
  auth,
  requireRole("admin"),
  (req, res) => {
    const id = Number(req.params.id);
    const password = String(
      req.body?.password || ""
    );

    if (password.length < 8) {
      return res.status(400).json({
        error: "Password must be at least 8 characters"
      });
    }

    const result = db.prepare(`
      UPDATE users
      SET password_hash=?
      WHERE id=? AND role='agent'
    `).run(
      bcrypt.hashSync(password, 12),
      id
    );

    if (!result.changes) {
      return res.status(404).json({
        error: "Agent not found"
      });
    }

    res.json({
      ok: true
    });
  }
);

// =========================
// CUSTOMER PRE-CHAT
// =========================

app.post("/api/customer/prechat/start", (req, res) => {
  const customerName =
    String(
      req.body?.customerName ||
      "Website visitor"
    ).trim() || "Website visitor";

  const token =
    crypto.randomBytes(24).toString("hex");

  const result = db.prepare(`
    INSERT INTO prechat_sessions
      (
        session_token,
        customer_name
      )
    VALUES (?,?)
  `).run(
    token,
    customerName
  );

  res.json({
    ok: true,
    id: result.lastInsertRowid,
    sessionToken: token
  });
});

app.post("/api/customer/prechat/message", (req, res) => {
  const {
    sessionToken,
    message
  } = req.body || {};

  if (!sessionToken || !message) {
    return res.status(400).json({
      error: "Session token and message are required"
    });
  }

  const session = db.prepare(`
    SELECT *
    FROM prechat_sessions
    WHERE session_token=?
      AND status='active'
  `).get(sessionToken);

  if (!session) {
    return res.status(404).json({
      error: "Pre-chat session not found"
    });
  }

  const text = String(message).trim();

  if (!text) {
    return res.status(400).json({
      error: "Message cannot be empty"
    });
  }

  db.prepare(`
    INSERT INTO prechat_messages
      (
        session_id,
        sender_type,
        message
      )
    VALUES (?, 'customer', ?)
  `).run(
    session.id,
    text
  );

  db.prepare(`
    UPDATE prechat_sessions
    SET last_activity_at=CURRENT_TIMESTAMP
    WHERE id=?
  `).run(session.id);

  res.json({
    ok: true
  });
});

app.post("/api/customer/prechat/finish", (req, res) => {
  const {
    sessionToken,
    message
  } = req.body || {};

  const session = db.prepare(`
    SELECT *
    FROM prechat_sessions
    WHERE session_token=?
  `).get(sessionToken);

  if (!session) {
    return res.status(404).json({
      error: "Pre-chat session not found"
    });
  }

  if (message) {
    db.prepare(`
      INSERT INTO prechat_messages
        (
          session_id,
          sender_type,
          message
        )
      VALUES (?, 'customer', ?)
    `).run(
      session.id,
      String(message).trim()
    );
  }

  db.prepare(`
    UPDATE prechat_sessions
    SET
      last_activity_at=CURRENT_TIMESTAMP
    WHERE id=?
  `).run(session.id);

  res.json({
    ok: true
  });
});// =========================
// ACCESS HELPER
// =========================

function conversationAllowed(user, conversationId) {
  const c = db.prepare(`
    SELECT *
    FROM conversations
    WHERE id=?
  `).get(conversationId);

  if (!c) return null;

  if (
    user.role === "agent" &&
    c.agent_id !== user.id
  ) {
    return null;
  }

  if (
    user.role === "customer" &&
    c.customer_token !== user.token
  ) {
    return null;
  }

  return c;
}

// =========================
// UNIVERSAL LOGIN
// =========================

app.post("/api/login", (req, res) => {
  const {
    username,
    password
  } = req.body || {};

  const user = db.prepare(`
    SELECT *
    FROM users
    WHERE username=? AND active=1
  `).get(username || "");

  if (
    !user ||
    !bcrypt.compareSync(
      password || "",
      user.password_hash
    )
  ) {
    return res.status(401).json({
      error: "Incorrect username or password"
    });
  }

  if (user.role === "agent") {
    const now = new Date().toISOString();

    db.prepare(`
      UPDATE users
      SET
        online=1,
        support_status='online',
        status_since=?,
        last_online_at=?
      WHERE id=?
    `).run(
      now,
      now,
      user.id
    );
  }

  const token = signToken({
    id: user.id,
    role: user.role,
    username: user.username,
    name: user.name
  });

  res.json({
    token,
    user: {
      id: user.id,
      name: user.name,
      username: user.username,
      role: user.role,
      capacity: user.capacity
    }
  });
});

// =========================
// ADMIN MANAGEMENT
// =========================

app.get(
  "/api/admin/admins",
  auth,
  requireRole("admin"),
  (req, res) => {
    const admins = db.prepare(`
      SELECT
        id,
        name,
        username,
        active,
        created_at
      FROM users
      WHERE role='admin'
      ORDER BY id ASC
    `).all();

    res.json(admins);
  }
);

app.post(
  "/api/admin/admins",
  auth,
  requireRole("admin"),
  (req, res) => {
    const {
      name,
      username,
      password
    } = req.body || {};

    if (!name || !username || !password) {
      return res.status(400).json({
        error: "Name, username and password are required"
      });
    }

    if (String(password).length < 8) {
      return res.status(400).json({
        error: "Password must be at least 8 characters"
      });
    }

    try {
      const result = db.prepare(`
        INSERT INTO users
          (
            name,
            username,
            password_hash,
            role,
            capacity,
            active
          )
        VALUES (?,?,?,'admin',999,1)
      `).run(
        String(name).trim(),
        String(username).trim(),
        bcrypt.hashSync(
          String(password),
          12
        )
      );

      res.json({
        ok: true,
        id: result.lastInsertRowid
      });
    } catch {
      res.status(400).json({
        error: "Username already exists"
      });
    }
  }
);

app.patch(
  "/api/admin/admins/:id",
  auth,
  requireRole("admin"),
  (req, res) => {
    const id = Number(req.params.id);

    const target = db.prepare(`
      SELECT *
      FROM users
      WHERE id=? AND role='admin'
    `).get(id);

    if (!target) {
      return res.status(404).json({
        error: "Admin not found"
      });
    }

    const {
      password,
      active
    } = req.body || {};

    if (password !== undefined) {
      if (String(password).length < 8) {
        return res.status(400).json({
          error: "Password must be at least 8 characters"
        });
      }

      db.prepare(`
        UPDATE users
        SET password_hash=?
        WHERE id=?
      `).run(
        bcrypt.hashSync(
          String(password),
          12
        ),
        id
      );
    }

    if (active !== undefined) {
      if (
        id === req.user.id &&
        !active
      ) {
        return res.status(400).json({
          error: "You cannot disable your own admin account"
        });
      }

      db.prepare(`
        UPDATE users
        SET active=?
        WHERE id=?
      `).run(
        active ? 1 : 0,
        id
      );
    }

    res.json({
      ok: true
    });
  }
);

app.patch(
  "/api/admin/me/password",
  auth,
  requireRole("admin"),
  (req, res) => {
    const {
      currentPassword,
      newPassword
    } = req.body || {};

    if (
      !currentPassword ||
      !newPassword
    ) {
      return res.status(400).json({
        error: "Current and new password are required"
      });
    }

    if (String(newPassword).length < 8) {
      return res.status(400).json({
        error: "New password must be at least 8 characters"
      });
    }

    const me = db.prepare(`
      SELECT *
      FROM users
      WHERE id=? AND role='admin'
    `).get(req.user.id);

    if (
      !me ||
      !bcrypt.compareSync(
        String(currentPassword),
        me.password_hash
      )
    ) {
      return res.status(401).json({
        error: "Current password is incorrect"
      });
    }

    db.prepare(`
      UPDATE users
      SET password_hash=?
      WHERE id=?
    `).run(
      bcrypt.hashSync(
        String(newPassword),
        12
      ),
      req.user.id
    );

    res.json({
      ok: true
    });
  }
);

// =========================
// ADMIN STATS
// =========================

app.get(
  "/api/admin/stats",
  auth,
  requireRole("admin"),
  (req, res) => {
    const totalAgents =
      db.prepare(`
        SELECT COUNT(*) AS count
        FROM users
        WHERE role='agent'
      `).get().count;

    const onlineAgents =
      db.prepare(`
        SELECT COUNT(*) AS count
        FROM users
        WHERE role='agent'
          AND active=1
          AND online=1
      `).get().count;

    const activeChats =
      db.prepare(`
        SELECT COUNT(*) AS count
        FROM conversations
        WHERE status='active'
      `).get().count;

    const waitingChats =
      db.prepare(`
        SELECT COUNT(*) AS count
        FROM conversations
        WHERE status='waiting'
      `).get().count;

    const closedChats =
      db.prepare(`
        SELECT COUNT(*) AS count
        FROM conversations
        WHERE status='closed'
      `).get().count;

    const totalChats =
      db.prepare(`
        SELECT COUNT(*) AS count
        FROM conversations
      `).get().count;

    const totalAdmins =
      db.prepare(`
        SELECT COUNT(*) AS count
        FROM users
        WHERE role='admin'
          AND active=1
      `).get().count;

    res.json({
      totalAgents,
      onlineAgents,
      activeChats,
      waitingChats,
      closedChats,
      totalChats,
      totalAdmins
    });
  }
);

// =========================
// ADMIN CONVERSATIONS
// =========================

app.get(
  "/api/admin/conversations",
  auth,
  requireRole("admin"),
  (req, res) => {
    const {
      fromDate,
      toDate,
      fromTime,
      toTime,
      agentId,
      status,
      search
    } = req.query || {};

    const where = [];
    const params = [];

    if (fromDate) {
      where.push(
        "date(c.created_at) >= date(?)"
      );
      params.push(String(fromDate));
    }

    if (toDate) {
      where.push(
        "date(c.created_at) <= date(?)"
      );
      params.push(String(toDate));
    }

    if (fromTime) {
      where.push(
        "time(c.created_at) >= time(?)"
      );
      params.push(String(fromTime));
    }

    if (toTime) {
      where.push(
        "time(c.created_at) <= time(?)"
      );
      params.push(String(toTime));
    }

    if (
      agentId &&
      /^\d+$/.test(String(agentId))
    ) {
      where.push("c.agent_id=?");
      params.push(Number(agentId));
    }

    if (
      status &&
      ["waiting", "active", "closed"]
        .includes(String(status))
    ) {
      where.push("c.status=?");
      params.push(String(status));
    }

    if (search) {
      where.push(
        "LOWER(c.customer_name) LIKE LOWER(?)"
      );
      params.push(
        "%" +
        String(search).slice(0, 80) +
        "%"
      );
    }

    const sql = `
      SELECT
        c.id,
        c.customer_name,
        c.agent_id,
        c.status,
        c.created_at,
        c.closed_at,
        c.assigned_at,
        c.first_assigned_at,
        u.name AS agent_name,
        (
          SELECT message
          FROM messages m
          WHERE m.conversation_id=c.id
          ORDER BY m.id DESC
          LIMIT 1
        ) AS last_message
      FROM conversations c
      LEFT JOIN users u
        ON u.id=c.agent_id
      ${
        where.length
          ? "WHERE " + where.join(" AND ")
          : ""
      }
      ORDER BY c.id DESC
    `;

    res.json(
      db.prepare(sql).all(...params)
    );
  }
);

app.get(
  "/api/admin/conversations/:id/detail",
  auth,
  requireRole("admin"),
  (req, res) => {
    const id = Number(
      req.params.id
    );

    const conversation =
      getConversation(id);

    if (!conversation) {
      return res.status(404).json({
        error: "Conversation not found"
      });
    }

    const messages =
      db.prepare(`
        SELECT
          id,
          sender_type,
          message,
          created_at
        FROM messages
        WHERE conversation_id=?
        ORDER BY id ASC
      `).all(id);

    const assignments =
      db.prepare(`
        SELECT
          ca.*,
          u.name AS agent_name
        FROM conversation_assignments ca
        JOIN users u
          ON u.id=ca.agent_id
        WHERE ca.conversation_id=?
        ORDER BY ca.id ASC
      `).all(id);

    const notes =
      db.prepare(`
        SELECT
          n.*,
          u.name AS agent_name
        FROM conversation_notes n
        JOIN users u
          ON u.id=n.agent_id
        WHERE n.conversation_id=?
        ORDER BY n.id DESC
      `).all(id);

    const prechatMessages =
      conversation.prechat_session_id
        ? db.prepare(`
            SELECT
              id,
              sender_type,
              message,
              created_at
            FROM prechat_messages
            WHERE session_id=?
            ORDER BY id ASC
          `).all(
            conversation.prechat_session_id
          )
        : [];

    res.json({
      conversation,
      messages,
      prechatMessages,
      assignments,
      notes
    });
  }
);

// =========================
// AGENT PROFILE
// =========================

app.get(
  "/api/agent/me",
  auth,
  requireRole("agent"),
  (req, res) => {
    const agent = db.prepare(`
      SELECT
        id,
        name,
        username,
        capacity,
        active,
        online,
        support_status,
        status_since,
        last_online_at,
        last_offline_at,
        last_break_at
      FROM users
      WHERE id=?
    `).get(req.user.id);

    if (!agent) {
      return res.status(404).json({
        error: "Agent not found"
      });
    }

    res.json({
      ...agent,
      current: activeCount(agent.id)
    });
  }
);

app.get(
  "/api/agent/stats",
  auth,
  requireRole("agent"),
  (req, res) => {
    const assignedActive =
      db.prepare(`
        SELECT COUNT(*) AS count
        FROM conversations
        WHERE agent_id=?
          AND status='active'
      `).get(req.user.id).count;

    const waitingChats =
      db.prepare(`
        SELECT COUNT(*) AS count
        FROM conversations
        WHERE status='waiting'
      `).get().count;

    const totalAssigned =
      db.prepare(`
        SELECT COUNT(*) AS count
        FROM conversations
        WHERE agent_id=?
      `).get(req.user.id).count;

    res.json({
      assignedActive,
      waitingChats,
      totalAssigned
    });
  }
);

// =========================
// AGENT ACTIVE CUSTOMERS
// =========================

app.get(
  "/api/agent/conversations",
  auth,
  requireRole("agent"),
  (req, res) => {
    const rows = db.prepare(`
      SELECT
        c.id,
        c.customer_name,
        c.agent_id,
        c.status,
        c.created_at,
        c.closed_at,
        c.assigned_at,
        c.first_assigned_at,
        c.last_activity_at,

        CASE
          WHEN c.status='active'
          THEN CAST(
            (
              julianday('now') -
              julianday(
                COALESCE(
                  c.assigned_at,
                  c.created_at
                )
              )
            ) * 86400
            AS INTEGER
          )
          ELSE 0
        END AS handling_seconds,

        (
          SELECT message
          FROM messages m
          WHERE m.conversation_id=c.id
          ORDER BY m.id DESC
          LIMIT 1
        ) AS last_message

      FROM conversations c
      WHERE c.agent_id=?
        AND c.status='active'

      ORDER BY c.id DESC
    `).all(req.user.id);

    res.json(rows);
  }
);

// =========================
// AGENT AVAILABLE AGENTS
// =========================

app.get(
  "/api/agent/available-agents",
  auth,
  requireRole("agent"),
  (req, res) => {
    const rows = db.prepare(`
      SELECT
        id,
        name,
        capacity
      FROM users
      WHERE role='agent'
        AND active=1
        AND support_status='online'
        AND id<>?
      ORDER BY name
    `).all(req.user.id);

    res.json(
      rows.map(agent => ({
        ...agent,
        current:
          activeCount(agent.id),
        available:
          activeCount(agent.id) <
          agent.capacity
      }))
    );
  }
);

// =========================
// AGENT TRANSFER
// =========================

app.post(
  "/api/agent/conversations/:id/transfer",
  auth,
  requireRole("agent"),
  (req, res) => {
    const id = Number(
      req.params.id
    );

    const targetId = Number(
      req.body?.targetAgentId
    );

    const conversation =
      conversationAllowed(
        req.user,
        id
      );

    if (
      !conversation ||
      conversation.status !== "active"
    ) {
      return res.status(404).json({
        error: "Active conversation not found"
      });
    }

    const target =
      db.prepare(`
        SELECT
          id,
          name,
          capacity
        FROM users
        WHERE id=?
          AND role='agent'
          AND active=1
          AND support_status='online'
      `).get(targetId);

    if (!target) {
      return res.status(400).json({
        error: "Target agent is not available"
      });
    }

    if (target.id === req.user.id) {
      return res.status(400).json({
        error: "Choose another agent"
      });
    }

    if (
      activeCount(target.id) >=
      target.capacity
    ) {
      return res.status(400).json({
        error: "Target agent is at capacity"
      });
    }

    const now =
      new Date().toISOString();

    db.prepare(`
      UPDATE conversation_assignments
      SET ended_at=?
      WHERE conversation_id=?
        AND ended_at IS NULL
    `).run(now, id);

    db.prepare(`
      UPDATE conversations
      SET
        agent_id=?,
        assigned_at=?,
        last_activity_at=?
      WHERE id=?
    `).run(
      target.id,
      now,
      now,
      id
    );

    db.prepare(`
      INSERT INTO conversation_assignments
        (
          conversation_id,
          agent_id,
          started_at
        )
      VALUES (?,?,?)
    `).run(
      id,
      target.id,
      now
    );

    broadcastConversation(id);

    res.json({
      ok: true,
      conversation:
        getConversation(id)
    });
  }
);

// =========================
// PRIVATE NOTES
// =========================

app.post(
  "/api/agent/conversations/:id/notes",
  auth,
  requireRole("agent"),
  (req, res) => {
    const id = Number(
      req.params.id
    );

    const conversation =
      conversationAllowed(
        req.user,
        id
      );

    if (!conversation) {
      return res.status(404).json({
        error: "Conversation not found"
      });
    }

    const note =
      String(
        req.body?.note || ""
      )
        .trim()
        .slice(0, 1000);

    if (!note) {
      return res.status(400).json({
        error: "Note is required"
      });
    }

    db.prepare(`
      INSERT INTO conversation_notes
        (
          conversation_id,
          agent_id,
          note
        )
      VALUES (?,?,?)
    `).run(
      id,
      req.user.id,
      note
    );

    res.json({
      ok: true
    });
  }
);

app.get(
  "/api/agent/conversations/:id/notes",
  auth,
  requireRole("agent"),
  (req, res) => {
    const id = Number(
      req.params.id
    );

    const conversation =
      conversationAllowed(
        req.user,
        id
      );

    if (!conversation) {
      return res.status(404).json({
        error: "Conversation not found"
      });
    }

    const notes =
      db.prepare(`
        SELECT
          n.id,
          n.note,
          n.created_at,
          u.name AS agent_name
        FROM conversation_notes n
        JOIN users u
          ON u.id=n.agent_id
        WHERE n.conversation_id=?
        ORDER BY n.id DESC
      `).all(id);

    res.json(notes);
  }
);

// =========================
// AGENT CHAT MESSAGES
// =========================

app.get(
  "/api/agent/conversations/:id/messages",
  auth,
  requireRole("agent"),
  (req, res) => {
    const id = Number(
      req.params.id
    );

    const conversation =
      conversationAllowed(
        req.user,
        id
      );

    if (!conversation) {
      return res.status(404).json({
        error: "Conversation not found"
      });
    }

    const messages =
      db.prepare(`
        SELECT
          id,
          sender_type,
          message,
          created_at
        FROM messages
        WHERE conversation_id=?
        ORDER BY id ASC
      `).all(id);

    const prechatMessages =
      conversation.prechat_session_id
        ? db.prepare(`
            SELECT
              id,
              sender_type,
              message,
              created_at
            FROM prechat_messages
            WHERE session_id=?
            ORDER BY id ASC
          `).all(
            conversation.prechat_session_id
          )
        : [];

    res.json({
      conversation:
        getConversation(id),
      messages,
      prechatMessages
    });
  }
);

// =========================
// AGENT END CHAT
// =========================

app.post(
  "/api/conversations/:id/close",
  auth,
  (req, res) => {
    const id = Number(
      req.params.id
    );

    const conversation =
      conversationAllowed(
        req.user,
        id
      );

    if (!conversation) {
      return res.status(404).json({
        error: "Conversation not found"
      });
    }

    const now =
      new Date().toISOString();

    db.prepare(`
      UPDATE conversations
      SET
        status='closed',
        closed_at=?,
        last_activity_at=?
      WHERE id=?
    `).run(
      now,
      now,
      id
    );

    db.prepare(`
      UPDATE conversation_assignments
      SET ended_at=?
      WHERE conversation_id=?
        AND ended_at IS NULL
    `).run(
      now,
      id
    );

    broadcast(
      id,
      {
        type: "conversation",
        conversation:
          getConversation(id)
      }
    );

    assignWaiting();

    res.json({
      ok: true
    });
  }
);

// =========================
// CUSTOMER END CHAT
// =========================

app.post(
  "/api/customer/conversations/:id/close",
  (req, res) => {
    const id = Number(
      req.params.id
    );

    const token =
      String(
        req.body?.token || ""
      );

    if (!token) {
      return res.status(400).json({
        error: "Customer token is required"
      });
    }

    const conversation =
      db.prepare(`
        SELECT *
        FROM conversations
        WHERE id=?
          AND customer_token=?
      `).get(
        id,
        token
      );

    if (!conversation) {
      return res.status(404).json({
        error: "Conversation not found"
      });
    }

    if (
      conversation.status === "closed"
    ) {
      return res.json({
        ok: true
      });
    }

    const now =
      new Date().toISOString();

    db.prepare(`
      UPDATE conversations
      SET
        status='closed',
        closed_at=?,
        last_activity_at=?
      WHERE id=?
    `).run(
      now,
      now,
      id
    );

    db.prepare(`
      UPDATE conversation_assignments
      SET ended_at=?
      WHERE conversation_id=?
        AND ended_at IS NULL
    `).run(
      now,
      id
    );

    broadcast(
      id,
      {
        type: "conversation",
        conversation:
          getConversation(id)
      }
    );

    assignWaiting();

    res.json({
      ok: true
    });
  }
);

// =========================
// CUSTOMER START CHAT
// =========================

app.post(
  "/api/customer/start",
  (req, res) => {
    const {
      name,
      prechatToken
    } = req.body || {};

    const customerName =
      String(
        name ||
        "Website visitor"
      )
        .trim()
        .slice(0, 80);

    const token =
      crypto.randomBytes(24)
        .toString("hex");

    const result =
      db.prepare(`
        INSERT INTO conversations
          (
            customer_name,
            customer_token,
            status
          )
        VALUES (?,?, 'waiting')
      `).run(
        customerName,
        token
      );

    if (prechatToken) {
      const session =
        db.prepare(`
          SELECT id
          FROM prechat_sessions
          WHERE session_token=?
        `).get(
          String(prechatToken)
        );

      if (session) {
        db.prepare(`
          UPDATE conversations
          SET prechat_session_id=?
          WHERE id=?
        `).run(
          session.id,
          result.lastInsertRowid
        );

        db.prepare(`
          UPDATE prechat_sessions
          SET
            customer_name=?,
            status='handed_off',
            handed_off_at=CURRENT_TIMESTAMP,
            last_activity_at=CURRENT_TIMESTAMP
          WHERE id=?
        `).run(
          customerName,
          session.id
        );
      }
    }

    assignWaiting();

    const conversation =
      getConversation(
        result.lastInsertRowid
      );

    res.json({
      conversationId:
        conversation.id,
      customerToken: token,
      conversation
    });
  }
);

// =========================
// CUSTOMER MESSAGES
// =========================

app.get(
  "/api/customer/conversations/:id/messages",
  (req, res) => {
    const token =
      String(
        req.query.token || ""
      );

    const conversation =
      db.prepare(`
        SELECT *
        FROM conversations
        WHERE id=?
          AND customer_token=?
      `).get(
        Number(req.params.id),
        token
      );

    if (!conversation) {
      return res.status(404).json({
        error: "Conversation not found"
      });
    }

    const messages =
      db.prepare(`
        SELECT
          id,
          sender_type,
          message,
          created_at
        FROM messages
        WHERE conversation_id=?
        ORDER BY id ASC
      `).all(
        conversation.id
      );

    res.json({
      conversation:
        getConversation(
          conversation.id
        ),
      messages
    });
  }
);

// =========================
// AGENT PRE-CHAT
// =========================

app.get(
  "/api/agent/prechats",
  auth,
  requireRole("agent"),
  (req, res) => {
    const rows =
      db.prepare(`
        SELECT
          s.id,
          s.session_token,
          s.customer_name,
          s.status,
          s.created_at,
          s.last_activity_at,

          (
            SELECT message
            FROM prechat_messages m
            WHERE m.session_id=s.id
            ORDER BY m.id DESC
            LIMIT 1
          ) AS last_message,

          (
            SELECT COUNT(*)
            FROM prechat_messages m
            WHERE m.session_id=s.id
          ) AS message_count

        FROM prechat_sessions s

        WHERE s.status='active'

        ORDER BY
          s.last_activity_at DESC

        LIMIT 100
      `).all();

    res.json(rows);
  }
);

app.get(
  "/api/agent/prechats/:id",
  auth,
  requireRole("agent"),
  (req, res) => {
    const id =
      Number(req.params.id);

    const session =
      db.prepare(`
        SELECT *
        FROM prechat_sessions
        WHERE id=?
      `).get(id);

    if (!session) {
      return res.status(404).json({
        error: "Pre-chat not found"
      });
    }

    const messages =
      db.prepare(`
        SELECT
          id,
          sender_type,
          message,
          created_at
        FROM prechat_messages
        WHERE session_id=?
        ORDER BY id ASC
      `).all(id);

    res.json({
      session,
      messages
    });
  }
);

// =========================
// ADMIN PRE-CHAT
// =========================

app.get(
  "/api/admin/prechats",
  auth,
  requireRole("admin"),
  (req, res) => {
    const rows =
      db.prepare(`
        SELECT
          s.id,
          s.customer_name,
          s.status,
          s.created_at,
          s.last_activity_at,
          s.handed_off_at,

          (
            SELECT COUNT(*)
            FROM prechat_messages m
            WHERE m.session_id=s.id
          ) AS message_count

        FROM prechat_sessions s

        ORDER BY s.id DESC

        LIMIT 200
      `).all();

    res.json(rows);
  }
);

// =========================
// WEBSOCKET LIVE CHAT
// =========================

wss.on(
  "connection",
  (ws, req) => {
    try {
      const url =
        new URL(
          req.url,
          `http://${req.headers.host}`
        );

      const conversationId =
        Number(
          url.searchParams.get(
            "conversationId"
          )
        );

      const token =
        url.searchParams.get(
          "token"
        );

      if (
        !conversationId ||
        !token
      ) {
        throw new Error(
          "Missing credentials"
        );
      }

      let user;

      try {
        user =
          jwt.verify(
            token,
            JWT_SECRET
          );
      } catch {
        user = {
          role: "customer",
          token
        };
      }

      const conversation =
        conversationAllowed(
          user,
          conversationId
        );

      if (!conversation) {
        throw new Error(
          "Not allowed"
        );
      }

      addSocket(
        conversationId,
        ws
      );

      sendJson(
        ws,
        {
          type: "conversation",
          conversation:
            getConversation(
              conversationId
            )
        }
      );

      ws.on(
        "message",
        raw => {
          try {
            const payload =
              JSON.parse(
                raw.toString()
              );

            if (
              !payload.message ||
              String(
                payload.message
              ).trim().length === 0
            ) {
              return;
            }

            const text =
              String(
                payload.message
              )
                .trim()
                .slice(0, 2000);

            const current =
              conversationAllowed(
                user,
                conversationId
              );

            if (
              !current ||
              current.status === "closed"
            ) {
              return;
            }

            const senderType =
              user.role === "agent"
                ? "agent"
                : "customer";

            const senderId =
              senderType === "agent"
                ? user.id
                : null;

            const result =
              db.prepare(`
                INSERT INTO messages
                  (
                    conversation_id,
                    sender_type,
                    sender_id,
                    message
                  )
                VALUES (?,?,?,?)
              `).run(
                conversationId,
                senderType,
                senderId,
                text
              );

            const message =
              db.prepare(`
                SELECT
                  id,
                  sender_type,
                  message,
                  created_at
                FROM messages
                WHERE id=?
              `).get(
                result.lastInsertRowid
              );

            db.prepare(`
              UPDATE conversations
              SET last_activity_at=?
              WHERE id=?
            `).run(
              new Date().toISOString(),
              conversationId
            );

            broadcast(
              conversationId,
              {
                type: "message",
                message
              }
            );

            broadcastConversation(
              conversationId
            );
          } catch {
            // Ignore malformed websocket messages
          }
        }
      );

      ws.on(
        "close",
        () => {
          removeSocket(ws);
        }
      );
    } catch {
      try {
        ws.close();
      } catch {}
    }
  }
);

// =========================
// FALLBACK
// =========================

app.get("*", (req, res) => {
  const indexFile =
    path.join(
      PUBLIC,
      "index.html"
    );

  if (
    fs.existsSync(indexFile)
  ) {
    res.sendFile(indexFile);
  } else {
    res.status(404).send(
      "Website not found"
    );
  }
});

// =========================
// START SERVER
// =========================

server.listen(
  PORT,
  () => {
    console.log(
      `Abhishek Events server running on port ${PORT}`
    );
  }
);
