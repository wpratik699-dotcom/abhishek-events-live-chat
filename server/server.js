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

const adminExists = db.prepare("SELECT id FROM users WHERE username='admin'").get();
if (!adminExists) {
  db.prepare(`
    INSERT INTO users (name, username, password_hash, role, capacity)
    VALUES (?, ?, ?, 'admin', 999)
  `).run("Administrator", "admin", bcrypt.hashSync(ADMIN_PASSWORD, 12));
} else if (process.env.SYNC_ADMIN_PASSWORD === "true") {
  // Optional one-time/admin recovery mode: set SYNC_ADMIN_PASSWORD=true on Render
  // to make ADMIN_PASSWORD the password for the default admin account.
  db.prepare("UPDATE users SET password_hash=? WHERE username='admin' AND role='admin'")
    .run(bcrypt.hashSync(ADMIN_PASSWORD, 12));
}

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
  res.header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

app.use(express.json({ limit: "20kb" }));
app.use(express.static(PUBLIC));

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "12h" });
}

function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: "Login required" });
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired login" });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) return res.status(403).json({ error: "Access denied" });
    next();
  };
}

function activeCount(agentId) {
  return db.prepare(`
    SELECT COUNT(*) AS count FROM conversations
    WHERE agent_id=? AND status='active'
  `).get(agentId).count;
}

function chooseAgent() {
  const agents = db.prepare(`
    SELECT id, name, capacity FROM users
    WHERE role='agent' AND active=1 AND online=1
    ORDER BY id ASC
  `).all();

  const candidates = agents
    .map(a => ({ ...a, current: activeCount(a.id) }))
    .filter(a => a.current < a.capacity)
    .sort((a,b) => (a.current - b.current) || (a.id - b.id));

  return candidates[0] || null;
}

function assignWaiting() {
  const waiting = db.prepare(`
    SELECT * FROM conversations WHERE status='waiting' ORDER BY id ASC
  `).all();

  for (const c of waiting) {
    const agent = chooseAgent();
    if (!agent) break;
    db.prepare(`
      UPDATE conversations SET agent_id=?, status='active' WHERE id=?
    `).run(agent.id, c.id);
    broadcastConversation(c.id);
  }
}

const rooms = new Map(); // conversationId -> Set<WebSocket>

function addSocket(conversationId, ws) {
  const key = String(conversationId);
  if (!rooms.has(key)) rooms.set(key, new Set());
  rooms.get(key).add(ws);
  ws.roomKey = key;
}

function removeSocket(ws) {
  if (!ws.roomKey) return;
  const room = rooms.get(ws.roomKey);
  if (!room) return;
  room.delete(ws);
  if (!room.size) rooms.delete(ws.roomKey);
}

function sendJson(ws, data) {
  if (ws.readyState === 1) ws.send(JSON.stringify(data));
}

function broadcast(conversationId, data) {
  const room = rooms.get(String(conversationId));
  if (!room) return;
  for (const ws of room) sendJson(ws, data);
}

function getConversation(id) {
  return db.prepare(`
    SELECT c.*, u.name AS agent_name, u.username AS agent_username
    FROM conversations c
    LEFT JOIN users u ON u.id=c.agent_id
    WHERE c.id=?
  `).get(id);
}

function broadcastConversation(id) {
  const c = getConversation(id);
  if (c) broadcast(id, { type: "conversation", conversation: c });
}

function conversationAllowed(user, conversationId) {
  const c = db.prepare("SELECT * FROM conversations WHERE id=?").get(conversationId);
  if (!c) return null;
  if (user.role === "agent" && c.agent_id !== user.id) return null;
  if (user.role === "customer" && c.customer_token !== user.token) return null;
  return c;
}

// ---------- Auth ----------
app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};
  const user = db.prepare("SELECT * FROM users WHERE username=? AND active=1").get(username || "");
  if (!user || !bcrypt.compareSync(password || "", user.password_hash)) {
    return res.status(401).json({ error: "Incorrect username or password" });
  }
  if (user.role === "agent") {
    db.prepare("UPDATE users SET online=1 WHERE id=?").run(user.id);
  }
  const token = signToken({ id: user.id, role: user.role, username: user.username, name: user.name });
  res.json({ token, user: { id:user.id, name:user.name, username:user.username, role:user.role, capacity:user.capacity }});
});

app.post("/api/logout", auth, (req,res) => {
  if (req.user.role === "agent") db.prepare("UPDATE users SET online=0 WHERE id=?").run(req.user.id);
  res.json({ ok:true });
});

// ---------- Admin account management ----------
app.get("/api/admin/admins", auth, requireRole("admin"), (req,res) => {
  const admins = db.prepare(`
    SELECT id,name,username,active,created_at
    FROM users WHERE role='admin' ORDER BY id ASC
  `).all();
  res.json(admins);
});

app.post("/api/admin/admins", auth, requireRole("admin"), (req,res) => {
  const { name, username, password } = req.body || {};
  if (!name || !username || !password) {
    return res.status(400).json({error:"Name, username and password are required"});
  }
  if (String(password).length < 6) {
    return res.status(400).json({error:"Password must be at least 6 characters"});
  }
  try {
    const info = db.prepare(`
      INSERT INTO users (name,username,password_hash,role,capacity)
      VALUES (?,?,?,?,?)
    `).run(String(name).trim(), String(username).trim(), bcrypt.hashSync(String(password),12), "admin", 999);
    res.json({ok:true,id:info.lastInsertRowid});
  } catch {
    res.status(400).json({error:"Username already exists"});
  }
});

app.patch("/api/admin/admins/:id", auth, requireRole("admin"), (req,res) => {
  const id = Number(req.params.id);
  const target = db.prepare("SELECT * FROM users WHERE id=? AND role='admin'").get(id);
  if (!target) return res.status(404).json({error:"Admin not found"});
  const { password, active } = req.body || {};
  if (password !== undefined) {
    if (String(password).length < 6) return res.status(400).json({error:"Password must be at least 6 characters"});
    db.prepare("UPDATE users SET password_hash=? WHERE id=?").run(bcrypt.hashSync(String(password),12), id);
  }
  if (active !== undefined) {
    if (id === req.user.id && !active) return res.status(400).json({error:"You cannot disable your own admin account"});
    db.prepare("UPDATE users SET active=? WHERE id=?").run(active ? 1 : 0, id);
  }
  res.json({ok:true});
});

app.patch("/api/admin/me/password", auth, requireRole("admin"), (req,res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) return res.status(400).json({error:"Current and new password are required"});
  if (String(newPassword).length < 6) return res.status(400).json({error:"New password must be at least 6 characters"});
  const me = db.prepare("SELECT * FROM users WHERE id=? AND role='admin'").get(req.user.id);
  if (!me || !bcrypt.compareSync(String(currentPassword), me.password_hash)) {
    return res.status(401).json({error:"Current password is incorrect"});
  }
  db.prepare("UPDATE users SET password_hash=? WHERE id=?").run(bcrypt.hashSync(String(newPassword),12), req.user.id);
  res.json({ok:true});
});

// ---------- Admin ----------
app.get("/api/admin/agents", auth, requireRole("admin"), (req,res) => {
  const agents = db.prepare(`
    SELECT id,name,username,capacity,active,online,created_at
    FROM users WHERE role='agent' ORDER BY id DESC
  `).all().map(a => ({...a, current:activeCount(a.id)}));
  res.json(agents);
});

app.post("/api/admin/agents", auth, requireRole("admin"), (req,res) => {
  const { name, username, password, capacity } = req.body || {};
  if (!name || !username || !password) return res.status(400).json({error:"Name, username and password are required"});
  const cap = Math.max(1, Math.min(100, Number(capacity || 5)));
  try {
    const info = db.prepare(`
      INSERT INTO users (name,username,password_hash,role,capacity)
      VALUES (?,?,?,?,?)
    `).run(name.trim(), username.trim(), bcrypt.hashSync(password,12), "agent", cap);
    res.json({ok:true,id:info.lastInsertRowid});
  } catch (e) {
    res.status(400).json({error:"Username already exists"});
  }
});

app.patch("/api/admin/agents/:id", auth, requireRole("admin"), (req,res) => {
  const id = Number(req.params.id);
  const { active, capacity, password } = req.body || {};
  const agent = db.prepare("SELECT * FROM users WHERE id=? AND role='agent'").get(id);
  if (!agent) return res.status(404).json({error:"Agent not found"});
  if (capacity !== undefined) {
    const cap = Math.max(1, Math.min(100, Number(capacity)));
    db.prepare("UPDATE users SET capacity=? WHERE id=?").run(cap,id);
  }
  if (active !== undefined) db.prepare("UPDATE users SET active=? WHERE id=?").run(active ? 1:0,id);
  if (password) db.prepare("UPDATE users SET password_hash=? WHERE id=?").run(bcrypt.hashSync(password,12),id);
  assignWaiting();
  res.json({ok:true});
});

app.get("/api/admin/conversations", auth, requireRole("admin"), (req,res) => {
  const rows = db.prepare(`
    SELECT c.id,c.customer_name,c.agent_id,c.status,c.created_at,c.closed_at,u.name AS agent_name
    FROM conversations c LEFT JOIN users u ON u.id=c.agent_id
    ORDER BY c.id DESC
  `).all();
  res.json(rows);
});

// ---------- Agent ----------
app.get("/api/agent/me", auth, requireRole("agent"), (req,res) => {
  const a = db.prepare(`
    SELECT id,name,username,capacity,active,online FROM users WHERE id=?
  `).get(req.user.id);
  res.json({...a,current:activeCount(a.id)});
});

app.post("/api/agent/status", auth, requireRole("agent"), (req,res) => {
  db.prepare("UPDATE users SET online=? WHERE id=?").run(req.body.online ? 1:0, req.user.id);
  if (!req.body.online) assignWaiting();
  res.json({ok:true});
});

app.get("/api/agent/conversations", auth, requireRole("agent"), (req,res) => {
  const rows = db.prepare(`
    SELECT id,customer_name,agent_id,status,created_at,closed_at
    FROM conversations WHERE agent_id=? ORDER BY id DESC
  `).all(req.user.id);
  res.json(rows);
});

app.post("/api/conversations/:id/close", auth, (req,res) => {
  const c = conversationAllowed(req.user, Number(req.params.id));
  if (!c) return res.status(404).json({error:"Conversation not found"});
  db.prepare(`
    UPDATE conversations SET status='closed', closed_at=CURRENT_TIMESTAMP WHERE id=?
  `).run(c.id);
  broadcast(c.id,{type:"conversation",conversation:getConversation(c.id)});
  assignWaiting();
  res.json({ok:true});
});

// ---------- Customer ----------
app.post("/api/customer/start", (req,res) => {
  const { name } = req.body || {};
  const customerName = String(name || "Website visitor").trim().slice(0,80);
  const token = crypto.randomBytes(24).toString("hex");

  const info = db.prepare(`
    INSERT INTO conversations (customer_name,customer_token,status)
    VALUES (?,?, 'waiting')
  `).run(customerName, token);

  assignWaiting();
  const c = getConversation(info.lastInsertRowid);
  res.json({
    conversationId:c.id,
    customerToken:token,
    conversation:c
  });
});

app.get("/api/customer/conversations/:id/messages", (req,res) => {
  const token = String(req.query.token || "");
  const c = db.prepare("SELECT * FROM conversations WHERE id=? AND customer_token=?")
    .get(Number(req.params.id), token);
  if (!c) return res.status(404).json({error:"Conversation not found"});
  const messages = db.prepare(`
    SELECT id,sender_type,message,created_at FROM messages
    WHERE conversation_id=? ORDER BY id ASC
  `).all(c.id);
  res.json({conversation:getConversation(c.id),messages});
});

app.get("/api/agent/conversations/:id/messages", auth, requireRole("agent"), (req,res) => {
  const c = conversationAllowed(req.user, Number(req.params.id));
  if (!c) return res.status(404).json({error:"Conversation not found"});
  const messages = db.prepare(`
    SELECT id,sender_type,message,created_at FROM messages
    WHERE conversation_id=? ORDER BY id ASC
  `).all(c.id);
  res.json({conversation:getConversation(c.id),messages});
});

// ---------- WebSocket ----------
wss.on("connection", (ws, req) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const conversationId = Number(url.searchParams.get("conversationId"));
    const token = url.searchParams.get("token");
    if (!conversationId || !token) throw new Error("Missing credentials");

    let user;
    try { user = jwt.verify(token, JWT_SECRET); } catch {
      user = { role:"customer", token };
    }

    const c = conversationAllowed(user, conversationId);
    if (!c) throw new Error("Not allowed");

    addSocket(conversationId, ws);
    sendJson(ws, {type:"conversation", conversation:getConversation(conversationId)});

    ws.on("message", raw => {
      try {
        const payload = JSON.parse(raw.toString());
        if (!payload.message || String(payload.message).trim().length === 0) return;
        const text = String(payload.message).trim().slice(0,2000);
        const current = conversationAllowed(user, conversationId);
        if (!current || current.status === "closed") return;

        const senderType = user.role === "agent" ? "agent" : "customer";
        const senderId = senderType === "agent" ? user.id : null;
        const info = db.prepare(`
          INSERT INTO messages (conversation_id,sender_type,sender_id,message)
          VALUES (?,?,?,?)
        `).run(conversationId,senderType,senderId,text);

        const msg = db.prepare(`
          SELECT id,sender_type,message,created_at FROM messages WHERE id=?
        `).get(info.lastInsertRowid);

        broadcast(conversationId,{type:"message",message:msg});
      } catch {}
    });

    ws.on("close", () => removeSocket(ws));
  } catch {
    try { ws.close(); } catch {}
  }
});

server.listen(PORT, () => {
  console.log(`Abhishek Events server running at http://localhost:${PORT}`);
});
