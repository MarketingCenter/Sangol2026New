const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { WebSocketServer } = require("ws");

const HOST = process.env.HOST || "0.0.0.0";
const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = __dirname;
const DB_PATH = path.join(__dirname, "data.db");
const usePg = !!process.env.DATABASE_URL;
let db = null;
let pool = null;

function toPgSql(sql) {
  if (!usePg) return sql;
  let i = 0;
  return sql.replace(/\?/g, () => `$${++i}`);
}

function dbGet(sql, params = []) {
  if (usePg) {
    return pool.query(toPgSql(sql), params).then((res) => res.rows[0] || null);
  }
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row || null);
    });
  });
}

function dbAll(sql, params = []) {
  if (usePg) {
    return pool.query(toPgSql(sql), params).then((res) => res.rows || []);
  }
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows || []);
    });
  });
}

function dbRun(sql, params = []) {
  if (usePg) {
    return pool.query(toPgSql(sql), params).then((res) => ({ changes: res.rowCount || 0 }));
  }
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve({ changes: this.changes || 0 });
    });
  });
}

function dbInsert(sql, params = []) {
  if (usePg) {
    const withReturn = `${sql} RETURNING id`;
    return pool.query(toPgSql(withReturn), params).then((res) => res.rows[0].id);
  }
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve(this.lastID);
    });
  });
}

function isUniqueError(err) {
  if (!err) return false;
  return err.code === "SQLITE_CONSTRAINT" || err.code === "23505";
}

async function initDb() {
  if (usePg) {
    const { Pool } = require("pg");
    const ssl = process.env.PGSSL_DISABLE ? false : { rejectUnauthorized: false };
    pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl });
    await pool.query(
      "CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, salt TEXT, active_deck_id INTEGER)"
    );
    await pool.query(
      "CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id INTEGER, created_at BIGINT)"
    );
    await pool.query(
      "CREATE TABLE IF NOT EXISTS decks (id SERIAL PRIMARY KEY, user_id INTEGER, name TEXT, cards_json TEXT, updated_at BIGINT)"
    );
    return;
  }
  const sqlite3 = require("sqlite3").verbose();
  db = new sqlite3.Database(DB_PATH);
  await new Promise((resolve) => {
    db.serialize(() => {
      db.run(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password_hash TEXT, salt TEXT, active_deck_id INTEGER)"
      );
      db.run(
        "CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id INTEGER, created_at INTEGER)"
      );
      db.run(
        "CREATE TABLE IF NOT EXISTS decks (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT, cards_json TEXT, updated_at INTEGER)"
      );
      resolve();
    });
  });
}

const dbReady = initDb();

function serveStatic(req, res) {
  if (req.url.startsWith("/api/")) {
    handleApi(req, res);
    return;
  }
  const urlPath = req.url === "/" ? "/index3.html" : req.url;
  const safePath = path.normalize(urlPath).replace(/^(\.\.[/\\])+/, "");
  const filePath = path.join(PUBLIC_DIR, safePath);

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404);
      res.end("Not found");
      return;
    }
    const ext = path.extname(filePath).toLowerCase();
    const contentType =
      ext === ".html"
        ? "text/html"
        : ext === ".js"
        ? "application/javascript"
        : ext === ".css"
        ? "text/css"
        : "application/octet-stream";
    res.writeHead(200, { "Content-Type": contentType });
    res.end(data);
  });
}

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload || {});
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(body);
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk) => {
      data += chunk.toString();
      if (data.length > 1e6) {
        reject(new Error("body_too_large"));
      }
    });
    req.on("end", () => {
      if (!data) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(data));
      } catch (err) {
        reject(err);
      }
    });
  });
}

function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, "sha512").toString("hex");
}

function createToken() {
  return crypto.randomBytes(24).toString("hex");
}

function getAuthUser(req, cb) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token) {
    cb(null, null);
    return;
  }
  dbGet(
    "SELECT users.id, users.username, users.active_deck_id FROM sessions JOIN users ON users.id = sessions.user_id WHERE sessions.token = ?",
    [token]
  )
    .then((row) => {
      if (!row) {
        cb(null, null);
        return;
      }
      cb(token, row);
    })
    .catch(() => cb(null, null));
}

async function handleApi(req, res) {
  await dbReady;

  if (req.method === "POST" && req.url === "/api/register") {
    try {
      const body = await parseBody(req);
      const username = (body.username || "").trim();
      const password = body.password || "";
      if (!username || !password) {
        sendJson(res, 400, { error: "missing_fields" });
        return;
      }
      const salt = crypto.randomBytes(16).toString("hex");
      const hash = hashPassword(password, salt);
      let userId;
      try {
        userId = await dbInsert(
          "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
          [username, hash, salt]
        );
      } catch (err) {
        if (isUniqueError(err)) {
          sendJson(res, 409, { error: "username_taken" });
          return;
        }
        sendJson(res, 500, { error: "db_error" });
        return;
      }
      const token = createToken();
      await dbRun("INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)", [
        token,
        userId,
        Date.now()
      ]);
      sendJson(res, 200, { token, username });
    } catch {
      sendJson(res, 400, { error: "invalid_json" });
    }
    return;
  }

  if (req.method === "POST" && req.url === "/api/login") {
    try {
      const body = await parseBody(req);
      const username = (body.username || "").trim();
      const password = body.password || "";
      if (!username || !password) {
        sendJson(res, 400, { error: "missing_fields" });
        return;
      }
      const row = await dbGet(
        "SELECT id, username, password_hash, salt FROM users WHERE username = ?",
        [username]
      );
      if (!row) {
        sendJson(res, 401, { error: "invalid_credentials" });
        return;
      }
      const hash = hashPassword(password, row.salt);
      if (hash !== row.password_hash) {
        sendJson(res, 401, { error: "invalid_credentials" });
        return;
      }
      const token = createToken();
      await dbRun("INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)", [
        token,
        row.id,
        Date.now()
      ]);
      sendJson(res, 200, { token, username: row.username });
    } catch {
      sendJson(res, 400, { error: "invalid_json" });
    }
    return;
  }

  if (req.method === "POST" && req.url === "/api/logout") {
    getAuthUser(req, async (token) => {
      if (!token) {
        sendJson(res, 401, { error: "unauthorized" });
        return;
      }
      await dbRun("DELETE FROM sessions WHERE token = ?", [token]);
      sendJson(res, 200, { ok: true });
    });
    return;
  }

  if (req.method === "GET" && req.url === "/api/me") {
    getAuthUser(req, (token, user) => {
      if (!user) {
        sendJson(res, 401, { error: "unauthorized" });
        return;
      }
      sendJson(res, 200, { username: user.username, activeDeckId: user.active_deck_id || null });
    });
    return;
  }

  if (req.url === "/api/decks" && req.method === "GET") {
    getAuthUser(req, async (token, user) => {
      if (!user) {
        sendJson(res, 401, { error: "unauthorized" });
        return;
      }
      try {
        const rows = await dbAll(
          "SELECT id, name, cards_json FROM decks WHERE user_id = ? ORDER BY updated_at DESC",
          [user.id]
        );
        const decks = rows.map((r) => ({
          id: r.id,
          name: r.name,
          cards: JSON.parse(r.cards_json || "[]")
        }));
        sendJson(res, 200, { decks, activeDeckId: user.active_deck_id || null });
      } catch {
        sendJson(res, 500, { error: "db_error" });
      }
    });
    return;
  }

  if (req.url === "/api/decks" && req.method === "POST") {
    getAuthUser(req, async (token, user) => {
      if (!user) {
        sendJson(res, 401, { error: "unauthorized" });
        return;
      }
      try {
        const body = await parseBody(req);
        const name = (body.name || "").trim();
        const cards = Array.isArray(body.cards) ? body.cards : [];
        if (!name || cards.length !== 30) {
          sendJson(res, 400, { error: "invalid_deck" });
          return;
        }
        const deckId = await dbInsert(
          "INSERT INTO decks (user_id, name, cards_json, updated_at) VALUES (?, ?, ?, ?)",
          [user.id, name, JSON.stringify(cards), Date.now()]
        );
        sendJson(res, 200, { id: deckId });
      } catch {
        sendJson(res, 400, { error: "invalid_json" });
      }
    });
    return;
  }

  if (req.url.startsWith("/api/decks/") && req.method === "PUT") {
    getAuthUser(req, async (token, user) => {
      if (!user) {
        sendJson(res, 401, { error: "unauthorized" });
        return;
      }
      const id = parseInt(req.url.split("/").pop(), 10);
      if (!id) {
        sendJson(res, 400, { error: "invalid_id" });
        return;
      }
      try {
        const body = await parseBody(req);
        const name = (body.name || "").trim();
        const cards = Array.isArray(body.cards) ? body.cards : [];
        if (!name || cards.length !== 30) {
          sendJson(res, 400, { error: "invalid_deck" });
          return;
        }
        const result = await dbRun(
          "UPDATE decks SET name = ?, cards_json = ?, updated_at = ? WHERE id = ? AND user_id = ?",
          [name, JSON.stringify(cards), Date.now(), id, user.id]
        );
        if (!result.changes) {
          sendJson(res, 404, { error: "not_found" });
          return;
        }
        sendJson(res, 200, { ok: true });
      } catch {
        sendJson(res, 400, { error: "invalid_json" });
      }
    });
    return;
  }

  if (req.url.startsWith("/api/decks/") && req.method === "DELETE") {
    getAuthUser(req, async (token, user) => {
      if (!user) {
        sendJson(res, 401, { error: "unauthorized" });
        return;
      }
      const id = parseInt(req.url.split("/").pop(), 10);
      if (!id) {
        sendJson(res, 400, { error: "invalid_id" });
        return;
      }
      const result = await dbRun("DELETE FROM decks WHERE id = ? AND user_id = ?", [id, user.id]);
      if (!result.changes) {
        sendJson(res, 404, { error: "not_found" });
        return;
      }
      sendJson(res, 200, { ok: true });
    });
    return;
  }

  if (req.url === "/api/decks/active" && req.method === "POST") {
    getAuthUser(req, async (token, user) => {
      if (!user) {
        sendJson(res, 401, { error: "unauthorized" });
        return;
      }
      try {
        const body = await parseBody(req);
        const deckId = body.deckId ? parseInt(body.deckId, 10) : null;
        await dbRun("UPDATE users SET active_deck_id = ? WHERE id = ?", [deckId, user.id]);
        sendJson(res, 200, { ok: true });
      } catch {
        sendJson(res, 400, { error: "invalid_json" });
      }
    });
    return;
  }

  sendJson(res, 404, { error: "not_found" });
}

const server = http.createServer(serveStatic);
const wss = new WebSocketServer({ server });

const rooms = new Map(); // code -> { sockets: Set<ws> }
const clientMeta = new WeakMap(); // ws -> { roomCode, seat }

function generateRoomCode() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let code = "";
  for (let i = 0; i < 6; i++) {
    code += alphabet[Math.floor(Math.random() * alphabet.length)];
  }
  return code;
}

function safeSend(ws, obj) {
  try {
    ws.send(JSON.stringify(obj));
  } catch (e) {
    // ignore send errors
  }
}

function addClientToRoom(ws, code) {
  let room = rooms.get(code);
  if (!room) {
    room = { sockets: new Set() };
    rooms.set(code, room);
  }
  room.sockets.add(ws);
  const seat = room.sockets.size - 1; // 0 or 1
  clientMeta.set(ws, { roomCode: code, seat });
  return seat;
}

function removeClient(ws) {
  const meta = clientMeta.get(ws);
  if (!meta) return;
  const room = rooms.get(meta.roomCode);
  if (!room) return;
  room.sockets.delete(ws);
  clientMeta.delete(ws);
  room.sockets.forEach((peer) => safeSend(peer, { type: "peerLeft" }));
  if (room.sockets.size === 0) {
    rooms.delete(meta.roomCode);
  }
}

wss.on("connection", (ws) => {
  ws.on("message", (data) => {
    let msg;
    try {
      msg = JSON.parse(data.toString());
    } catch (e) {
      safeSend(ws, { type: "error", reason: "invalid_json" });
      return;
    }

    if (msg.type === "createRoom") {
      if (clientMeta.has(ws)) {
        safeSend(ws, { type: "error", reason: "already_in_room" });
        return;
      }
      let code;
      do {
        code = generateRoomCode();
      } while (rooms.has(code));

      const seat = addClientToRoom(ws, code);
      safeSend(ws, { type: "roomCreated", code, seat });
      return;
    }

    if (msg.type === "joinRoom") {
      if (clientMeta.has(ws)) {
        safeSend(ws, { type: "error", reason: "already_in_room" });
        return;
      }
      const code = (msg.code || "").toUpperCase();
      const room = rooms.get(code);
      if (!room) {
        safeSend(ws, { type: "error", reason: "room_not_found" });
        return;
      }
      if (room.sockets.size >= 2) {
        safeSend(ws, { type: "error", reason: "room_full" });
        return;
      }
      const seat = addClientToRoom(ws, code);
      safeSend(ws, { type: "roomJoined", code, seat });
      room.sockets.forEach((peer) => {
        if (peer !== ws) {
          safeSend(peer, { type: "peerJoined" });
        }
      });
      return;
    }

    if (msg.type === "relay") {
      const meta = clientMeta.get(ws);
      if (!meta) {
        safeSend(ws, { type: "error", reason: "not_in_room" });
        return;
      }
      if (typeof msg.payload !== "object" || msg.payload === null) {
        safeSend(ws, { type: "error", reason: "invalid_payload" });
        return;
      }
      const room = rooms.get(meta.roomCode);
      if (!room) {
        safeSend(ws, { type: "error", reason: "room_missing" });
        return;
      }
      room.sockets.forEach((peer) => {
        if (peer !== ws) {
          safeSend(peer, { type: "relay", fromSeat: meta.seat, payload: msg.payload || {} });
        }
      });
      return;
    }

    safeSend(ws, { type: "error", reason: "unknown_type" });
  });

  ws.on("close", () => removeClient(ws));
  ws.on("error", () => removeClient(ws));
});

server.listen(PORT, HOST, () => {
  console.log(`Server running at http://${HOST}:${PORT}`);
});
