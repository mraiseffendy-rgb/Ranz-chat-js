"use strict";
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const os = require("os");
const WebSocket = require("ws");
const config = require("./config.js");

const HOST = "0.0.0.0";
const PORT = Number(process.env.SERVER_PORT || process.env.PORT || process.env.SERVER_ALLOCATION_PORT || 2487);
const DATA_FILE = path.join(__dirname, "data.json");
const HTML_FILE = path.join(__dirname, "index.html");

const SESSION_DAYS = 30;
const MAX_BODY_SIZE = 25 * 1024 * 1024;

/* ============ AI MODERATION RULES ============ */
const AI_RULES = {
  windowMs: 10000, maxInWindow: 5, repeatLimit: 3, longBurstWindowMs: 30000, longBurstMax: 10,
  spamFlagThreshold: 2, 
  immediateBlockCategories: ["judol", "toxic", "sara", "ancaman", "porno", "doxx"],
  immediateBlockSeverities: ["high"], 
  flagResetMs: 24 * 60 * 60 * 1000, baseBanMs: 10 * 60 * 1000,
  maxBanMs: 6 * 60 * 60 * 1000, resetStrikeMs: 7 * 24 * 60 * 60 * 1000
};
const REPORT_THRESHOLDS = { text: 12, media: 15 };
const APPEAL_MIN_MS = 15000;
const APPEAL_MAX_MS = 60000;
const spamTracker = new Map();
const reportReviewTriggered = new Set();

/* ============ MISTRAL AI ============ */
let lastMistralCall = 0;
const mistralQueue = [];
let mistralProcessing = false;
const sleep = ms => new Promise(r => setTimeout(r, ms));

function callMistral(messages, options = {}) {
  const { temperature = config.MISTRAL_TEMPERATURE, maxTokens = config.MISTRAL_MAX_TOKENS } = options;
  return new Promise((resolve, reject) => {
    mistralQueue.push({ messages, temperature, maxTokens, resolve, reject });
    processMistralQueue();
  });
}

async function processMistralQueue() {
  if (mistralProcessing) return;
  mistralProcessing = true;
  while (mistralQueue.length > 0) {
    const job = mistralQueue.shift();
    const elapsed = Date.now() - lastMistralCall;
    if (elapsed < config.MISTRAL_MIN_INTERVAL_MS) await sleep(config.MISTRAL_MIN_INTERVAL_MS - elapsed);
    
    let attempt = 0, success = false, lastError = null;
    while (attempt <= config.MISTRAL_MAX_RETRIES && !success) {
      try {
        if (!config.MISTRAL_API_KEY || config.MISTRAL_API_KEY.includes("mstrl_3BvMtGxX0tqexiuw2hvqZjPnTCmDSBqU_0TIwZv")) throw new Error("API Key missing");
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), config.MISTRAL_TIMEOUT_MS);
        const response = await fetch(`${config.MISTRAL_BASE_URL}/chat/completions`, {
          method: "POST",
          headers: { "Content-Type": "application/json", "Authorization": `Bearer ${config.MISTRAL_API_KEY}` },
          body: JSON.stringify({
            model: config.MISTRAL_MODEL, messages: job.messages, temperature: job.temperature,
            max_tokens: job.maxTokens, response_format: { type: "json_object" }
          }),
          signal: controller.signal
        });
        clearTimeout(timeout);
        lastMistralCall = Date.now();
        if (response.status === 429) { await sleep(config.MISTRAL_RETRY_BASE_MS * Math.pow(2, attempt)); attempt++; continue; }
        if (!response.ok) throw new Error(`Mistral ${response.status}`);
        const data = await response.json();
        job.resolve(data.choices?.[0]?.message?.content || "");
        success = true;
      } catch (err) {
        lastError = err.name === "AbortError" ? new Error("Timeout") : err;
        attempt++;
        if (attempt <= config.MISTRAL_MAX_RETRIES) await sleep(config.MISTRAL_RETRY_BASE_MS * attempt);
      }
    }
    if (!success) job.reject(lastError || new Error("Gagal"));
  }
  mistralProcessing = false;
}

function safeParseJSON(text) {
  if (!text) return null;
  try { return JSON.parse(String(text).replace(/```json\s*/gi, "").replace(/```/g, "").trim()); } 
  catch { const m = String(text).match(/\{[\s\S]*\}/); if (m) { try { return JSON.parse(m[0]); } catch {} } return null; }
}

function regexDetect(content) {
  const t = content.toLowerCase();
  const judol = ["slot", "togel", "toto", "gacor", "maxwin", "rtp", "scatter", "jackpot", "sbobet", "casino", "judi", "taruhan", "bandar", "situs slot", "link slot", "bonus slot", "depo", "wd", "withdraw"];
  if (/\b(situs\s+slot|link\s+slot|slot\s+gacor|slot\s+maxwin|rtp\s+slot|bonus\s+new\s+member|deposit\s+pulsa|judi\s+online|bandar\s+judi|togel\s+online|slot\s+online|jp\s+maxwin)\b/.test(t) || judol.filter(k => t.includes(k)).length >= 2) return { spam: true, category: "judol", severity: "high", reason: "Kata kunci judi" };
  if (/\b(anjing|babi|kontol|memek|bangsat|goblok|tolol|idiot|bajingan|kampret|asu|jancok|jancuk|kimak|pukimak|ngentot|ngehe|tai|tahi|berengsek)\b/.test(t)) return { spam: true, category: "toxic", severity: "high", reason: "Kata kotor" };
  return null;
}

async function aiDetectSpam(content, recentMessages) {
  const rx = regexDetect(content);
  if (rx) return { ...rx, source: "regex" };
  const sys = `Balas HANYA JSON: {"spam": true/false, "reason": "alasan", "severity": "low|medium|high", "category": "judol|toxic|sara|ancaman|porno|doxx|spam|none"}`;
  try {
    const raw = await callMistral([{ role: "system", content: sys }, { role: "user", content: `Pesan: "${content.slice(0,600)}"` }], { temperature: 0.0, maxTokens: 200 });
    const p = safeParseJSON(raw);
    return p ? { spam: p.spam, reason: String(p.reason||""), severity: p.severity||"low", category: p.category||"none" } : { spam: false };
  } catch { return { spam: false }; }
}

async function aiReviewReport(content, reportReason) {
  const r = regexDetect(content);
  if (r) return { violation: true, reason: r.reason, category: r.category };
  try {
    const raw = await callMistral([{ role: "system", content: `Balas JSON: {"violation": true/false, "reason": "alasan", "category": "string"}` }, { role: "user", content: `Pesan: "${content.slice(0,800)}"\nLaporan: "${reportReason}"` }], { temperature: 0.0, maxTokens: 200 });
    const p = safeParseJSON(raw);
    return { violation: !!p?.violation, reason: String(p?.reason||""), category: String(p?.category||"none") };
  } catch { return { violation: false, category: "none" }; }
}

async function aiReviewAppeal(appeal) {
  const userMsgs = Array.from(db.messages.values()).filter(m => m.from === appeal.username && m.type === "text").slice(-15).map(m => m.content.slice(0,150));
  const hasViol = userMsgs.some(m => regexDetect(m));
  try {
    const raw = await callMistral([{ role: "system", content: `Setujui jika mengakui/penjelasan logis. Balas JSON: {"approved": true/false, "reason": "alasan"}` }, { role: "user", content: `Ban: ${appeal.banReason}\nPesan:\n${userMsgs.join("\n")}\nKronologi:\n"""${(appeal.chronology||"").slice(0,1500)}"""` }], { temperature: 0.1, maxTokens: 250 });
    const p = safeParseJSON(raw);
    return { approved: !!p?.approved, reason: String(p?.reason||"") };
  } catch { return { approved: !hasViol, reason: "Evaluasi fallback." }; }
}

/* ============ DB & OPTIMIZATION ============ */
const moderationQueue = [];
let moderationProcessing = false;
function enqueueModeration(task) { moderationQueue.push(task); processModerationQueue(); }
async function processModerationQueue() {
  if (moderationProcessing) return;
  moderationProcessing = true;
  while (moderationQueue.length > 0) { try { await moderationQueue.shift()(); } catch (err) {} }
  moderationProcessing = false;
}

let db = {
  users: {}, usersById: {}, sessions: {}, banSessions: {}, blocks: [], reports: [], appeals: [], moderationLog: [], savedContacts: {},
  statuses: [], groups: [], 
  messages: new Map(), 
  conversations: {}, 
  groupMessages: {}, 
  pendingDeliveries: {} 
};

let saveTimer = null;
function scheduleSave() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    setImmediate(() => {
      try {
        const arrMessages = Array.from(db.messages.values());
        const data = {
          users: db.users, messages: arrMessages, sessions: db.sessions, banSessions: db.banSessions,
          blocks: db.blocks, reports: db.reports, appeals: db.appeals, moderationLog: db.moderationLog, savedContacts: db.savedContacts,
          statuses: db.statuses, groups: db.groups
        };
        fs.writeFile(DATA_FILE + ".tmp", JSON.stringify(data), (err) => {
          if (!err) fs.rename(DATA_FILE + ".tmp", DATA_FILE, () => {});
        });
      } catch (e) { console.error("[DB] Save gagal:", e.message); }
    });
  }, 3000); 
}

function loadDB() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const saved = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
      db.users = saved.users || {};
      db.sessions = saved.sessions || {};
      db.banSessions = saved.banSessions || {};
      db.blocks = saved.blocks || [];
      db.reports = saved.reports || [];
      db.appeals = saved.appeals || [];
      db.moderationLog = saved.moderationLog || [];
      db.savedContacts = saved.savedContacts || {};
      db.statuses = saved.statuses || [];
      db.groups = saved.groups || [];

      for (const [u, data] of Object.entries(db.users)) db.usersById[data.id] = u;
      
      if (Array.isArray(saved.messages)) {
        for (const m of saved.messages) {
          db.messages.set(m.id, m); 
          if (m.groupId) {
            if (!db.groupMessages[m.groupId]) db.groupMessages[m.groupId] = [];
            db.groupMessages[m.groupId].push(m);
          } else {
            const convKey = [m.fromId, m.toId].sort().join("_");
            if (!db.conversations[convKey]) db.conversations[convKey] = [];
            db.conversations[convKey].push(m);
            if (m.status === "sent") {
              if (!db.pendingDeliveries[m.toId]) db.pendingDeliveries[m.toId] = [];
              db.pendingDeliveries[m.toId].push(m);
            }
          }
        }
      }
    }
  } catch (e) { console.error("[DB] Baca gagal:", e.message); }

  const devKey = Object.keys(db.users).find(n => n.toLowerCase() === config.DEV_USERNAME.toLowerCase());
  if (!devKey) {
    const salt = crypto.randomBytes(16).toString("hex");
    const dev = {
      id: makeUserId(), username: config.DEV_USERNAME, passwordSalt: salt, passwordHash: hashPassword(config.DEV_PASSWORD, salt),
      role: "developer", verified: true, banned: false, tempBanned: false, tempBanUntil: 0, tempBanReason: "",
      tempBanStrikes: 0, lastOffenseAt: 0, spamFlags: 0, lastSpamFlagAt: 0, bio: "Developer", createdAt: new Date().toISOString()
    };
    db.users[config.DEV_USERNAME] = dev;
    db.usersById[dev.id] = config.DEV_USERNAME;
    scheduleSave();
  }
}

/* ============ AUTH & UTILS ============ */
function hashPassword(password, salt) { return crypto.scryptSync(password, salt, 64).toString("hex"); }
function verifyPassword(password, user) {
  const a = Buffer.from(hashPassword(password, user.passwordSalt), "hex");
  const b = Buffer.from(user.passwordHash, "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function makeId(len = 12) { return crypto.randomBytes(len).toString("hex"); }
function makeUserId() {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  for (let i = 0; i < 5000; i++) {
    let id = "Rz"; for (let j = 0; j < 12; j++) id += chars[Math.floor(Math.random() * chars.length)];
    if (!db.usersById[id]) return id;
  }
  throw new Error("ID full");
}
function parseCookies(req) {
  const r = {};
  for (const p of (req.headers.cookie || "").split(";")) {
    const i = p.indexOf("="); if (i < 0) continue;
    const k = p.slice(0, i).trim(), v = p.slice(i + 1).trim();
    try { r[k] = decodeURIComponent(v); } catch { r[k] = v; }
  }
  return r;
}
function getCurrentUser(req) {
  let token = req.headers["authorization"] ? req.headers["authorization"].replace("Bearer ", "") : null;
  if (!token) token = parseCookies(req)["ranzchat_session"];
  
  if (!token) return null;
  const s = db.sessions[token];
  if (!s || s.expiresAt < Date.now()) { if (s) delete db.sessions[token]; return null; }
  const u = db.users[s.username];
  if (!u || u.banned || isTempBanned(u)) return null;
  return u;
}
function createSession(res, username) {
  const t = makeId(32);
  db.sessions[t] = { username, expiresAt: Date.now() + SESSION_DAYS * 86400000 };
  scheduleSave();
  res.setHeader("Set-Cookie", `ranzchat_session=${encodeURIComponent(t)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}`);
  return t;
}
function clearSession(req, res) {
  const token = req.headers["authorization"] ? req.headers["authorization"].replace("Bearer ", "") : parseCookies(req)["ranzchat_session"];
  if (token && db.sessions[token]) { delete db.sessions[token]; scheduleSave(); }
  res.setHeader("Set-Cookie", `ranzchat_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
}
function createBanSession(username) {
  for (const [t, s] of Object.entries(db.banSessions)) if (s.username === username) delete db.banSessions[t];
  const t = makeId(24);
  db.banSessions[t] = { username, expiresAt: Date.now() + 7 * 86400000 };
  scheduleSave(); return t;
}
function getBanSession(token) {
  const s = db.banSessions[token];
  if (!s || s.expiresAt < Date.now()) return null;
  return s;
}

/* ============ BAN LOGIC ============ */
function isTempBanned(user) {
  if (!user.tempBanned) return false;
  if (Date.now() >= user.tempBanUntil) {
    user.tempBanned = false; user.tempBanUntil = 0; user.tempBanReason = ""; scheduleSave(); return false;
  }
  return true;
}

function removeMessageById(id) {
  const msg = db.messages.get(id);
  if (!msg) return;
  db.messages.delete(id);
  if (msg.groupId) {
    if (db.groupMessages[msg.groupId]) db.groupMessages[msg.groupId] = db.groupMessages[msg.groupId].filter(m => m.id !== id);
    const g = db.groups.find(x => x.id === msg.groupId);
    if (g) g.members.forEach(uid => broadcastToUser(db.usersById[uid], { type: "message_deleted", messageId: id, groupId: msg.groupId }));
  } else {
    const convKey = [msg.fromId, msg.toId].sort().join("_");
    if (db.conversations[convKey]) db.conversations[convKey] = db.conversations[convKey].filter(m => m.id !== id);
    if (db.pendingDeliveries[msg.toId]) db.pendingDeliveries[msg.toId] = db.pendingDeliveries[msg.toId].filter(m => m.id !== id);
    broadcastToUser(msg.from, { type: "message_deleted", messageId: id });
    broadcastToUser(msg.to, { type: "message_deleted", messageId: id });
  }
  scheduleSave();
}

function recordSpamFlag(username, reason) {
  const user = db.users[username];
  if (!user) return;
  if (user.lastSpamFlagAt && Date.now() - user.lastSpamFlagAt > AI_RULES.flagResetMs) user.spamFlags = 0;
  user.spamFlags = (user.spamFlags || 0) + 1;
  user.lastSpamFlagAt = Date.now();
  scheduleSave();

  if (user.spamFlags >= AI_RULES.spamFlagThreshold) {
    applyTempBan(username, `Akumulasi pelanggaran: ${reason}`);
    return;
  }
  broadcastToUser(username, { type: "spam_warning", count: user.spamFlags, threshold: AI_RULES.spamFlagThreshold, reason });
}

function applyTempBan(username, reason) {
  const user = db.users[username];
  if (!user) return;
  if (user.lastOffenseAt && Date.now() - user.lastOffenseAt > AI_RULES.resetStrikeMs) user.tempBanStrikes = 0;
  user.tempBanStrikes = (user.tempBanStrikes || 0) + 1;
  const duration = Math.min(AI_RULES.baseBanMs * Math.pow(3, user.tempBanStrikes - 1), AI_RULES.maxBanMs);
  user.tempBanned = true; user.tempBanUntil = Date.now() + duration; user.tempBanReason = reason;
  user.lastOffenseAt = Date.now(); user.spamFlags = 0;

  for (const [t, s] of Object.entries(db.sessions)) if (s.username === username) delete db.sessions[t];
  db.appeals = db.appeals.filter(a => a.username !== username); 

  db.moderationLog.unshift({ id: makeId(8), username, type: "auto_temp_ban", reason, strike: user.tempBanStrikes, durationMs: duration, createdAt: new Date().toISOString(), expiresAt: new Date(user.tempBanUntil).toISOString(), status: "active" });
  scheduleSave();

  const banToken = createBanSession(username);
  broadcastToUser(username, { type: "account_temp_banned", reason, until: user.tempBanUntil, strike: user.tempBanStrikes, banToken, appeal: null });
}

function finalizeAppeal(appeal, approved, reason, decider) {
  appeal.status = approved ? "approved" : "rejected";
  appeal.decision = approved ? "approve" : "reject";
  appeal.aiReason = reason; appeal.decidedAt = new Date().toISOString(); appeal.decidedBy = decider;

  const user = db.users[appeal.username];
  if (user && approved) {
    user.tempBanned = false; user.tempBanUntil = 0; user.tempBanReason = ""; user.tempBanStrikes = 0; user.spamFlags = 0;
  }
  db.moderationLog.unshift({ id: makeId(8), username: appeal.username, type: "appeal_decided", decision: appeal.decision, reason, decider, createdAt: new Date().toISOString() });
  scheduleSave();
  broadcastToUser(appeal.username, { type: "appeal_update", appealId: appeal.id, status: appeal.status, decision: appeal.decision, reason });
}

setInterval(async () => {
  const now = Date.now();
  for (const appeal of db.appeals) {
    if (appeal.status !== "pending") continue;
    const user = db.users[appeal.username];
    if (user && !user.banned && !isTempBanned(user)) {
      appeal.status = "expired"; appeal.decidedAt = new Date().toISOString(); appeal.aiReason = "Pemblokiran habis.";
      scheduleSave(); broadcastToUser(appeal.username, { type: "appeal_update", appealId: appeal.id, status: "expired", decision: null, reason: appeal.aiReason });
      continue;
    }
    if (user && isTempBanned(user) && now >= appeal.autoReviewAt) {
      aiReviewAppeal(appeal).then(res => {
        const fresh = db.appeals.find(a => a.id === appeal.id);
        if (fresh && fresh.status === "pending") finalizeAppeal(fresh, res.approved, res.reason, "ai-mistral");
      });
    }
  }
}, 4000);

function checkReportThreshold(messageId) {
  const message = db.messages.get(messageId);
  if (!message || reportReviewTriggered.has(messageId)) return;
  const reporters = new Set();
  for (const r of db.reports) if (r.messageId === messageId) reporters.add(r.by);
  const threshold = message.type === "text" ? REPORT_THRESHOLDS.text : REPORT_THRESHOLDS.media;
  
  if (reporters.size >= threshold) {
    reportReviewTriggered.add(messageId);
    enqueueModeration(async () => {
      const verdict = await aiReviewReport(message.content, "Banyak laporan");
      if (verdict.violation) {
        applyTempBan(message.from, `Dilaporkan ${reporters.size}x & terbukti: ${verdict.reason}`);
        for (const r of db.reports) if (r.messageId === messageId) broadcastToUser(r.by, { type: "report_result", ok: true, message: `Laporan diverifikasi AI.` });
      } else {
        for (const r of db.reports) if (r.messageId === messageId) broadcastToUser(r.by, { type: "report_result", ok: false, message: `Pesan tidak melanggar.` });
      }
    });
  }
}

/* ============ HTTP HELPERS ============ */
function sendJSON(res, status, data) {
  if (res.writableEnded || res.headersSent) return;
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "Access-Control-Allow-Origin": "*" });
  res.end(JSON.stringify(data));
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "", size = 0;
    req.on("data", c => { size += c.length; if (size > MAX_BODY_SIZE) { reject(new Error("BODY_LARGE")); req.destroy(); return; } data += c.toString("utf8"); });
    req.on("end", () => { if (!data) return resolve({}); try { resolve(JSON.parse(data)); } catch { reject(new Error("INVALID_JSON")); } });
    req.on("error", reject);
  });
}
function requireLogin(req, res) {
  const u = getCurrentUser(req);
  if (!u) { sendJSON(res, 401, { success: false, error: "Login.", sessionInvalid: true }); return null; }
  return u;
}
function requireDeveloper(req, res) {
  const u = requireLogin(req, res); if (!u) return null;
  if (u.role !== "developer") { sendJSON(res, 403, { success: false, error: "Dev only." }); return null; }
  return u;
}
function publicUser(u) {
  return { id: u.id, username: u.username, role: u.role, verified: !!u.verified, bio: u.bio || "", createdAt: u.createdAt, online: isOnline(u.username), banned: !!u.banned, tempBanned: !!(u.tempBanned && Date.now() < u.tempBanUntil), tempBanUntil: u.tempBanUntil || 0, tempBanReason: u.tempBanReason || "", tempBanStrikes: u.tempBanStrikes || 0, spamFlags: u.spamFlags || 0 };
}
function isOnline(username) { return !!(sockets.get(username)?.size > 0); }
function isBlocked(a, b) { return db.blocks.some(i => (i.by === a && i.username === b) || (i.by === b && i.username === a)); }
function getUsernameById(id) { return db.usersById[id] || null; }

function markDeliveredFor(userId) {
  const pending = db.pendingDeliveries[userId];
  if (!pending || pending.length === 0) return;
  let changed = false;
  for (const m of pending) {
    if (m.status === "sent") { m.status = "delivered"; changed = true; broadcastToUser(m.from, { type: "message_status", messageId: m.id, status: "delivered" }); }
  }
  db.pendingDeliveries[userId] = [];
  if (changed) scheduleSave();
}

function markReadBetween(userAId, userBId) {
  const convKey = [userAId, userBId].sort().join("_");
  const msgs = db.conversations[convKey] || [];
  let changed = false;
  for (const m of msgs) {
    if (m.fromId === userBId && m.toId === userAId && m.status !== "read") {
      m.status = "read"; changed = true;
      broadcastToUser(m.from, { type: "message_status", messageId: m.id, status: "read" });
    }
  }
  if (changed) scheduleSave();
}

/* ============ HTTP SERVER ============ */
const server = http.createServer(async (req, res) => {
  if (req.method === "OPTIONS") {
    res.writeHead(204, { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, Authorization" });
    return res.end();
  }

  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const route = url.pathname;

  if (req.method === "GET" && (route === "/" || route === "/index.html")) {
    if (!fs.existsSync(HTML_FILE)) { res.writeHead(404); return res.end("No html"); }
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
    return fs.createReadStream(HTML_FILE).pipe(res);
  }
  if (route === "/favicon.ico") { res.writeHead(204); return res.end(); }

  try {
    if (req.method === "POST" && route === "/api/register") {
      const body = await readBody(req);
      const username = String(body.username || "").trim(), password = String(body.password || "");
      if (!/^[a-zA-Z0-9_.-]{3,24}$/.test(username) || password.length < 8 || Object.keys(db.users).some(n => n.toLowerCase() === username.toLowerCase()))
        return sendJSON(res, 400, { success: false, error: "Validasi gagal." });
      
      const salt = crypto.randomBytes(16).toString("hex");
      const user = { id: makeUserId(), username, passwordSalt: salt, passwordHash: hashPassword(password, salt), role: "user", verified: false, banned: false, tempBanned: false, tempBanUntil: 0, tempBanReason: "", tempBanStrikes: 0, lastOffenseAt: 0, spamFlags: 0, lastSpamFlagAt: 0, bio: "", createdAt: new Date().toISOString() };
      db.users[username] = user; db.usersById[user.id] = username; scheduleSave(); 
      const token = createSession(res, username);
      return sendJSON(res, 201, { success: true, user: publicUser(user), token });
    }

    if (req.method === "POST" && route === "/api/login") {
      const body = await readBody(req);
      const username = String(body.username || "").trim(), password = String(body.password || "");
      const key = Object.keys(db.users).find(n => n.toLowerCase() === username.toLowerCase());
      const user = key ? db.users[key] : null;
      if (!user || !verifyPassword(password, user)) return sendJSON(res, 401, { success: false, error: "Login gagal." });
      if (user.banned) return sendJSON(res, 403, { success: false, permanentBan: true, error: "Banned permanen." });
      
      if (isTempBanned(user)) {
        const banToken = createBanSession(key);
        const app = db.appeals.filter(a => a.username === key && (a.status === "pending" || a.status === "rejected")).sort((a,b) => new Date(b.createdAt)-new Date(a.createdAt))[0];
        return sendJSON(res, 429, { success: false, tempBanned: true, reason: user.tempBanReason, until: user.tempBanUntil, strike: user.tempBanStrikes, banToken, appeal: app ? { id: app.id, status: app.status, decision: app.decision, aiReason: app.aiReason } : null });
      }
      
      const token = createSession(res, key); markDeliveredFor(user.id);
      return sendJSON(res, 200, { success: true, user: publicUser(user), token });
    }

    if (req.method === "POST" && route === "/api/logout") { clearSession(req, res); return sendJSON(res, 200, { success: true }); }

    if (req.method === "GET" && route === "/api/me") {
      const user = getCurrentUser(req);
      if (!user) return sendJSON(res, 401, { success: false, sessionInvalid: true });
      return sendJSON(res, 200, { success: true, user: publicUser(user) });
    }

    if (req.method === "GET" && route === "/api/ban/check") {
      const sess = getBanSession(url.searchParams.get("token") || "");
      if (!sess) return sendJSON(res, 401, { success: false });
      const user = db.users[sess.username];
      const app = db.appeals.filter(a => a.username === sess.username && (a.status === "pending" || a.status === "rejected")).sort((a,b) => new Date(b.createdAt)-new Date(a.createdAt))[0];
      return sendJSON(res, 200, { success: true, banned: isTempBanned(user), reason: user.tempBanReason, until: user.tempBanUntil, strike: user.tempBanStrikes, appeal: app ? { id: app.id, status: app.status, decision: app.decision, aiReason: app.aiReason } : null });
    }

    if (req.method === "POST" && route === "/api/appeal") {
      const b = await readBody(req);
      const sess = getBanSession(String(b.banToken || ""));
      if (!sess) return sendJSON(res, 401, { success: false });
      const chronology = String(b.chronology || "").trim();
      if (chronology.length < 40) return sendJSON(res, 400, { success: false, error: "Min 40 karakter." });
      const user = db.users[sess.username];
      if (!isTempBanned(user)) return sendJSON(res, 400, { success: false, error: "Tidak dibanned." });
      
      const app = { id: makeId(10), username: sess.username, banReason: user.tempBanReason, banStrike: user.tempBanStrikes, banUntil: user.tempBanUntil, chronology, status: "pending", createdAt: new Date().toISOString(), autoReviewAt: Date.now() + APPEAL_MIN_MS + Math.random() * (APPEAL_MAX_MS - APPEAL_MIN_MS) };
      db.appeals.push(app); scheduleSave();
      return sendJSON(res, 201, { success: true, appeal: { id: app.id, status: app.status } });
    }

    if (req.method === "GET" && route === "/api/appeal/status") {
      const sess = getBanSession(url.searchParams.get("token") || "");
      if (!sess) return sendJSON(res, 401, { success: false });
      const user = db.users[sess.username];
      const app = db.appeals.filter(a => a.username === sess.username && (a.status === "pending" || a.status === "rejected")).sort((a,b) => new Date(b.createdAt)-new Date(a.createdAt))[0];
      return sendJSON(res, 200, { success: true, banned: isTempBanned(user), reason: user.tempBanReason, until: user.tempBanUntil, appeal: app ? { id: app.id, status: app.status, decision: app.decision, aiReason: app.aiReason } : null });
    }

    if (req.method === "GET" && route === "/api/contacts") {
      const user = requireLogin(req, res); if (!user) return;
      const savedList = db.savedContacts[user.username] || [];
      const savedIds = new Set(savedList.map(sc => sc.contactId));
      const convPartners = new Set();
      
      for (const key in db.conversations) {
        const msgs = db.conversations[key];
        if (!msgs || !msgs.length) continue;
        const lastM = msgs[msgs.length - 1];
        if (lastM.fromId === user.id && !savedIds.has(lastM.toId)) convPartners.add(lastM.toId);
        else if (lastM.toId === user.id && !savedIds.has(lastM.fromId)) convPartners.add(lastM.fromId);
      }

      const contacts = [];
      const getLastMsg = (tid) => {
        const key = [user.id, tid].sort().join("_");
        const arr = db.conversations[key];
        return arr && arr.length ? arr[arr.length - 1] : null;
      };

      for (const sc of savedList) {
        const target = db.users[getUsernameById(sc.contactId)];
        if (!target || target.banned || isBlocked(user.username, target.username)) continue;
        const lastMsg = getLastMsg(target.id);
        const unread = (db.conversations[[user.id, target.id].sort().join("_")] || []).filter(m => m.toId === user.id && m.status !== "read").length;
        contacts.push({ ...publicUser(target), saved: true, firstName: sc.firstName, lastName: sc.lastName, lastMessage: lastMsg || null, unread });
      }

      for (const tid of convPartners) {
        const target = db.users[getUsernameById(tid)];
        if (!target || target.banned || isBlocked(user.username, target.username)) continue;
        const lastMsg = getLastMsg(target.id);
        const unread = (db.conversations[[user.id, target.id].sort().join("_")] || []).filter(m => m.toId === user.id && m.status !== "read").length;
        contacts.push({ id: target.id, online: isOnline(target.username), saved: false, lastMessage: lastMsg || null, unread });
      }
      
      contacts.sort((a,b) => {
        if (a.saved && !b.saved) return -1; if (b.saved && !a.saved) return 1;
        return (b.lastMessage ? new Date(b.lastMessage.createdAt).getTime() : 0) - (a.lastMessage ? new Date(a.lastMessage.createdAt).getTime() : 0);
      });
      return sendJSON(res, 200, { success: true, contacts });
    }

    if (req.method === "POST" && route === "/api/contacts/save") {
      const user = requireLogin(req, res); if (!user) return;
      const body = await readBody(req);
      const targetU = db.users[getUsernameById(body.contactId)];
      if (!targetU || targetU.username === user.username) return sendJSON(res, 400, { success: false, error: "ID salah." });
      if (!db.savedContacts[user.username]) db.savedContacts[user.username] = [];
      const ex = db.savedContacts[user.username].find(sc => sc.contactId === targetU.id);
      if (ex) { ex.firstName = body.firstName; ex.lastName = body.lastName; }
      else { db.savedContacts[user.username].push({ id: makeId(8), firstName: body.firstName, lastName: body.lastName, contactId: targetU.id, createdAt: new Date().toISOString() }); }
      scheduleSave(); return sendJSON(res, 201, { success: true });
    }

    if (req.method === "GET" && route === "/api/users/search") {
      const user = requireLogin(req, res); if (!user) return;
      const q = String(url.searchParams.get("q") || "").trim().toLowerCase();
      if (!q) return sendJSON(res, 200, { success: true, users: [] });
      const savedIds = new Set((db.savedContacts[user.username] || []).map(sc => sc.contactId));
      const results = Object.values(db.users).filter(o => !o.banned && o.username !== user.username && !isBlocked(user.username, o.username) && (o.username.toLowerCase().includes(q) || o.id.toLowerCase().includes(q)))
        .slice(0, 30).map(o => ({ ...publicUser(o), saved: savedIds.has(o.id) }));
      return sendJSON(res, 200, { success: true, users: results });
    }

    if (req.method === "GET" && route === "/api/messages") {
      const user = requireLogin(req, res); if (!user) return;
      const targetU = db.users[getUsernameById(url.searchParams.get("userId"))];
      if (!targetU) return sendJSON(res, 404, { success: false });
      
      markReadBetween(user.id, targetU.id);
      const convKey = [user.id, targetU.id].sort().join("_");
      
      const msgs = db.conversations[convKey] || [];
      return sendJSON(res, 200, { success: true, messages: msgs });
    }

    if (req.method === "GET" && route === "/api/group_messages") {
      const user = requireLogin(req, res); if (!user) return;
      const gid = url.searchParams.get("groupId");
      const g = db.groups.find(x => x.id === gid);
      if (!g || !g.members.includes(user.id)) return sendJSON(res, 403, { success: false });
      
      const msgs = db.groupMessages[gid] || [];
      return sendJSON(res, 200, { success: true, messages: msgs });
    }

    if (req.method === "GET" && route === "/api/status") {
      const user = requireLogin(req, res); if (!user) return;
      const savedIds = new Set((db.savedContacts[user.username] || []).map(sc => sc.contactId));
      const valid = db.statuses.filter(s => (s.userId === user.id || savedIds.has(s.userId)) && (Date.now() - s.createdAt < 24*60*60*1000));
      return sendJSON(res, 200, { success: true, statuses: valid });
    }

    if (req.method === "POST" && route === "/api/status") {
      const user = requireLogin(req, res); if (!user) return;
      const body = await readBody(req);
      if (!body.content) return sendJSON(res, 400, { success: false });
      const newStatus = { id: makeId(12), userId: user.id, username: user.username, type: body.type || "image", content: body.content, createdAt: Date.now() };
      db.statuses.push(newStatus);
      scheduleSave();
      return sendJSON(res, 201, { success: true, status: newStatus });
    }

    if (req.method === "GET" && route === "/api/groups") {
      const user = requireLogin(req, res); if (!user) return;
      const groups = db.groups.filter(g => g.members.includes(user.id)).map(g => {
        const msgs = db.groupMessages[g.id] || [];
        const lastMsg = msgs.length ? msgs[msgs.length - 1] : null;
        return { id: g.id, name: g.name, lastMessage: lastMsg, membersCount: g.members.length };
      });
      return sendJSON(res, 200, { success: true, groups });
    }

    if (req.method === "POST" && route === "/api/groups") {
      const user = requireLogin(req, res); if (!user) return;
      const body = await readBody(req);
      if (!body.name || !body.members) return sendJSON(res, 400, { success: false });
      const g = {
        id: makeId(10), name: body.name.trim(), creatorId: user.id,
        admins: [user.id], members: [...new Set([user.id, ...body.members])], createdAt: Date.now()
      };
      db.groups.push(g); scheduleSave();
      return sendJSON(res, 201, { success: true, group: g });
    }

    if (req.method === "GET" && route === "/api/groups/info") {
      const user = requireLogin(req, res); if (!user) return;
      const gid = url.searchParams.get("groupId");
      const g = db.groups.find(x => x.id === gid);
      if (!g) return sendJSON(res, 404, { success: false });
      const members = g.members.map(id => {
        const u = db.users[getUsernameById(id)];
        return u ? { ...publicUser(u), isAdmin: g.admins.includes(id) } : null;
      }).filter(Boolean);
      return sendJSON(res, 200, { success: true, group: { ...g, membersData: members } });
    }

    if (req.method === "POST" && route === "/api/groups/promote") {
      const user = requireLogin(req, res); if (!user) return;
      const b = await readBody(req);
      const g = db.groups.find(x => x.id === b.groupId);
      if (!g || !g.admins.includes(user.id)) return sendJSON(res, 403, { success: false, error: "Bukan admin." });
      if (b.action === "add" && !g.admins.includes(b.userId)) g.admins.push(b.userId);
      if (b.action === "remove") g.admins = g.admins.filter(id => id !== b.userId);
      scheduleSave();
      return sendJSON(res, 200, { success: true });
    }

    if (req.method === "POST" && route === "/api/groups/leave") {
      const user = requireLogin(req, res); if (!user) return;
      const b = await readBody(req);
      const g = db.groups.find(x => x.id === b.groupId);
      if (!g) return sendJSON(res, 404, { success: false });
      
      g.members = g.members.filter(id => id !== user.id);
      g.admins = g.admins.filter(id => id !== user.id);
      
      const sysMsg = { id: makeId(12), groupId: g.id, from: user.username, fromId: user.id, type: "system", content: `${user.username} keluar dari grup`, createdAt: new Date().toISOString() };
      db.messages.set(sysMsg.id, sysMsg);
      if (!db.groupMessages[g.id]) db.groupMessages[g.id] = [];
      db.groupMessages[g.id].push(sysMsg);
      
      scheduleSave();
      g.members.forEach(uid => broadcastToUser(db.usersById[uid], { type: "new_message", message: sysMsg }));
      
      return sendJSON(res, 200, { success: true });
    }

    if (req.method === "POST" && route === "/api/messages") {
      const user = requireLogin(req, res); if (!user) return;
      if (isTempBanned(user)) return sendJSON(res, 429, { success: false, tempBanned: true, error: "Diblokir." });

      const body = await readBody(req);
      const content = String(body.content || "").trim();
      if (!content) return sendJSON(res, 400, { success: false, error: "Kosong." });
      const type = ["image", "video"].includes(body.type) ? body.type : "text";

      let message, isGroup = false, targetUsers = [];

      if (body.groupId) {
        isGroup = true;
        const g = db.groups.find(x => x.id === body.groupId);
        if (!g || !g.members.includes(user.id)) return sendJSON(res, 403, { success: false });
        
        message = { id: makeId(12), groupId: g.id, from: user.username, fromId: user.id, type, content, createdAt: new Date().toISOString() };
        targetUsers = g.members.map(id => db.usersById[id]).filter(Boolean);
      } else {
        const targetU = db.users[getUsernameById(body.userId)];
        if (!targetU || targetU.username === user.username) return sendJSON(res, 400, { success: false, error: "Tujuan salah." });
        if (isBlocked(user.username, targetU.username)) return sendJSON(res, 403, { success: false, error: "Diblokir." });
        
        message = { id: makeId(12), from: user.username, fromId: user.id, to: targetU.username, toId: targetU.id, type, content, status: isOnline(targetU.username) ? "delivered" : "sent", createdAt: new Date().toISOString() };
        targetUsers = [targetU.username];
      }

      db.messages.set(message.id, message);
      if (isGroup) {
        if (!db.groupMessages[message.groupId]) db.groupMessages[message.groupId] = [];
        db.groupMessages[message.groupId].push(message);
      } else {
        const convKey = [user.id, message.toId].sort().join("_");
        if (!db.conversations[convKey]) db.conversations[convKey] = [];
        db.conversations[convKey].push(message);
        if (message.status === "sent") {
          if (!db.pendingDeliveries[message.toId]) db.pendingDeliveries[message.toId] = [];
          db.pendingDeliveries[message.toId].push(message);
        }
      }

      scheduleSave();
      
      broadcastToUser(user.username, { type: "new_message", message });
      targetUsers.forEach(t => { if (t !== user.username) broadcastToUser(t, { type: "new_message", message }); });

      sendJSON(res, 201, { success: true, message });

      if (type === "text") {
        enqueueModeration(async () => {
          const tracker = spamTracker.get(user.username) || { recent: [], longRecent: [], lastContent: null, sameCount: 0 };
          const now = Date.now();
          tracker.recent = tracker.recent.filter(ts => now - ts < AI_RULES.windowMs); tracker.recent.push(now);
          tracker.longRecent = tracker.longRecent.filter(ts => now - ts < AI_RULES.longBurstWindowMs); tracker.longRecent.push(now);
          if (content === tracker.lastContent) tracker.sameCount++; else { tracker.lastContent = content; tracker.sameCount = 1; }
          spamTracker.set(user.username, tracker);

          let ruleViolation = null;
          if (tracker.recent.length > AI_RULES.maxInWindow) ruleViolation = `Flood.`;
          else if (tracker.sameCount >= AI_RULES.repeatLimit) ruleViolation = `Spam.`;
          
          if (ruleViolation) {
            tracker.recent = []; tracker.longRecent = []; tracker.sameCount = 0; tracker.lastContent = null;
            removeMessageById(message.id); recordSpamFlag(user.username, ruleViolation);
            return;
          }

          try {
            const recent = Array.from(db.messages.values()).filter(m => m.from === user.username && m.type === "text" && m.id !== message.id).slice(-5).map(m => m.content);
            const v = await aiDetectSpam(content, recent);
            if (v.spam) {
              removeMessageById(message.id);
              if (AI_RULES.immediateBlockCategories.includes(v.category) || AI_RULES.immediateBlockSeverities.includes(v.severity)) {
                applyTempBan(user.username, `Konten ${v.category}: ${v.reason}`);
              } else {
                recordSpamFlag(user.username, `AI: ${v.reason}`);
              }
            }
          } catch {}
        });
      }
    }

    if (req.method === "POST" && route === "/api/messages/delete") {
      const user = requireLogin(req, res); if (!user) return;
      const id = String((await readBody(req)).messageId || "");
      const msg = db.messages.get(id);
      if (!msg) return sendJSON(res, 404, { success: false });
      if (msg.fromId !== user.id && user.role !== "developer") return sendJSON(res, 403, { success: false });
      removeMessageById(id); return sendJSON(res, 200, { success: true });
    }

    if (req.method === "POST" && route === "/api/profile") {
      const user = requireLogin(req, res); if (!user) return;
      const body = await readBody(req);
      if (body.username && body.username !== user.username) {
        if (!/^[a-zA-Z0-9_.-]{3,24}$/.test(body.username) || db.users[body.username]) return sendJSON(res, 400, { success: false });
        const old = user.username; delete db.users[old]; db.users[body.username] = user; user.username = body.username; db.usersById[user.id] = body.username;
        for (const m of db.messages.values()) { if (m.from === old) m.from = body.username; if (m.to === old) m.to = body.username; }
        if (db.savedContacts[old]) { db.savedContacts[body.username] = db.savedContacts[old]; delete db.savedContacts[old]; }
      }
      if (body.bio !== undefined) user.bio = String(body.bio).slice(0, 160);
      scheduleSave(); return sendJSON(res, 200, { success: true, user: publicUser(user) });
    }

    if (req.method === "POST" && route === "/api/block") {
      const user = requireLogin(req, res); if (!user) return;
      const target = db.users[getUsernameById((await readBody(req)).userId)];
      if (target && target.username !== user.username && !isBlocked(user.username, target.username)) {
        db.blocks.push({ by: user.username, username: target.username, createdAt: new Date().toISOString() }); scheduleSave();
      }
      return sendJSON(res, 200, { success: true });
    }

    if (route.startsWith("/api/developer")) {
      const dev = requireDeveloper(req, res); if (!dev) return;
      if (route === "/api/developer/users") return sendJSON(res, 200, { users: Object.values(db.users).map(publicUser) });
      if (route === "/api/developer/logs") return sendJSON(res, 200, { logs: db.moderationLog.slice(0, 100) });
      if (route === "/api/developer/reports") return sendJSON(res, 200, { reports: db.reports.slice(-100) });
      if (route === "/api/developer/appeals") return sendJSON(res, 200, { appeals: db.appeals });
      
      const b = await readBody(req);
      if (route === "/api/developer/ban") { const u = db.users[b.username]; if(u) { u.banned = true; for (const [t,s] of Object.entries(db.sessions)) if(s.username === u.username) delete db.sessions[t]; scheduleSave(); broadcastToUser(u.username, { type: "account_banned" }); } return sendJSON(res, 200, { success: true }); }
      if (route === "/api/developer/unban") { const u = db.users[b.username]; if(u) { u.banned=false; u.tempBanned=false; u.spamFlags=0; scheduleSave(); } return sendJSON(res, 200, { success: true }); }
      if (route === "/api/developer/verify") { const u = db.users[b.username]; if(u) { u.verified = b.verified !== false; scheduleSave(); } return sendJSON(res, 200, { success: true }); }
      if (route === "/api/developer/appeals/decide") { const a = db.appeals.find(x => x.id === b.appealId); if(a) finalizeAppeal(a, b.decision === "approve", b.reason || "Dev", "developer"); return sendJSON(res, 200, { success: true }); }
      return sendJSON(res, 404, { success: false });
    }

    return sendJSON(res, 404, { success: false, error: "Endpoint tidak ditemukan." });
  } catch (err) {
    if (err.message === "INVALID_JSON") return sendJSON(res, 400, { success: false, error: "JSON salah." });
    console.error(err);
    if (!res.headersSent) sendJSON(res, 500, { success: false, error: "Internal error." });
  }
});

/* ============ WEBSOCKET ============ */
const wss = new WebSocket.Server({ noServer: true, maxPayload: 25 * 1024 * 1024 });
const sockets = new Map();

server.on("upgrade", (req, socket, head) => {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  if (url.pathname !== "/ws") { socket.destroy(); return; }
  
  let token = null;
  const authHeader = req.headers["authorization"];
  if (authHeader) token = authHeader.replace("Bearer ", "");
  
  if (!token) {
    const cookies = parseCookies(req);
    token = cookies["ranzchat_session"];
  }

  const session = token ? db.sessions[token] : null;
  if (!session || session.expiresAt < Date.now()) { socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n"); socket.destroy(); return; }
  const user = db.users[session.username];
  if (!user || user.banned || isTempBanned(user)) { socket.write("HTTP/1.1 403 Forbidden\r\n\r\n"); socket.destroy(); return; }
  wss.handleUpgrade(req, socket, head, ws => { ws.userId = user.id; ws.username = user.username; ws.isAlive = true; wss.emit("connection", ws, req); });
});

wss.on("connection", ws => {
  if (!sockets.has(ws.username)) sockets.set(ws.username, new Set());
  sockets.get(ws.username).add(ws);
  ws.send(JSON.stringify({ type: "connected", username: ws.username }));
  markDeliveredFor(ws.userId);

  ws.on("pong", () => { ws.isAlive = true; });
  ws.on("message", raw => {
    try {
      const data = JSON.parse(raw.toString());
      if (data.type === "ping") ws.send(JSON.stringify({ type: "pong" }));
      if (data.type === "typing" && data.to) {
        const target = getUsernameById(data.to);
        if (target && target !== ws.username) broadcastToUser(target, { type: "typing", from: ws.username, typing: !!data.typing });
      }
    } catch {}
  });
  ws.on("close", () => {
    const c = sockets.get(ws.username);
    if (c) { c.delete(ws); if (c.size === 0) sockets.delete(ws.username); }
    broadcastToUser(ws.username, { type: "user_offline", username: ws.username });
  });
  ws.on("error", () => {});
});

setInterval(() => {
  wss.clients.forEach(ws => { if (ws.isAlive === false) return ws.terminate(); ws.isAlive = false; try { ws.ping(); } catch {} });
}, 25000);

function broadcastToUser(username, payload) {
  const clients = sockets.get(username);
  if (!clients) return;
  const msg = JSON.stringify(payload);
  for (const ws of clients) if (ws.readyState === WebSocket.OPEN) ws.send(msg);
}

/* ============ IP DETECTION & START ============ */
function cleanIP(value) {
  if (!value) return null;
  let r = String(value).trim().replace(/^https?:\/\//i, "").split("/")[0];
  if (/^\d{1,3}(?:\.\d{1,3}){3}:\d+$/.test(r)) r = r.replace(/:\d+$/, "");
  r = r.replace(/^\[|\]$/g, "");
  if (!r || r === "0.0.0.0" || r === "127.0.0.1" || r === "localhost") return null;
  return r;
}
function getAllocationIP() {
  const possible = [process.env.ALLOCATION_IP, process.env.SERVER_IP, process.env.SERVER_ADDRESS, process.env.P_SERVER_IP, process.env.SERVER_ALLOCATION_IP, process.env.ALLOCATION_ADDRESS, process.env.SERVER_NODE_IP];
  for (const v of possible) { const ip = cleanIP(v); if (ip) return ip; }
  const ifs = os.networkInterfaces();
  for (const entries of Object.values(ifs)) for (const it of entries || []) if (it.family === "IPv4" && !it.internal && it.address !== "0.0.0.0") { const ip = cleanIP(it.address); if (ip) return ip; }
  return null;
}

loadDB();
server.listen(PORT, HOST, () => {
  const ip = getAllocationIP();
  console.log(`\n==========================================\n  RANZCHAT — ZERO DELAY ENGINE (FLUTTER READY)\n==========================================\nStatus: ONLINE | Port: ${PORT}`);
  if (ip) console.log(`Detected URL : http://${ip}:${PORT}`);
  else console.log(`Local URL: http://127.0.0.1:${PORT}`);
  console.log(`Auth Mode: Bearer Token & Cookie (Dual Support)`);
  console.log(`AI Guard: BACKGROUND PROCESSING ACTIVE`);
  console.log(`==========================================\n`);
});
process.on("SIGINT", () => { saveDB(); process.exit(0); });
process.on("SIGTERM", () => { saveDB(); process.exit(0); });
