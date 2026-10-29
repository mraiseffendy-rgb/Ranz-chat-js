"use strict";
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const os = require("os");
const { spawn } = require("child_process");
const WebSocket = require("ws");
const config = require("./config.js");

const HOST = "0.0.0.0";
const PORT = Number(process.env.SERVER_PORT || process.env.PORT || process.env.SERVER_ALLOCATION_PORT || 2487);
const DATA_FILE = path.join(__dirname, "data.json");
const HTML_FILE = path.join(__dirname, "index.html");
const COOKIE_NAME = "ranzchat_session";
const SESSION_DAYS = 30;
const MAX_BODY_SIZE = 15 * 1024 * 1024;
const ENABLE_CF_TUNNEL = String(process.env.ENABLE_CF_TUNNEL || "true").toLowerCase() !== "false";
const CF_BIN = process.env.CLOUDFLARED_BIN || "cloudflared";

/* ============ AI & MODERATION RULES ============ */
const AI_RULES = {
  windowMs: 10000,
  maxInWindow: 6,
  repeatLimit: 3,
  longBurstWindowMs: 30000,
  longBurstMax: 15,
  spamFlagThreshold: 6,
  immediateBlockCategories: ["judol", "toxic", "sara", "ancaman", "porno", "doxx"],
  immediateBlockSeverities: ["high"],
  flagResetMs: 24 * 60 * 60 * 1000,
  baseBanMs: 10 * 60 * 1000,
  maxBanMs: 6 * 60 * 60 * 1000,
  resetStrikeMs: 7 * 24 * 60 * 60 * 1000
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
        if (!config.MISTRAL_API_KEY || config.MISTRAL_API_KEY.includes("mstrl_3BvMtGxX0tqexiuw2hvqZjPnTCmDSBqU_0TIwZv")) throw new Error("MISTRAL_API_KEY belum diisi");
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), config.MISTRAL_TIMEOUT_MS);
        const response = await fetch(`${config.MISTRAL_BASE_URL}/chat/completions`, {
          method: "POST",
          headers: { "Content-Type": "application/json", "Authorization": `Bearer ${config.MISTRAL_API_KEY}` },
          body: JSON.stringify({
            model: config.MISTRAL_MODEL,
            messages: job.messages,
            temperature: job.temperature,
            max_tokens: job.maxTokens,
            response_format: { type: "json_object" }
          }),
          signal: controller.signal
        });
        clearTimeout(timeout);
        lastMistralCall = Date.now();
        if (response.status === 429) {
          await sleep(config.MISTRAL_RETRY_BASE_MS * Math.pow(2, attempt));
          attempt++;
          continue;
        }
        if (!response.ok) throw new Error(`Mistral ${response.status}`);
        const data = await response.json();
        job.resolve(data.choices?.[0]?.message?.content || "");
        success = true;
      } catch (err) {
        lastError = err.name === "AbortError" ? new Error("Mistral timeout") : err;
        attempt++;
        if (attempt <= config.MISTRAL_MAX_RETRIES) await sleep(config.MISTRAL_RETRY_BASE_MS * attempt);
      }
    }
    if (!success) job.reject(lastError || new Error("Mistral gagal"));
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
  const judolMatches = judol.filter(k => t.includes(k));
  if (/\b(situs\s+slot|link\s+slot|slot\s+gacor|slot\s+maxwin|rtp\s+slot|bonus\s+new\s+member|deposit\s+pulsa|judi\s+online|bandar\s+judi|togel\s+online|slot\s+online|jp\s+maxwin|scatter\s+hitam)\b/.test(t) || judolMatches.length >= 2) {
    return { spam: true, category: "judol", severity: "high", reason: "Kata kunci judi online terdeteksi" };
  }
  if (/\b(anjing|babi|kontol|memek|bangsat|goblok|tolol|idiot|bajingan|kampret|asu|jancok|jancuk|kimak|pukimak|ngentot|ngehe|tai|tahi|berengsek|brengsek)\b/.test(t)) {
    return { spam: true, category: "toxic", severity: "high", reason: "Kata kotor terdeteksi" };
  }
  if (/\b(kafir\s+bangsat|agama\s+\w+\s+anjing|suku\s+\w+\s+babi|ras\s+\w+\s+monyet)\b/.test(t)) {
    return { spam: true, category: "sara", severity: "high", reason: "Ujaran SARA terdeteksi" };
  }
  if (/\b(saya\s+akan\s+(bunuh|hajar|gebuk|hancurkan)|akan\s+saya\s+(hack|ddos|bom)|doxx|doxing|saya\s+tahu\s+alamat(mu)?)\b/.test(t)) {
    return { spam: true, category: "ancaman", severity: "high", reason: "Ancaman terdeteksi" };
  }
  return null;
}

async function aiDetectSpam(content, recentMessages) {
  const rx = regexDetect(content);
  if (rx) return { ...rx, source: "regex" };
  const sys = `Kamu AI moderator. Balas HANYA JSON: {"spam": true/false, "reason": "alasan", "severity": "low|medium|high", "category": "judol|toxic|sara|ancaman|porno|doxx|spam|none"}`;
  const ctx = recentMessages.length ? `Riwayat: ${recentMessages.slice(-5).map(m => `"${m.slice(0,80)}"`).join("|")}` : "";
  try {
    const raw = await callMistral([{ role: "system", content: sys }, { role: "user", content: `Pesan: "${content.slice(0,600)}"\n${ctx}` }], { temperature: 0.0, maxTokens: 200 });
    const p = safeParseJSON(raw);
    if (!p || typeof p.spam !== "boolean") return { spam: false, category: "none" };
    return { spam: p.spam, reason: String(p.reason||"").slice(0,300), severity: p.severity||"low", category: p.category||"none", source: "ai" };
  } catch { return { spam: false, category: "none" }; }
}

async function aiReviewReport(content, reportReason) {
  const r = regexDetect(content);
  if (r) return { violation: true, reason: r.reason, category: r.category };
  try {
    const raw = await callMistral([{ role: "system", content: `Balas JSON: {"violation": true/false, "reason": "alasan", "category": "judol|toxic|sara|ancaman|porno|doxx|spam|none"}` }, { role: "user", content: `Pesan: "${content.slice(0,800)}"\nLaporan: "${reportReason}"` }], { temperature: 0.0, maxTokens: 200 });
    const p = safeParseJSON(raw);
    return { violation: !!p?.violation, reason: String(p?.reason||"").slice(0,300), category: String(p?.category||"none") };
  } catch { return { violation: false, category: "none" }; }
}

async function aiReviewAppeal(appeal) {
  const userMsgs = Array.from(db.messages.values()).filter(m => m.from === appeal.username && m.type === "text").slice(-15).map(m => m.content.slice(0,150));
  const hasViol = userMsgs.some(m => regexDetect(m));
  try {
    const raw = await callMistral([{ role: "system", content: `Setujui jika mengakui/penjelasan logis. Tolak jika bohong/toxic. Balas JSON: {"approved": true/false, "reason": "alasan"}` }, { role: "user", content: `Ban: ${appeal.banReason}\nPesan:\n${userMsgs.join("\n")}\nKronologi:\n"""${(appeal.chronology||"").slice(0,1500)}"""` }], { temperature: 0.1, maxTokens: 250 });
    const p = safeParseJSON(raw);
    return { approved: !!p?.approved, reason: String(p?.reason||"").slice(0,500) };
  } catch { return { approved: !hasViol && appeal.chronology.length >= 100, reason: "Evaluasi fallback." }; }
}

/* ============ BACKGROUND MODERATION QUEUE ============ */
const moderationQueue = [];
let moderationProcessing = false;
function enqueueModeration(task) { moderationQueue.push(task); processModerationQueue(); }
async function processModerationQueue() {
  if (moderationProcessing) return;
  moderationProcessing = true;
  while (moderationQueue.length > 0) {
    try { await moderationQueue.shift()(); } catch (err) {}
  }
  moderationProcessing = false;
}

/* ============ OPTIMIZED DATABASE ============ */
let db = {
  users: {},
  usersById: {},
  sessions: {},
  banSessions: {},
  blocks: [],
  reports: [],
  appeals: [],
  moderationLog: [],
  savedContacts: {},
  messages: new Map(),
  conversations: {},
  pendingDeliveries: {}
};

let saveTimer = null;
function scheduleSave() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    saveDB();
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

      for (const [u, data] of Object.entries(db.users)) db.usersById[data.id] = u;
      
      if (Array.isArray(saved.messages)) {
        for (const m of saved.messages) {
          db.messages.set(m.id, m);
          const convKey = [m.fromId, m.toId].sort().join("_");
          if (!db.conversations[convKey]) db.conversations[convKey] = [];
          db.conversations[convKey].push(m.id);
          if (m.status === "sent") {
            if (!db.pendingDeliveries[m.toId]) db.pendingDeliveries[m.toId] = [];
            db.pendingDeliveries[m.toId].push(m.id);
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
    saveDB();
  }
}

function saveDB() {
  try {
    const arrMessages = Array.from(db.messages.values());
    const data = {
      users: db.users, messages: arrMessages, sessions: db.sessions, banSessions: db.banSessions,
      blocks: db.blocks, reports: db.reports, appeals: db.appeals, moderationLog: db.moderationLog, savedContacts: db.savedContacts
    };
    fs.writeFileSync(DATA_FILE + ".tmp", JSON.stringify(data));
    fs.renameSync(DATA_FILE + ".tmp", DATA_FILE);
  } catch (e) { console.error("[DB] Save gagal:", e.message); }
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
  const token = parseCookies(req)[COOKIE_NAME];
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
  res.setHeader("Set-Cookie", `${COOKIE_NAME}=${encodeURIComponent(t)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}`);
}
function clearSession(req, res) {
  const t = parseCookies(req)[COOKIE_NAME];
  if (t && db.sessions[t]) { delete db.sessions[t]; scheduleSave(); }
  res.setHeader("Set-Cookie", `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
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
  
  const convKey = [msg.fromId, msg.toId].sort().join("_");
  if (db.conversations[convKey]) db.conversations[convKey] = db.conversations[convKey].filter(m => m !== id);
  if (db.pendingDeliveries[msg.toId]) db.pendingDeliveries[msg.toId] = db.pendingDeliveries[msg.toId].filter(m => m !== id);
  
  scheduleSave();
  broadcastToUser(msg.from, { type: "message_deleted", messageId: id });
  broadcastToUser(msg.to, { type: "message_deleted", messageId: id });
}

function recordSpamFlag(username, reason) {
  const user = db.users[username];
  if (!user) return;
  if (user.lastSpamFlagAt && Date.now() - user.lastSpamFlagAt > AI_RULES.flagResetMs) user.spamFlags = 0;
  user.spamFlags = (user.spamFlags || 0) + 1;
  user.lastSpamFlagAt = Date.now();
  scheduleSave();

  if (user.spamFlags >= AI_RULES.spamFlagThreshold) {
    applyTempBan(username, `Akumulasi ${user.spamFlags} pelanggaran: ${reason}`);
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

  db.moderationLog.unshift({ id: makeId(8), username, type: "auto_temp_ban", reason, strike: user.tempBanStrikes, durationMs: duration, createdAt: new Date().toISOString(), expiresAt: new Date(user.tempBanUntil).toISOString(), status: "active" });
  scheduleSave();

  const banToken = createBanSession(username);
  const currentAppeal = db.appeals.filter(a => a.username === username).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))[0];

  broadcastToUser(username, {
    type: "account_temp_banned", reason, until: user.tempBanUntil, strike: user.tempBanStrikes, banToken,
    appeal: currentAppeal ? { id: currentAppeal.id, status: currentAppeal.status, decision: currentAppeal.decision, aiReason: currentAppeal.aiReason } : null
  });
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
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
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
  for (const msgId of pending) {
    const m = db.messages.get(msgId);
    if (m && m.status === "sent") {
      m.status = "delivered"; changed = true;
      broadcastToUser(m.from, { type: "message_status", messageId: m.id, status: "delivered" });
    }
  }
  db.pendingDeliveries[userId] = [];
  if (changed) scheduleSave();
}

function markReadBetween(userAId, userBId) {
  const convKey = [userAId, userBId].sort().join("_");
  const msgIds = db.conversations[convKey] || [];
  let changed = false;
  for (const msgId of msgIds) {
    const m = db.messages.get(msgId);
    if (m && m.fromId === userBId && m.toId === userAId && m.status !== "read") {
      m.status = "read"; changed = true;
      broadcastToUser(m.from, { type: "message_status", messageId: m.id, status: "read" });
    }
  }
  if (changed) scheduleSave();
}

/* ============ HTTP SERVER ============ */
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const route = url.pathname;

  if (req.method === "GET" && (route === "/" || route === "/index.html")) {
    if (!fs.existsSync(HTML_FILE)) { res.writeHead(404); return res.end("No html"); }
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
    return fs.createReadStream(HTML_FILE).pipe(res);
  }
  if (route === "/favicon.ico") { res.writeHead(204); return res.end(); }
  if (route === "/api/health") return sendJSON(res, 200, { ok: true, tunnel: cloudflareUrl || null, uptime: process.uptime() });

  try {
    if (req.method === "POST" && route === "/api/register") {
      const body = await readBody(req);
      const username = String(body.username || "").trim(), password = String(body.password || "");
      if (!/^[a-zA-Z0-9_.-]{3,24}$/.test(username) || password.length < 8 || Object.keys(db.users).some(n => n.toLowerCase() === username.toLowerCase()))
        return sendJSON(res, 400, { success: false, error: "Validasi gagal." });
      
      const salt = crypto.randomBytes(16).toString("hex");
      const user = { id: makeUserId(), username, passwordSalt: salt, passwordHash: hashPassword(password, salt), role: "user", verified: false, banned: false, tempBanned: false, tempBanUntil: 0, tempBanReason: "", tempBanStrikes: 0, lastOffenseAt: 0, spamFlags: 0, lastSpamFlagAt: 0, bio: "", createdAt: new Date().toISOString() };
      db.users[username] = user; db.usersById[user.id] = username; scheduleSave(); createSession(res, username);
      return sendJSON(res, 201, { success: true, user: publicUser(user) });
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
        const app = db.appeals.filter(a => a.username === key).sort((a,b) => new Date(b.createdAt)-new Date(a.createdAt))[0];
        return sendJSON(res, 429, { success: false, tempBanned: true, reason: user.tempBanReason, until: user.tempBanUntil, strike: user.tempBanStrikes, banToken, appeal: app ? { id: app.id, status: app.status, decision: app.decision, aiReason: app.aiReason } : null });
      }
      createSession(res, key); markDeliveredFor(user.id);
      return sendJSON(res, 200, { success: true, user: publicUser(user) });
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
      const app = db.appeals.filter(a => a.username === sess.username).sort((a,b) => new Date(b.createdAt)-new Date(a.createdAt))[0];
      return sendJSON(res, 200, { success: true, banned: isTempBanned(user), reason: user.tempBanReason, until: user.tempBanUntil, strike: user.tempBanStrikes, appeal: app ? { id: app.id, status: app.status, decision: app.decision, aiReason: app.aiReason } : null });
    }

    if (req.method === "POST" && route === "/api/appeal") {
      const sess = getBanSession(String((await readBody(req)).banToken || ""));
      if (!sess) return sendJSON(res, 401, { success: false });
      const chronology = String((await readBody(req)).chronology || "").trim();
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
      const app = db.appeals.filter(a => a.username === sess.username).sort((a,b) => new Date(b.createdAt)-new Date(a.createdAt))[0];
      return sendJSON(res, 200, { success: true, banned: isTempBanned(user), reason: user.tempBanReason, until: user.tempBanUntil, appeal: app ? { id: app.id, status: app.status, decision: app.decision, aiReason: app.aiReason } : null });
    }

    if (req.method === "GET" && route === "/api/contacts") {
      const user = requireLogin(req, res); if (!user) return;
      const savedList = db.savedContacts[user.username] || [];
      const savedIds = new Set(savedList.map(sc => sc.contactId));
      const convPartners = new Set();
      for (const m of db.messages.values()) {
        if (m.fromId === user.id && !savedIds.has(m.toId)) convPartners.add(m.toId);
        else if (m.toId === user.id && !savedIds.has(m.fromId)) convPartners.add(m.fromId);
      }

      const contacts = [];
      const getLastMsg = (tid) => {
        const key = [user.id, tid].sort().join("_");
        const ids = db.conversations[key] || [];
        if (!ids.length) return null;
        return db.messages.get(ids[ids.length - 1]);
      };

      for (const sc of savedList) {
        const target = db.users[getUsernameById(sc.contactId)];
        if (!target || target.banned || isBlocked(user.username, target.username)) continue;
        const lastMsg = getLastMsg(target.id);
        const unread = (db.conversations[[user.id, target.id].sort().join("_")] || []).filter(id => db.messages.get(id)?.toId === user.id && db.messages.get(id)?.status !== "read").length;
        contacts.push({ ...publicUser(target), saved: true, firstName: sc.firstName, lastName: sc.lastName, lastMessage: lastMsg || null, unread });
      }

      for (const tid of convPartners) {
        const target = db.users[getUsernameById(tid)];
        if (!target || target.banned || isBlocked(user.username, target.username)) continue;
        const lastMsg = getLastMsg(target.id);
        const unread = (db.conversations[[user.id, target.id].sort().join("_")] || []).filter(id => db.messages.get(id)?.toId === user.id && db.messages.get(id)?.status !== "read").length;
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
      const msgIds = db.conversations[convKey] || [];
      const msgs = msgIds.map(id => db.messages.get(id)).filter(Boolean);
      
      return sendJSON(res, 200, { success: true, messages: msgs });
    }

    if (req.method === "POST" && route === "/api/messages") {
      const user = requireLogin(req, res); if (!user) return;
      if (isTempBanned(user)) return sendJSON(res, 429, { success: false, tempBanned: true, error: "Diblokir." });

      const body = await readBody(req);
      const targetU = db.users[getUsernameById(body.userId)];
      if (!targetU || targetU.username === user.username) return sendJSON(res, 400, { success: false, error: "Tujuan salah." });
      if (isBlocked(user.username, targetU.username)) return sendJSON(res, 403, { success: false, error: "Diblokir." });

      const content = String(body.content || "").trim();
      if (!content) return sendJSON(res, 400, { success: false, error: "Kosong." });
      const type = ["image", "video"].includes(body.type) ? body.type : "text";
      
      const message = {
        id: makeId(12), from: user.username, fromId: user.id, to: targetU.username, toId: targetU.id,
        type, content, status: isOnline(targetU.username) ? "delivered" : "sent", createdAt: new Date().toISOString()
      };

      db.messages.set(message.id, message);
      const convKey = [user.id, targetU.id].sort().join("_");
      if (!db.conversations[convKey]) db.conversations[convKey] = [];
      db.conversations[convKey].push(message.id);
      
      if (message.status === "sent") {
        if (!db.pendingDeliveries[targetU.id]) db.pendingDeliveries[targetU.id] = [];
        db.pendingDeliveries[targetU.id].push(message.id);
      }

      scheduleSave();

      broadcastToUser(user.username, { type: "new_message", message });
      broadcastToUser(targetU.username, { type: "new_message", message });

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
          if (tracker.recent.length > AI_RULES.maxInWindow) ruleViolation = `Flood ${tracker.recent.length} pesan.`;
          else if (tracker.sameCount >= AI_RULES.repeatLimit) ruleViolation = `Pesan identik ${tracker.sameCount}x.`;
          else if (tracker.longRecent.length > AI_RULES.longBurstMax) ruleViolation = `Burst ${tracker.longRecent.length} pesan.`;

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
              const reason = `AI: ${v.reason} (${v.category}/${v.severity})`;
              if (AI_RULES.immediateBlockCategories.includes(v.category) || AI_RULES.immediateBlockSeverities.includes(v.severity)) {
                applyTempBan(user.username, `Konten ${v.category}: ${v.reason}`);
              } else {
                recordSpamFlag(user.username, reason);
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

    if (req.method === "POST" && route === "/api/messages/report") {
      const user = requireLogin(req, res); if (!user) return;
      const body = await readBody(req);
      const id = String(body.messageId || ""), reason = String(body.reason || "").slice(0,500);
      const msg = db.messages.get(id);
      if (!msg || msg.fromId === user.id) return sendJSON(res, 400, { success: false });
      if (db.reports.some(r => r.messageId === id && r.by === user.username)) return sendJSON(res, 400, { success: false, error: "Sudah." });
      
      const rep = { id: makeId(8), by: user.username, target: msg.from, messageId: id, content: msg.content, mediaType: msg.type, reason, status: "pending_review", createdAt: new Date().toISOString() };
      db.reports.push(rep); scheduleSave();
      
      sendJSON(res, 201, { success: true, message: "Dilaporkan." });
      
      enqueueModeration(async () => {
        const v = await aiReviewReport(msg.content, reason);
        rep.status = "reviewed"; rep.aiVerdict = v; scheduleSave();
        if (v.violation) {
          applyTempBan(msg.from, `Dilaporkan: ${v.reason}`);
          broadcastToUser(user.username, { type: "report_result", ok: true, message: "Pelanggaran terbukti." });
        } else {
          broadcastToUser(user.username, { type: "report_result", ok: false, message: "Tidak melanggar." });
        }
      });
      checkReportThreshold(id);
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
const wss = new WebSocket.Server({ noServer: true, maxPayload: 20 * 1024 * 1024 });
const sockets = new Map();

server.on("upgrade", (req, socket, head) => {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  if (url.pathname !== "/ws") { socket.destroy(); return; }
  const token = parseCookies(req)[COOKIE_NAME];
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

/* ============ CLOUDFLARE TUNNEL ============ */
let cloudflareUrl = null;
let cloudflaredProc = null;

function startCloudflareTunnel(port) {
  if (!ENABLE_CF_TUNNEL) {
    console.log("[Cloudflare] Dinonaktifkan (ENABLE_CF_TUNNEL=false).");
    return;
  }

  console.log(`[Cloudflare] Menjalankan: ${CF_BIN} tunnel --url http://localhost:${port}`);
  console.log(`[Cloudflare] Menunggu URL publik...`);

  try {
    cloudflaredProc = spawn(CF_BIN, ["tunnel", "--no-autoupdate", "--url", `http://localhost:${port}`], {
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, TUNNEL_LOGLEVEL: "info" }
    });
  } catch (err) {
    console.error("[Cloudflare] Gagal spawn:", err.message);
    return;
  }

  let buffer = "";

  const handleChunk = (chunk) => {
    buffer += chunk.toString();
    // Quick tunnel URL muncul di stderr dengan format https://<random>.trycloudflare.com
    const matches = buffer.match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/g);
    if (matches && !cloudflareUrl) {
      cloudflareUrl = matches[matches.length - 1];
      printAccessInfo();
    }
    // Hindari buffer terlalu besar
    if (buffer.length > 8192) buffer = buffer.slice(-4096);
  };

  cloudflaredProc.stderr.on("data", handleChunk);
  cloudflaredProc.stdout.on("data", handleChunk);

  cloudflaredProc.on("error", (err) => {
    if (err.code === "ENOENT") {
      console.error("");
      console.error("[Cloudflare] Binary 'cloudflared' tidak ditemukan!");
      console.error("  Linux : curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o /usr/local/bin/cloudflared && chmod +x /usr/local/bin/cloudflared");
      console.error("  Atau  : npm install -g cloudflared");
      console.error("  Atau  : set env CLOUDFLARED_BIN=/path/ke/cloudflared");
      console.error("");
    } else {
      console.error("[Cloudflare] Error:", err.message);
    }
  });

  cloudflaredProc.on("exit", (code, signal) => {
    if (cloudflareUrl) console.log(`[Cloudflare] Tunnel berhenti (code=${code}, signal=${signal}). URL lama tidak valid lagi.`);
    cloudflareUrl = null;
    cloudflaredProc = null;
  });
}

function stopCloudflareTunnel() {
  if (!cloudflaredProc) return;
  try { cloudflaredProc.kill("SIGTERM"); } catch {}
  // Force kill setelah 3 detik kalau belum mati
  setTimeout(() => { try { if (cloudflaredProc) cloudflaredProc.kill("SIGKILL"); } catch {} }, 3000);
}

/* ============ START ============ */
function getAllocationInfo() {
  const ip =
    process.env.SERVER_ALLOCATION_IP ||
    process.env.P_SERVER_ALLOCATION_IP ||
    process.env.SERVER_IP ||
    process.env.P_SERVER_IP ||
    "0.0.0.0";

  const port =
    process.env.SERVER_ALLOCATION_PORT ||
    process.env.SERVER_PORT ||
    process.env.PORT ||
    PORT;

  const isPtero = !!(
    process.env.P_SERVER_LOCATION ||
    process.env.P_SERVER_UUID ||
    process.env.P_SERVER_ALLOCATION_LIMIT
  );

  return { ip, port, isPtero };
}

function printURLs() {
  const { ip, port, isPtero } = getAllocationInfo();
  const source = isPtero ? "Pterodactyl Panel" : "Local / VPS";
  const line = "=".repeat(56);
  console.log(line);
  console.log("  RANZCHAT — ZERO DELAY SERVER");
  console.log(line);
  console.log(`Status       : ONLINE`);
  console.log(`Environment  : ${source}`);
  console.log(`Bind (local) : ${HOST}:${PORT}`);
  console.log(`Public URL   : http://${ip}:${port}`);
  console.log(`Optimization : O(1) Message Indexing`);
  console.log(`Save Mode    : Debounced (3s)`);
  console.log(`CF Tunnel    : ${ENABLE_CF_TUNNEL ? "starting..." : "disabled"}`);
  console.log(line);
  if (isPtero && (ip === "0.0.0.0" || ip === "127.0.0.1")) {
    console.log("⚠  IP publik tidak terdeteksi di env.");
    console.log("   Tambahkan di tab Startup → SERVER_ALLOCATION_IP = <ip-publik-node>");
  }
}

function printAccessInfo() {
  const { ip, port } = getAllocationInfo();
  const line = "=".repeat(56);
  console.log("");
  console.log(line);
  console.log("  RANZCHAT — ACCESS URLS");
  console.log(line);
  console.log(`Local       : http://localhost:${PORT}`);
  console.log(`Pterodactyl : http://${ip}:${port}`);
  if (cloudflareUrl) {
    console.log(`Cloudflare  : ${cloudflareUrl}`);
    console.log("");
    console.log("  ⚠  URL Cloudflare Quick Tunnel bersifat ephemeral.");
    console.log("     Akan berubah setiap restart. Cocok untuk testing.");
  } else if (ENABLE_CF_TUNNEL) {
    console.log(`Cloudflare  : (menghubungkan...)`);
  } else {
    console.log(`Cloudflare  : (disabled)`);
  }
  console.log(line);
  console.log("");
}

loadDB();

server.listen(PORT, HOST, () => {
  printURLs();

  // Beri jeda 300ms agar log utama tampil dulu
  setTimeout(() => startCloudflareTunnel(PORT), 300);
});

function gracefulShutdown(signal) {
  console.log(`\n[Server] ${signal} diterima, mematikan...`);
  stopCloudflareTunnel();
  saveDB();
  setTimeout(() => process.exit(0), 500);
}

process.on("SIGINT", () => gracefulShutdown("SIGINT"));
process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("uncaughtException", (err) => {
  console.error("[Uncaught]", err);
});
process.on("unhandledRejection", (err) => {
  console.error("[UnhandledRejection]", err);
});
