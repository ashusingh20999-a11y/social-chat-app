import { DurableObject } from "cloudflare:workers";

export class ChatRoom extends DurableObject {
  async fetch(request) {
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return new Response("Expected WebSocket", { status: 426 });
    const url = new URL(request.url);
    const username = (url.searchParams.get("username") || "Anonymous").slice(0, 40);
    const userId = (url.searchParams.get("user_id") || "").slice(0, 80);
    const [client, server] = Object.values(new WebSocketPair());
    this.ctx.acceptWebSocket(server);
    server.serializeAttachment({ username, userId });
    this.broadcast(JSON.stringify({ type: "system", text: `${username} joined the encrypted room` }), server);
    return new Response(null, { status: 101, webSocket: client });
  }
  webSocketMessage(ws, message) {
    let payload; try { payload = typeof message === "string" ? JSON.parse(message) : null; } catch { payload = null; }
    if (!payload || payload.type !== "encrypted" || typeof payload.iv !== "string" || typeof payload.ciphertext !== "string" || !Array.isArray(payload.recipients)) return;
    if (payload.iv.length > 100 || payload.ciphertext.length > 10000 || payload.recipients.length > 100) return;
    const state = ws.deserializeAttachment() || {};
    const safe = { type: "encrypted", from: state.userId, user: state.username, senderPublicKey: payload.senderPublicKey, iv: payload.iv, recipients: payload.recipients.map(r => ({ userId: String(r.userId || "").slice(0,80), ciphertext: String(r.ciphertext || "").slice(0,10000) })) };
    this.broadcast(JSON.stringify(safe));
  }
  webSocketClose(ws) { const s = ws.deserializeAttachment() || { username: "Anonymous" }; this.broadcast(JSON.stringify({ type: "system", text: `${s.username} left the room` }), ws); }
  webSocketError(ws) { try { ws.close(); } catch {} }
  broadcast(message, except = null) { for (const ws of this.ctx.getWebSockets()) { if (ws !== except && ws.readyState === WebSocket.OPEN) try { ws.send(message); } catch {} } }
}

const json = (data, status = 200) => Response.json(data, { status, headers: { "Cache-Control": "no-store" } });
const enc = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
async function sha256(value) { return hex(await crypto.subtle.digest("SHA-256", enc.encode(value))); }
async function passwordHash(password, salt = crypto.randomUUID()) { const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]); const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: enc.encode(salt), iterations: 100000, hash: "SHA-256" }, key, 256); return `${salt}:${hex(bits)}`; }
async function passwordVerify(password, stored) { const [salt, expected] = String(stored || "").split(":"); if (!salt || !expected) return false; return (await passwordHash(password, salt)).split(":")[1] === expected; }
function validUsername(v) { return /^[A-Za-z0-9_]{3,30}$/.test(v); }
function validEmail(v) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v); }
function cookie(name, value, maxAge) { return `${name}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`; }
async function sessionUser(request, db) { const m = request.headers.get("Cookie")?.match(/(?:^|; )sc_session=([^;]+)/); if (!m) return null; const tokenHash = await sha256(m[1]); return await db.prepare("SELECT u.id,u.username,u.email,u.display_name FROM auth_users u JOIN sessions s ON s.user_id=u.id WHERE s.token_hash=? AND s.expires_at>datetime('now') AND u.email_verified=1").bind(tokenHash).first(); }
async function initDatabase(db) { await db.batch([
  db.prepare(`CREATE TABLE IF NOT EXISTS auth_users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, email_verified INTEGER NOT NULL DEFAULT 0, display_name TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`),
  db.prepare(`CREATE TABLE IF NOT EXISTS email_otps (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, otp_hash TEXT NOT NULL, expires_at TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`),
  db.prepare(`CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, expires_at TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`),
  db.prepare(`CREATE TABLE IF NOT EXISTS app_posts (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, username TEXT NOT NULL, content TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`),
  db.prepare(`CREATE TABLE IF NOT EXISTS chat_keys (user_id TEXT PRIMARY KEY, username TEXT NOT NULL, public_key TEXT NOT NULL, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`)
]); }
async function sendOtp(env, email, otp) { if (!env.RESEND_API_KEY) return false; const from = env.FROM_EMAIL || "Social Chat <onboarding@resend.dev>"; const r = await fetch("https://api.resend.com/emails", { method: "POST", headers: { "Authorization": `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" }, body: JSON.stringify({ from, to: [email], subject: "Your Social Chat verification code", html: `<p>Your Social Chat verification code is:</p><h2>${otp}</h2><p>This code expires in 10 minutes.</p>` }) }); return r.ok; }

export default { async fetch(request, env) {
  const url = new URL(request.url);
  if (url.pathname === "/home.html") { if (!env.DB) return new Response("D1 binding DB is missing", { status: 500 }); await initDatabase(env.DB); if (!await sessionUser(request, env.DB)) return Response.redirect(new URL("/", request.url), 302); return env.ASSETS.fetch(request); }
  if (url.pathname.startsWith("/chat/")) { if (!env.DB) return new Response("D1 binding DB is missing", { status: 500 }); const u = await sessionUser(request, env.DB); if (!u) return new Response("Login required", { status: 401 }); if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return new Response("Expected WebSocket", { status: 426 }); const room = decodeURIComponent(url.pathname.split("/")[2] || "general").slice(0, 80); const target = new URL(request.url); target.search = `?username=${encodeURIComponent(u.username)}&user_id=${encodeURIComponent(u.id)}`; return env.CHAT_ROOM.get(env.CHAT_ROOM.idFromName(room)).fetch(new Request(target, request)); }
  if (url.pathname.startsWith("/api/")) {
    if (!env.DB) return json({ ok:false,error:"D1 binding DB is missing" },500); await initDatabase(env.DB);
    if (url.pathname === "/api/signup" && request.method === "POST") { const b=await request.json().catch(()=>({})); const username=String(b.username||"").trim(), email=String(b.email||"").trim().toLowerCase(), password=String(b.password||""); if(!validUsername(username))return json({ok:false,error:"Username 3-30 characters: letters, numbers and _ only"},400); if(!validEmail(email)||!email.endsWith("@gmail.com"))return json({ok:false,error:"Please use a valid Gmail address"},400); if(password.length<8)return json({ok:false,error:"Password must be at least 8 characters"},400); if(await env.DB.prepare("SELECT id FROM auth_users WHERE username=? OR email=?").bind(username,email).first())return json({ok:false,error:"Username or Gmail already registered"},409); const userId=crypto.randomUUID(); await env.DB.prepare("INSERT INTO auth_users(id,username,email,password_hash) VALUES(?,?,?,?)").bind(userId,username,email,await passwordHash(password)).run(); const random=new Uint32Array(1); crypto.getRandomValues(random); const otp=String(100000+(random[0]%900000)); await env.DB.prepare("INSERT INTO email_otps(id,user_id,otp_hash,expires_at) VALUES(?,?,?,datetime('now','+10 minutes'))").bind(crypto.randomUUID(),userId,await sha256(otp)).run(); const sent=await sendOtp(env,email,otp); if(!sent){await env.DB.prepare("DELETE FROM email_otps WHERE user_id=?").bind(userId).run();await env.DB.prepare("DELETE FROM auth_users WHERE id=?").bind(userId).run();return json({ok:false,error:"Email service is not configured. Add RESEND_API_KEY in Cloudflare Secrets."},503);} return json({ok:true,message:"OTP sent to your Gmail",user_id:userId}); }
    if (url.pathname === "/api/verify-email" && request.method === "POST") { const b=await request.json().catch(()=>({})), userId=String(b.user_id||""), otp=String(b.otp||"").trim(); const row=await env.DB.prepare("SELECT id,otp_hash,expires_at,attempts FROM email_otps WHERE user_id=? ORDER BY created_at DESC LIMIT 1").bind(userId).first(); if(!row||row.attempts>=5||new Date(String(row.expires_at).replace(" ","T")+"Z")<new Date())return json({ok:false,error:"OTP expired. Please sign up again."},400); if(await sha256(otp)!==row.otp_hash){await env.DB.prepare("UPDATE email_otps SET attempts=attempts+1 WHERE id=?").bind(row.id).run();return json({ok:false,error:"Invalid OTP"},400);} await env.DB.prepare("UPDATE auth_users SET email_verified=1 WHERE id=?").bind(userId).run();await env.DB.prepare("DELETE FROM email_otps WHERE user_id=?").bind(userId).run();return json({ok:true,message:"Email verified. You can now login."}); }
    if (url.pathname === "/api/login" && request.method === "POST") { const b=await request.json().catch(()=>({})), identity=String(b.username||b.email||"").trim().toLowerCase(), password=String(b.password||""); const u=await env.DB.prepare("SELECT * FROM auth_users WHERE lower(username)=? OR lower(email)=?").bind(identity,identity).first(); if(!u||!(await passwordVerify(password,u.password_hash)))return json({ok:false,error:"Invalid username/email or password"},401); if(!u.email_verified)return json({ok:false,error:"Email not verified. Complete Gmail OTP verification first."},403); const token=crypto.randomUUID()+crypto.randomUUID(),sid=crypto.randomUUID(); await env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(u.id).run();await env.DB.prepare("INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES(?,?,?,datetime('now','+30 days'))").bind(sid,u.id,await sha256(token)).run();return new Response(JSON.stringify({ok:true,user:{id:u.id,username:u.username,email:u.email,display_name:u.display_name||u.username}}),{status:200,headers:{"Content-Type":"application/json","Cache-Control":"no-store","Set-Cookie":cookie("sc_session",token,60*60*24*30)}}); }
    if (url.pathname === "/api/logout" && request.method === "POST") { const u=await sessionUser(request,env.DB);if(u)await env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(u.id).run();return new Response(JSON.stringify({ok:true}),{headers:{"Content-Type":"application/json","Set-Cookie":cookie("sc_session","",0)}}); }
    if (url.pathname === "/api/me" && request.method === "GET") { const u=await sessionUser(request,env.DB);if(!u)return json({ok:false,error:"Not logged in"},401);return json({ok:true,user:u}); }
    const u=await sessionUser(request,env.DB);
    if (url.pathname === "/api/chat/keys" && request.method === "GET") { if(!u)return json({ok:false,error:"Login required"},401); const {results}=await env.DB.prepare("SELECT user_id,username,public_key FROM chat_keys WHERE user_id IN (SELECT id FROM auth_users WHERE email_verified=1)").all(); return json({ok:true,keys:results||[]}); }
    if (url.pathname === "/api/chat/keys" && request.method === "POST") { if(!u)return json({ok:false,error:"Login required"},401); const b=await request.json().catch(()=>({})); const publicKey=String(b.public_key||""); if(publicKey.length<20||publicKey.length>5000)return json({ok:false,error:"Invalid public key"},400); await env.DB.prepare("INSERT INTO chat_keys(user_id,username,public_key,updated_at) VALUES(?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(user_id) DO UPDATE SET username=excluded.username,public_key=excluded.public_key,updated_at=CURRENT_TIMESTAMP").bind(u.id,u.username,publicKey).run(); return json({ok:true}); }
    if (url.pathname === "/api/posts" && request.method === "GET") { if(!u)return json({ok:false,error:"Login required"},401); const {results}=await env.DB.prepare("SELECT id,user_id,username,content,created_at FROM app_posts ORDER BY created_at DESC LIMIT 100").all();return json({ok:true,posts:results||[]}); }
    if (url.pathname === "/api/posts" && request.method === "POST") { if(!u)return json({ok:false,error:"Login required"},401); const b=await request.json().catch(()=>({})),content=String(b.content||"").trim();if(!content)return json({ok:false,error:"Post is empty"},400);if(content.length>2000)return json({ok:false,error:"Maximum 2000 characters"},400);await env.DB.prepare("INSERT INTO app_posts(id,user_id,username,content) VALUES(?,?,?,?)").bind(crypto.randomUUID(),u.id,u.username,content).run();return json({ok:true}); }
    return json({ok:false,error:"API route not found"},404);
  }
  if(env.ASSETS)return env.ASSETS.fetch(request);return new Response("Not Found",{status:404});
} };
