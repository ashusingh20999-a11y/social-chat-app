import { DurableObject } from "cloudflare:workers";

export class ChatRoom extends DurableObject {
  async fetch(request) {
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return new Response("Expected WebSocket", { status: 426 });
    }

    const url = new URL(request.url);
    const username = (url.searchParams.get("username") || "Anonymous").slice(0, 40);
    const [client, server] = Object.values(new WebSocketPair());

    this.ctx.acceptWebSocket(server);
    server.serializeAttachment({ username });

    this.broadcast(JSON.stringify({ type: "system", text: `${username} joined the room` }), server);

    return new Response(null, { status: 101, webSocket: client });
  }

  webSocketMessage(ws, message) {
    const state = ws.deserializeAttachment() || { username: "Anonymous" };
    let payload;
    try {
      payload = typeof message === "string" ? JSON.parse(message) : null;
    } catch {
      payload = null;
    }

    if (!payload || typeof payload.text !== "string") return;

    const text = payload.text.trim().slice(0, 1000);
    if (!text) return;

    this.broadcast(JSON.stringify({
      type: "message",
      user: state.username,
      text,
      time: new Date().toISOString()
    }));
  }

  webSocketClose(ws) {
    const state = ws.deserializeAttachment() || { username: "Anonymous" };
    this.broadcast(JSON.stringify({ type: "system", text: `${state.username} left the room` }), ws);
  }

  webSocketError(ws) {
    try { ws.close(); } catch {}
  }

  broadcast(message, except = null) {
    for (const ws of this.ctx.getWebSockets()) {
      if (ws === except) continue;
      if (ws.readyState === WebSocket.OPEN) {
        try { ws.send(message); } catch {}
      }
    }
  }
}

async function initDatabase(db) {
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS app_users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS app_posts (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      username TEXT NOT NULL,
      content TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`)
  ]);
}

function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: { "Cache-Control": "no-store" }
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/chat/")) {
      if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
        return new Response("Expected WebSocket", { status: 426 });
      }
      const roomName = decodeURIComponent(url.pathname.split("/")[2] || "general").slice(0, 80);
      const id = env.CHAT_ROOM.idFromName(roomName);
      return env.CHAT_ROOM.get(id).fetch(request);
    }

    if (url.pathname.startsWith("/api/")) {
      if (!env.DB) return json({ ok: false, error: "D1 binding DB is missing" }, 500);
      await initDatabase(env.DB);

      if (url.pathname === "/api/health" && request.method === "GET") {
        const row = await env.DB.prepare("SELECT 1 AS ok").first();
        return json({ ok: row?.ok === 1, service: "social-chat", version: "2.0" });
      }

      if (url.pathname === "/api/users" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const username = String(body.username || "").trim().slice(0, 40);
        const id = String(body.id || crypto.randomUUID());
        if (!username) return json({ ok: false, error: "Username is required" }, 400);

        await env.DB.prepare("INSERT INTO app_users (id, username) VALUES (?, ?) ON CONFLICT(username) DO UPDATE SET id=excluded.id")
          .bind(id, username).run();
        const user = await env.DB.prepare("SELECT id, username FROM app_users WHERE username = ?")
          .bind(username).first();
        return json({ ok: true, user });
      }

      if (url.pathname === "/api/users" && request.method === "GET") {
        const { results } = await env.DB.prepare("SELECT id, username, created_at FROM app_users ORDER BY created_at DESC LIMIT 100").all();
        return json({ ok: true, users: results || [] });
      }

      if (url.pathname === "/api/posts" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const username = String(body.username || "").trim().slice(0, 40);
        const userId = String(body.user_id || "").trim();
        const content = String(body.content || "").trim();
        if (!username || !content) return json({ ok: false, error: "Username and content are required" }, 400);
        if (content.length > 2000) return json({ ok: false, error: "Post is too long (max 2000 characters)" }, 400);

        const existing = await env.DB.prepare("SELECT id FROM app_users WHERE username = ?").bind(username).first();
        const id = userId || String(crypto.randomUUID());
        if (!existing) {
          await env.DB.prepare("INSERT INTO app_users (id, username) VALUES (?, ?)").bind(id, username).run();
        }

        const postId = crypto.randomUUID();
        await env.DB.prepare("INSERT INTO app_posts (id, user_id, username, content) VALUES (?, ?, ?, ?)")
          .bind(postId, existing?.id || id, username, content).run();
        return json({ ok: true, post: { id: postId, user_id: existing?.id || id, username, content } });
      }

      if (url.pathname === "/api/posts" && request.method === "GET") {
        const { results } = await env.DB.prepare("SELECT id, user_id, username, content, created_at FROM app_posts ORDER BY created_at DESC LIMIT 100").all();
        return json({ ok: true, posts: results || [] });
      }

      return json({ ok: false, error: "API route not found" }, 404);
    }

    if (env.ASSETS) return env.ASSETS.fetch(request);
    return new Response("Not Found", { status: 404 });
  }
};
