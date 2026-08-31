const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" }
  });

async function hashPassword(password) {
  const data = new TextEncoder().encode(password);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function normalizeUsername(value) {
  return value.trim().replace(/^@/, "").toLowerCase();
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/")) {
      if (request.method === "OPTIONS") {
        return new Response(null, {
          headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type"
          }
        });
      }

      if (url.pathname === "/api/health" && request.method === "GET") {
        return json({ ok: true, service: "social-chat-api", database: "connected" });
      }

      if (url.pathname === "/api/signup" && request.method === "POST") {
        try {
          const body = await request.json();
          const name = String(body.name || "").trim();
          const username = normalizeUsername(String(body.username || ""));
          const email = String(body.email || "").trim().toLowerCase();
          const phone = String(body.phone || "").trim();
          const password = String(body.password || "");

          if (!name || username.length < 3 || !email || !phone || password.length < 8) {
            return json({ ok: false, error: "Please fill all fields correctly." }, 400);
          }

          const existing = await env.DB.prepare(
            "SELECT id FROM users WHERE username = ? OR email = ? LIMIT 1"
          ).bind(username, email).first();

          if (existing) {
            return json({ ok: false, error: "Username or email already exists." }, 409);
          }

          const id = crypto.randomUUID();
          const passwordHash = await hashPassword(password);

          await env.DB.prepare(
            "INSERT INTO users (id, username, email, password_hash, display_name) VALUES (?, ?, ?, ?, ?)"
          ).bind(id, username, email, passwordHash, name).run();

          return json({
            ok: true,
            message: "Account created successfully.",
            user: { id, username, email, display_name: name }
          }, 201);
        } catch {
          return json({ ok: false, error: "Unable to create account." }, 500);
        }
      }

      if (url.pathname === "/api/login" && request.method === "POST") {
        try {
          const body = await request.json();
          const identity = String(body.identity || "").trim().toLowerCase();
          const password = String(body.password || "");

          if (!identity || !password) {
            return json({ ok: false, error: "Email/username and password are required." }, 400);
          }

          const user = await env.DB.prepare(
            "SELECT id, username, email, password_hash, display_name, avatar_url FROM users WHERE email = ? OR username = ? LIMIT 1"
          ).bind(identity, normalizeUsername(identity)).first();

          if (!user) {
            return json({ ok: false, error: "Invalid login details." }, 401);
          }

          const passwordHash = await hashPassword(password);
          if (passwordHash !== user.password_hash) {
            return json({ ok: false, error: "Invalid login details." }, 401);
          }

          return json({
            ok: true,
            message: "Login successful.",
            user: {
              id: user.id,
              username: user.username,
              email: user.email,
              display_name: user.display_name,
              avatar_url: user.avatar_url
            }
          });
        } catch {
          return json({ ok: false, error: "Unable to login." }, 500);
        }
      }

      return json({ ok: false, error: "API route not found." }, 404);
    }

    return env.ASSETS.fetch(request);
  }
};