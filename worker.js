const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json; charset=utf-8","Access-Control-Allow-Origin":"*","Access-Control-Allow-Methods":"GET,POST,OPTIONS","Access-Control-Allow-Headers":"Content-Type"});
const BUILD_VERSION="2026-09-04-feed-final-10";
const uid=()=>crypto.randomUUID();

async function hashPassword(password){const data=new TextEncoder().encode(password);const digest=await crypto.subtle.digest("SHA-256",data);return [...new Uint8Array(digest)].map(b=>b.toString(16).padStart(2,"0")).join("");}
function normalizeUsername(v){return v.trim().replace(/^@/,"").toLowerCase()}

async function ensureSchema(db){
  await db.batch([
    db.prepare("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, display_name TEXT, avatar_url TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"),
    db.prepare("CREATE TABLE IF NOT EXISTS posts (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, content TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id))"),
    db.prepare("CREATE TABLE IF NOT EXISTS likes (post_id TEXT NOT NULL, user_id TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(post_id,user_id))"),
    db.prepare("CREATE TABLE IF NOT EXISTS comments (id TEXT PRIMARY KEY, post_id TEXT NOT NULL, user_id TEXT NOT NULL, content TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"),
    db.prepare("CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, identity_key TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"),
    db.prepare("CREATE TABLE IF NOT EXISTS conversations (id TEXT PRIMARY KEY, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"),
    db.prepare("CREATE TABLE IF NOT EXISTS conversation_members (conversation_id TEXT NOT NULL, device_id TEXT NOT NULL, PRIMARY KEY(conversation_id,device_id))"),
    db.prepare("CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL DEFAULT '', sender_id TEXT NOT NULL, receiver_id TEXT NOT NULL, sender_device_id TEXT NOT NULL DEFAULT '', receiver_device_id TEXT NOT NULL DEFAULT '', content TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"),
    db.prepare("CREATE TABLE IF NOT EXISTS friend_requests (id TEXT PRIMARY KEY, sender_id TEXT NOT NULL, receiver_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(sender_id,receiver_id))"),
    db.prepare("CREATE TABLE IF NOT EXISTS friendships (user_id TEXT NOT NULL, friend_id TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(user_id,friend_id))")
  ]);
}

export default {async fetch(request,env){
  const url=new URL(request.url);
  if(url.pathname.startsWith("/api/")){
    if(request.method==="OPTIONS")return json({});
    try{
      try{await ensureSchema(env.DB)}catch(e){console.error("schema maintenance failed:",e)}
      if(url.pathname==="/api/health")return json({ok:true,database:"connected",build:BUILD_VERSION});
      if(url.pathname==="/api/signup"&&request.method==="POST"){
        const b=await request.json();const name=String(b.name||"").trim(),username=normalizeUsername(String(b.username||"")),email=String(b.email||"").trim().toLowerCase(),password=String(b.password||"");
        if(!name||username.length<3||!email||password.length<8)return json({ok:false,error:"Please fill all fields correctly."},400);
        const ex=await env.DB.prepare("SELECT id FROM users WHERE username=? OR email=? LIMIT 1").bind(username,email).first();if(ex)return json({ok:false,error:"Username or email already exists."},409);
        const id=uid();await env.DB.prepare("INSERT INTO users(id,username,email,password_hash,display_name) VALUES(?,?,?,?,?)").bind(id,username,email,await hashPassword(password),name).run();return json({ok:true,user:{id,username,email,display_name:name}},201);
      }
      if(url.pathname==="/api/login"&&request.method==="POST"){
        const b=await request.json(),identity=String(b.identity||"").trim().toLowerCase(),password=String(b.password||"");
        const u=await env.DB.prepare("SELECT id,username,email,password_hash,display_name,avatar_url FROM users WHERE email=? OR username=? LIMIT 1").bind(identity,normalizeUsername(identity)).first();
        if(!u||await hashPassword(password)!==u.password_hash)return json({ok:false,error:"Invalid login details."},401);
        return json({ok:true,message:"Login successful.",user:{id:u.id,username:u.username,email:u.email,display_name:u.display_name,avatar_url:u.avatar_url}});
      }
      if(url.pathname==="/api/feed"&&request.method==="GET"){
        const userId=String(url.searchParams.get("user_id")||"").trim();if(!userId)return json({ok:false,error:"user_id is required."},400);
        const r=await env.DB.prepare(`SELECT p.id,p.user_id,p.content,p.created_at,COALESCE(u.username,'user') AS username,COALESCE(u.display_name,'User') AS display_name,COALESCE(u.avatar_url,'') AS avatar_url FROM posts p LEFT JOIN users u ON u.id=p.user_id WHERE p.user_id=? OR EXISTS(SELECT 1 FROM friendships f WHERE (f.user_id=? AND f.friend_id=p.user_id) OR (f.friend_id=? AND f.user_id=p.user_id)) ORDER BY p.created_at DESC LIMIT 50`).bind(userId,userId,userId).all();
        return json({ok:true,posts:(r.results||[]).map(p=>({id:p.id,user_id:p.user_id,content:String(p.content||""),created_at:p.created_at||"",username:p.username||"user",display_name:p.display_name||"User",avatar_url:p.avatar_url||"",like_count:0,comment_count:0,liked:0})),build:BUILD_VERSION});
      }
      if(url.pathname==="/api/posts"&&request.method==="GET"){
        const r=await env.DB.prepare("SELECT p.id,p.user_id,p.content,p.created_at,COALESCE(u.username,'user') AS username,COALESCE(u.display_name,'User') AS display_name,COALESCE(u.avatar_url,'') AS avatar_url FROM posts p LEFT JOIN users u ON u.id=p.user_id ORDER BY p.created_at DESC LIMIT 50").all();return json({ok:true,posts:r.results||[],build:BUILD_VERSION});
      }
      if(url.pathname==="/api/posts"&&request.method==="POST"){
        const b=await request.json(),userId=String(b.user_id||"").trim(),content=String(b.content||"").trim();
        if(!userId)return json({ok:false,error:"user_id is required."},400);if(!content)return json({ok:false,error:"Post content cannot be empty."},400);if(content.length>2000)return json({ok:false,error:"Post is too long."},400);
        const user=await env.DB.prepare("SELECT id FROM users WHERE id=?").bind(userId).first();if(!user)return json({ok:false,error:"User not found."},404);
        const id=uid(),createdAt=new Date().toISOString();await env.DB.prepare("INSERT INTO posts(id,user_id,content,created_at) VALUES(?,?,?,?)").bind(id,userId,content,createdAt).run();return json({ok:true,post:{id,user_id:userId,content,created_at:createdAt},build:BUILD_VERSION},201);
      }
      return json({ok:false,error:"API route not found."},404);
    }catch(e){console.error("API error:",e);return json({ok:false,error:String(e?.message||e),build:BUILD_VERSION},500)}
  }

  const html=`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Social Chat</title><style>body{font-family:system-ui;margin:0;background:#f6f7fb;color:#182033}.shell{max-width:520px;margin:auto;padding:20px}.card{background:#fff;border:1px solid #e7e9f0;border-radius:18px;padding:15px;margin:10px 0}.primary,.smallbtn{background:#6d5dfc;color:#fff;border:0;border-radius:12px;padding:11px 15px}.field{width:100%;box-sizing:border-box;padding:12px;border:1px solid #ddd;border-radius:10px;margin:5px 0}.empty{text-align:center;padding:28px;color:#7b8498}.post-content{white-space:pre-wrap;line-height:1.45;margin:12px 0}</style></head><body><div class="shell"><section id="auth"><h1>Social Chat</h1><div id="loginPane"><input id="li" class="field" placeholder="Username or email"><input id="lp" class="field" type="password" placeholder="Password"><button class="primary" onclick="login()">Log in</button><p id="le"></p></div></section><section id="app" style="display:none"><h2>Home</h2><div class="card"><textarea id="postText" class="field" placeholder="What's on your mind?"></textarea><button class="smallbtn" onclick="createPost()">Post</button></div><div id="feed"></div></section></div><script>let me=null;const $=id=>document.getElementById(id);async function api(u,o){try{const r=await fetch(u,o),t=await r.text();let d;try{d=JSON.parse(t)}catch(_){d={ok:false,error:'HTTP '+r.status+': '+t.slice(0,200)}}return d}catch(e){return{ok:false,error:'Network error: '+e.message}}}function esc(s){return String(s||'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}async function login(){const d=await api('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({identity:$('li').value,password:$('lp').value})});if(!d.ok){$('le').textContent=d.error;return}me=d.user;enter()}function enter(){localStorage.setItem('social_user',JSON.stringify(me));$('auth').style.display='none';$('app').style.display='block';loadPosts()}async function loadPosts(){const feed=$('feed');if(!feed||!me?.id)return;feed.innerHTML='<div class="empty">Loading feed...</div>';const d=await api('/api/feed?user_id='+encodeURIComponent(me.id)+'&_t='+Date.now(),{cache:'no-store'});if(!d.ok){feed.innerHTML='<div class="empty">Unable to load feed<br>'+esc(d.error)+'</div>';return}const posts=Array.isArray(d.posts)?d.posts:[];if(!posts.length){feed.innerHTML='<div class="empty">No posts yet.</div>';return}feed.innerHTML=posts.map(p=>'<article class="card"><b>'+esc(p.display_name||p.username||'User')+'</b><div class="post-content">'+esc(p.content)+'</div></article>').join('')}async function createPost(){const t=$('postText').value.trim();if(!t||!me?.id)return;const d=await api('/api/posts',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user_id:me.id,content:t})});if(!d.ok){alert(d.error);return}$('postText').value='';loadPosts()}(()=>{try{const x=JSON.parse(localStorage.getItem('social_user')||'null');if(x?.id){me=x;enter()}}catch(e){}})();</script></body></html>`;
  return new Response(html,{headers:{"content-type":"text/html; charset=utf-8","cache-control":"no-store"}});
}};