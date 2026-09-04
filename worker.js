const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json; charset=utf-8","Access-Control-Allow-Origin":"*","Access-Control-Allow-Methods":"GET,POST,OPTIONS","Access-Control-Allow-Headers":"Content-Type"}});
const BUILD_VERSION="2026-09-04-feed-final-11";
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
        const b=await request.json();
        const username=normalizeUsername(String(b.username||"")),email=String(b.email||"").trim().toLowerCase(),password=String(b.password||"");
        if(!username||!email||!password)return json({ok:false,error:"Username, email and password are required."},400);
        const exists=await env.DB.prepare("SELECT id FROM users WHERE username=? OR email=?").bind(username,email).first();
        if(exists)return json({ok:false,error:"Username or email already exists."},409);
        const id=uid();
        await env.DB.prepare("INSERT INTO users(id,username,email,password_hash,display_name,created_at) VALUES(?,?,?,?,?,?)").bind(id,username,email,await hashPassword(password),username,new Date().toISOString()).run();
        return json({ok:true,user:{id,username,email,display_name:username},build:BUILD_VERSION},201);
      }
      if(url.pathname==="/api/login"&&request.method==="POST"){
        const b=await request.json();
        const login=String(b.username||b.email||"").trim().toLowerCase(),password=String(b.password||"");
        if(!login||!password)return json({ok:false,error:"Username/email and password are required."},400);
        const user=await env.DB.prepare("SELECT id,username,email,password_hash,display_name,avatar_url FROM users WHERE lower(username)=? OR lower(email)=?").bind(login,login).first();
        if(!user||user.password_hash!==await hashPassword(password))return json({ok:false,error:"Invalid login."},401);
        return json({ok:true,user:{id:user.id,username:user.username,email:user.email,display_name:user.display_name||user.username,avatar_url:user.avatar_url||""},build:BUILD_VERSION});
      }
      if(url.pathname==="/api/feed"&&request.method==="GET"){
        const userId=String(url.searchParams.get("user_id")||"").trim();
        if(!userId)return json({ok:false,error:"user_id is required."},400);
        const result=await env.DB.prepare("SELECT p.id,p.user_id,p.content,p.created_at,COALESCE(u.username,'user') AS username,COALESCE(u.display_name,'User') AS display_name,COALESCE(u.avatar_url,'') AS avatar_url FROM posts p LEFT JOIN users u ON u.id=p.user_id WHERE p.user_id=? OR EXISTS(SELECT 1 FROM friendships f WHERE (f.user_id=? AND f.friend_id=p.user_id) OR (f.friend_id=? AND f.user_id=p.user_id)) ORDER BY p.created_at DESC LIMIT 50").bind(userId,userId,userId).all();
        return json({ok:true,posts:result.results||[],build:BUILD_VERSION});
      }
      if(url.pathname==="/api/posts"&&request.method==="GET"){
        const result=await env.DB.prepare("SELECT p.id,p.user_id,p.content,p.created_at,COALESCE(u.username,'user') AS username,COALESCE(u.display_name,'User') AS display_name,COALESCE(u.avatar_url,'') AS avatar_url FROM posts p LEFT JOIN users u ON u.id=p.user_id ORDER BY p.created_at DESC LIMIT 50").all();
        return json({ok:true,posts:result.results||[],build:BUILD_VERSION});
      }
      if(url.pathname==="/api/posts"&&request.method==="POST"){
        const b=await request.json();
        const userId=String(b.user_id||"").trim(),content=String(b.content||"").trim();
        if(!userId)return json({ok:false,error:"user_id is required."},400);
        if(!content)return json({ok:false,error:"Post content cannot be empty."},400);
        if(content.length>2000)return json({ok:false,error:"Post is too long."},400);
        const user=await env.DB.prepare("SELECT id FROM users WHERE id=?").bind(userId).first();
        if(!user)return json({ok:false,error:"User not found."},404);
        const id=uid(),createdAt=new Date().toISOString();
        await env.DB.prepare("INSERT INTO posts(id,user_id,content,created_at) VALUES(?,?,?,?)").bind(id,userId,content,createdAt).run();
        return json({ok:true,post:{id,user_id:userId,content,created_at:createdAt},build:BUILD_VERSION},201);
      }
      return json({ok:false,error:"API endpoint not found."},404);
    }catch(e){
      console.error("API error:",e);
      return json({ok:false,error:String(e?.message||e||"Server error"),build:BUILD_VERSION},500);
    }
  }
  return new Response("Social Chat API is running. Build "+BUILD_VERSION,{headers:{"content-type":"text/plain; charset=utf-8"}});
}};
