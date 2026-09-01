const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json; charset=utf-8","Access-Control-Allow-Origin":"*","Access-Control-Allow-Methods":"GET,POST,OPTIONS","Access-Control-Allow-Headers":"Content-Type"}});
const BUILD_VERSION="2026-09-01-post-never-lose-draft";
const uid=()=>crypto.randomUUID();

async function hashPassword(password){
  const data=new TextEncoder().encode(password);
  const digest=await crypto.subtle.digest("SHA-256",data);
  return [...new Uint8Array(digest)].map(b=>b.toString(16).padStart(2,"0")).join("");
}
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

  const info=await db.prepare("PRAGMA table_info(messages)").all();
  const names=new Set((info.results||[]).map(x=>x.name));
  const alters=[];
  if(!names.has("conversation_id")) alters.push(db.prepare("ALTER TABLE messages ADD COLUMN conversation_id TEXT NOT NULL DEFAULT ''"));
  if(!names.has("sender_device_id")) alters.push(db.prepare("ALTER TABLE messages ADD COLUMN sender_device_id TEXT NOT NULL DEFAULT ''"));
  if(!names.has("receiver_device_id")) alters.push(db.prepare("ALTER TABLE messages ADD COLUMN receiver_device_id TEXT NOT NULL DEFAULT ''"));
  if(!names.has("content")) alters.push(db.prepare("ALTER TABLE messages ADD COLUMN content TEXT"));
  if(!names.has("ciphertext")) alters.push(db.prepare("ALTER TABLE messages ADD COLUMN ciphertext TEXT"));
  if(!names.has("nonce")) alters.push(db.prepare("ALTER TABLE messages ADD COLUMN nonce TEXT"));
  if(alters.length) await db.batch(alters);

  const postInfo=await db.prepare("PRAGMA table_info(posts)").all();
  const postNames=new Set((postInfo.results||[]).map(x=>x.name));
  const postAlters=[];
  if(!postNames.has("content")) postAlters.push(db.prepare("ALTER TABLE posts ADD COLUMN content TEXT"));
  if(!postNames.has("ciphertext")) postAlters.push(db.prepare("ALTER TABLE posts ADD COLUMN ciphertext TEXT"));
  if(!postNames.has("nonce")) postAlters.push(db.prepare("ALTER TABLE posts ADD COLUMN nonce TEXT"));
  if(postAlters.length) await db.batch(postAlters);
}

export default {async fetch(request,env){
  const url=new URL(request.url);
  if(url.pathname.startsWith("/api/")){
    if(request.method==="OPTIONS") return json({});
    try{
      await ensureSchema(env.DB);

      if(url.pathname==="/api/health")
        return json({ok:true,database:"connected",build:BUILD_VERSION});

      if(url.pathname==="/api/debug-schema")
        return json({ok:true,build:BUILD_VERSION,
          users:await env.DB.prepare("PRAGMA table_info(users)").all(),
          posts:await env.DB.prepare("PRAGMA table_info(posts)").all(),
          messages:await env.DB.prepare("PRAGMA table_info(messages)").all()});

      if(url.pathname==="/api/signup"&&request.method==="POST"){
        const b=await request.json();
        const name=String(b.name||"").trim(),username=normalizeUsername(String(b.username||""));
        const email=String(b.email||"").trim().toLowerCase(),phone=String(b.phone||"").trim(),password=String(b.password||"");
        if(!name||username.length<3||!email||!phone||password.length<8) return json({ok:false,error:"Please fill all fields correctly."},400);
        const ex=await env.DB.prepare("SELECT id FROM users WHERE username=? OR email=? LIMIT 1").bind(username,email).first();
        if(ex) return json({ok:false,error:"Username or email already exists."},409);
        const id=uid();
        await env.DB.prepare("INSERT INTO users(id,username,email,password_hash,display_name) VALUES(?,?,?,?,?)").bind(id,username,email,await hashPassword(password),name).run();
        return json({ok:true,user:{id,username,email,display_name:name}},201);
      }

      if(url.pathname==="/api/login"&&request.method==="POST"){
        const b=await request.json(),identity=String(b.identity||"").trim().toLowerCase(),password=String(b.password||"");
        const u=await env.DB.prepare("SELECT id,username,email,password_hash,display_name,avatar_url FROM users WHERE email=? OR username=? LIMIT 1").bind(identity,normalizeUsername(identity)).first();
        if(!u||await hashPassword(password)!==u.password_hash) return json({ok:false,error:"Invalid login details."},401);
        return json({ok:true,message:"Login successful.",user:{id:u.id,username:u.username,email:u.email,display_name:u.display_name,avatar_url:u.avatar_url}});
      }

      if(url.pathname==="/api/users"&&request.method==="GET"){
        const r=await env.DB.prepare("SELECT id,username,display_name,avatar_url FROM users ORDER BY display_name,username").all();
        return json({users:r.results||[]});
      }

      if(url.pathname==="/api/friends"&&request.method==="GET"){
        const me=url.searchParams.get("user_id");
        if(!me) return json({friends:[],requests:[]});
        const f=await env.DB.prepare("SELECT u.id,u.username,u.display_name,u.avatar_url FROM friendships x JOIN users u ON u.id=x.friend_id WHERE x.user_id=? ORDER BY u.display_name,u.username").bind(me).all();
        const q=await env.DB.prepare("SELECT r.id,r.sender_id,u.username,u.display_name FROM friend_requests r JOIN users u ON u.id=r.sender_id WHERE r.receiver_id=? AND r.status='pending' ORDER BY r.created_at DESC").bind(me).all();
        return json({friends:f.results||[],requests:q.results||[]});
      }

      if(url.pathname==="/api/friends/request"&&request.method==="POST"){
        const b=await request.json(),sender=String(b.sender_id||""),receiver=String(b.receiver_id||"");
        if(!sender||!receiver||sender===receiver) return json({ok:false,error:"Invalid friend request."},400);
        const ex=await env.DB.prepare("SELECT status FROM friend_requests WHERE sender_id=? AND receiver_id=?").bind(sender,receiver).first();
        const already=await env.DB.prepare("SELECT user_id FROM friendships WHERE user_id=? AND friend_id=?").bind(sender,receiver).first();
        if(already) return json({ok:false,error:"Already friends."},409);
        if(ex&&ex.status==="pending") return json({ok:false,error:"Friend request already sent."},409);
        const id=uid();
        await env.DB.prepare("INSERT OR REPLACE INTO friend_requests(id,sender_id,receiver_id,status) VALUES(?,?,?,'pending')").bind(id,sender,receiver).run();
        return json({ok:true,id},201);
      }

      if(url.pathname==="/api/friends/accept"&&request.method==="POST"){
        const b=await request.json(),requestId=String(b.request_id||""),me=String(b.user_id||"");
        const r=await env.DB.prepare("SELECT sender_id,receiver_id FROM friend_requests WHERE id=? AND receiver_id=? AND status='pending'").bind(requestId,me).first();
        if(!r) return json({ok:false,error:"Request not found."},404);
        await env.DB.batch([
          env.DB.prepare("UPDATE friend_requests SET status='accepted' WHERE id=?").bind(requestId),
          env.DB.prepare("INSERT OR IGNORE INTO friendships(user_id,friend_id) VALUES(?,?)").bind(r.sender_id,r.receiver_id),
          env.DB.prepare("INSERT OR IGNORE INTO friendships(user_id,friend_id) VALUES(?,?)").bind(r.receiver_id,r.sender_id)
        ]);
        return json({ok:true});
      }

      if(url.pathname==="/api/posts"&&request.method==="GET"){
        const me=url.searchParams.get("user_id")||"";
        const info=await env.DB.prepare("PRAGMA table_info(posts)").all();
        const names=new Set((info.results||[]).map(x=>x.name));
        const contentCol=names.has("content")?"p.content":(names.has("ciphertext")?"p.ciphertext":(names.has("text")?"p.text":"''"));
        if(contentCol==="''") return json({posts:[],error:"Posts table has no content column."},500);
        const r=await env.DB.prepare("SELECT p.id,p.user_id,"+contentCol+" AS content,p.created_at,u.username,u.display_name,u.avatar_url,(SELECT COUNT(*) FROM likes l WHERE l.post_id=p.id) like_count,(SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id) comment_count,(SELECT COUNT(*) FROM likes l2 WHERE l2.post_id=p.id AND l2.user_id=?) liked FROM posts p JOIN users u ON u.id=p.user_id ORDER BY p.created_at DESC LIMIT 50").bind(me).all();
        return json({posts:r.results||[]});
      }

      if(url.pathname==="/api/posts"&&request.method==="POST"){
        const b=await request.json(),content=String(b.content||"").trim(),userId=String(b.user_id||"");
        if(!userId||!content) return json({ok:false,error:"Post cannot be empty."},400);
        if(content.length>2000) return json({ok:false,error:"Post is too long."},400);
        const u=await env.DB.prepare("SELECT id FROM users WHERE id=?").bind(userId).first();
        if(!u) return json({ok:false,error:"User not found."},404);
        const info=await env.DB.prepare("PRAGMA table_info(posts)").all();
        const schema=info.results||[];
        const names=new Set(schema.map(x=>x.name));
        const id=uid(),cols=[],vals=[];
        const add=(name,value)=>{if(names.has(name)){cols.push(name);vals.push(value);}};
        add("id",id);
        add("user_id",userId);
        if(names.has("content")) add("content",content);
        else if(names.has("ciphertext")) add("ciphertext",content);
        else if(names.has("text")) add("text",content);
        for(const col of schema){
          if(cols.includes(col.name)||!col.notnull||col.dflt_value!==null) continue;
          const n=String(col.name).toLowerCase();
          let v="";
          if(n.includes("ciphertext")||n==="content"||n==="text"||n.includes("body")) v=content;
          else if(n.includes("nonce")||n.includes("token")) v=uid();
          else if(n==="user_id"||n.endsWith("_user_id")||n.includes("author")) v=userId;
          else if(n.endsWith("_id")) v=uid();
          else if(n.includes("device")) v="device:"+userId;
          else if(n.includes("conversation")) v="";
          else if(n.includes("created")||n.includes("updated")) v=new Date().toISOString();
          else if(String(col.type||"").toUpperCase().includes("INT")) v=0;
          else v="";
          cols.push(col.name); vals.push(v);
        }
        if(!cols.includes("id")||!cols.includes("user_id")||(!cols.includes("content")&&!cols.includes("ciphertext")&&!cols.includes("text")))
          return json({ok:false,error:"Posts table schema is incompatible.",schema},500);
        const placeholders=cols.map(()=>"?").join(",");
        try{
          await env.DB.prepare("INSERT INTO posts("+cols.join(",")+") VALUES("+placeholders+")").bind(...vals).run();
        }catch(insertError){
          return json({ok:false,error:"Post insert failed: "+(insertError?.message||"unknown"),schema},500);
        }
        return json({ok:true,id},201);
      }

      const likeMatch=url.pathname.match(/^\/api\/posts\/([^/]+)\/like$/);
      if(likeMatch&&request.method==="POST"){
        const postId=likeMatch[1],b=await request.json(),userId=String(b.user_id||"");
        const ex=await env.DB.prepare("SELECT post_id FROM likes WHERE post_id=? AND user_id=?").bind(postId,userId).first();
        if(ex) await env.DB.prepare("DELETE FROM likes WHERE post_id=? AND user_id=?").bind(postId,userId).run();
        else await env.DB.prepare("INSERT INTO likes(post_id,user_id) VALUES(?,?)").bind(postId,userId).run();
        return json({ok:true,liked:!ex});
      }

      const commentMatch=url.pathname.match(/^\/api\/posts\/([^/]+)\/comments$/);
      if(commentMatch&&request.method==="GET"){
        const r=await env.DB.prepare("SELECT c.id,c.content,c.created_at,u.username,u.display_name FROM comments c JOIN users u ON u.id=c.user_id WHERE c.post_id=? ORDER BY c.created_at ASC").bind(commentMatch[1]).all();
        return json({comments:r.results||[]});
      }

      if(commentMatch&&request.method==="POST"){
        const b=await request.json(),content=String(b.content||"").trim(),userId=String(b.user_id||"");
        if(!content||!userId) return json({ok:false,error:"Comment cannot be empty."},400);
        const id=uid();
        await env.DB.prepare("INSERT INTO comments(id,post_id,user_id,content) VALUES(?,?,?,?)").bind(id,commentMatch[1],userId,content).run();
        return json({ok:true,id},201);
      }

      if(url.pathname==="/api/messages"&&request.method==="GET"){
        const a=url.searchParams.get("user_id"),b=url.searchParams.get("with_user_id");
        if(!a||!b) return json({messages:[]});
        const r=await env.DB.prepare("SELECT id,conversation_id,sender_id,receiver_id,sender_device_id,receiver_device_id,content,created_at FROM messages WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?) ORDER BY created_at ASC LIMIT 200").bind(a,b,b,a).all();
        return json({messages:r.results||[]});
      }

      if(url.pathname==="/api/messages"&&request.method==="POST"){
        const b=await request.json(),sender=String(b.sender_id||""),receiver=String(b.receiver_id||""),content=String(b.content||"").trim();
        if(!sender||!receiver||!content) return json({ok:false,error:"Message cannot be empty."},400);
        if(content.length>5000) return json({ok:false,error:"Message is too long."},400);
        if(sender===receiver) return json({ok:false,error:"You cannot message yourself."},400);
        const users=await env.DB.prepare("SELECT id FROM users WHERE id IN (?,?)").bind(sender,receiver).all();
        if((users.results||[]).length!==2) return json({ok:false,error:"User not found."},404);

        const conversationId=[sender,receiver].sort().join(":");
        const senderDeviceId="device:"+sender;
        const receiverDeviceId="device:"+receiver;

        await env.DB.batch([
          env.DB.prepare("INSERT OR IGNORE INTO devices(id,user_id,identity_key) VALUES(?,?,?)").bind(senderDeviceId,sender,uid()),
          env.DB.prepare("INSERT OR IGNORE INTO devices(id,user_id,identity_key) VALUES(?,?,?)").bind(receiverDeviceId,receiver,uid()),
          env.DB.prepare("INSERT OR IGNORE INTO conversations(id) VALUES(?)").bind(conversationId),
          env.DB.prepare("INSERT OR IGNORE INTO conversation_members(conversation_id,device_id) VALUES(?,?)").bind(conversationId,senderDeviceId),
          env.DB.prepare("INSERT OR IGNORE INTO conversation_members(conversation_id,device_id) VALUES(?,?)").bind(conversationId,receiverDeviceId)
        ]);

        const id=uid();
        const msgSchema=await env.DB.prepare("PRAGMA table_info(messages)").all();
        const schema=msgSchema.results||[];
        const names=new Set(schema.map(x=>x.name));
        const cols=[],vals=[];
        const add=(name,value)=>{if(names.has(name)){cols.push(name);vals.push(value);}};
        add("id",id);
        add("conversation_id",conversationId);
        add("sender_id",sender);
        add("receiver_id",receiver);
        add("sender_device_id",senderDeviceId);
        add("receiver_device_id",receiverDeviceId);
        if(names.has("content")) add("content",content);
        else if(names.has("ciphertext")) add("ciphertext",content);
        for(const col of schema){
          if(cols.includes(col.name)||!col.notnull||col.dflt_value!==null) continue;
          const n=String(col.name).toLowerCase();
          let v="";
          if(n.includes("ciphertext")||n==="content"||n==="text"||n.includes("body")) v=content;
          else if(n.includes("nonce")||n.includes("token")) v=uid();
          else if(n==="sender_id"||n==="receiver_id"||n.endsWith("_user_id")) v=(n==="sender_id"?sender:receiver);
          else if(n.includes("sender_device")) v=senderDeviceId;
          else if(n.includes("receiver_device")) v=receiverDeviceId;
          else if(n.includes("conversation")) v=conversationId;
          else if(n.endsWith("_id")) v=uid();
          else if(n.includes("created")||n.includes("updated")) v=new Date().toISOString();
          else if(String(col.type||"").toUpperCase().includes("INT")) v=0;
          cols.push(col.name); vals.push(v);
        }
        if(!cols.includes("id")||!cols.includes("sender_id")||!cols.includes("receiver_id")||
           (!cols.includes("content")&&!cols.includes("ciphertext")))
          return json({ok:false,error:"Messages table schema is incompatible.",schema},500);
        try{
          const placeholders=cols.map(()=>"?").join(",");
          await env.DB.prepare("INSERT INTO messages("+cols.join(",")+") VALUES("+placeholders+")").bind(...vals).run();
        }catch(insertError){
          return json({ok:false,error:"Message insert failed: "+(insertError?.message||"unknown"),schema},500);
        }
        return json({ok:true,id,conversation_id:conversationId},201);
      }

      return json({ok:false,error:"API route not found."},404);
    }catch(e){
      return json({ok:false,error:"Server error: "+(e?.message||"unknown"),build:BUILD_VERSION},500);
    }
  }
  return new Response(FRONTEND_HTML, {headers: {"Content-Type":"text/html;charset=UTF-8","Cache-Control":"no-store, no-cache, must-revalidate"}});
}};

const FRONTEND_HTML = "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"UTF-8\">\n<meta name=\"viewport\" content=\"width=device-width,initial-scale=1,viewport-fit=cover\">\n<meta name=\"theme-color\" content=\"#6d5dfc\">\n<title>Social Chat</title>\n<style>\n:root{--p:#6d5dfc;--p2:#5848e8;--bg:#f6f7fb;--card:#fff;--text:#182033;--muted:#7b8498;--line:#e7e9f0;--soft:#f0efff}\n*{box-sizing:border-box}body{margin:0;font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif;background:var(--bg);color:var(--text)}\nbutton,input,textarea,select{font:inherit}button{cursor:pointer}.shell{max-width:520px;margin:auto;min-height:100vh}\n.auth{padding:34px 20px;min-height:100vh;display:flex;align-items:center}.auth-card{width:100%;background:#fff;border-radius:28px;padding:28px;box-shadow:0 15px 45px #20204014}\n.logo{width:58px;height:58px;border-radius:18px;background:linear-gradient(135deg,#7d6cff,#5140df);color:#fff;display:grid;place-items:center;font-size:26px;font-weight:800;margin-bottom:18px}\nh1{font-size:29px;margin:0 0 6px}h2{font-size:21px;margin:0}.sub,.muted{color:var(--muted)}.sub{margin:0 0 22px;font-size:14px}\n.field{width:100%;border:1px solid var(--line);background:#fafbfe;border-radius:13px;padding:13px 14px;margin:7px 0;outline:none}.field:focus{border-color:var(--p);box-shadow:0 0 0 3px #6d5dfc18}\n.primary{width:100%;border:0;border-radius:13px;padding:13px;background:var(--p);color:#fff;font-weight:700;margin-top:8px}.primary:active{transform:scale(.99)}\n.linkbtn{border:0;background:none;color:var(--p);font-weight:700;padding:4px}.err{color:#c62828;font-size:13px;min-height:18px}\n.app{display:none;padding-bottom:78px}.top{padding:20px 18px 10px;display:flex;align-items:center;justify-content:space-between}.brand{font-size:22px;font-weight:800}.iconbtn{width:40px;height:40px;border:0;border-radius:13px;background:#fff;font-size:18px}\n.page{padding:8px 14px}.view{display:none}.view.active{display:block}\n.profile-mini{background:linear-gradient(135deg,#6d5dfc,#8b7fff);color:#fff;border-radius:22px;padding:18px;margin-bottom:14px;display:flex;align-items:center;gap:13px}.avatar{width:48px;height:48px;border-radius:50%;background:#fff;color:var(--p);display:grid;place-items:center;font-weight:800;font-size:18px;flex:none}.profile-mini .muted{color:#e8e6ff}\n.card{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:15px;margin:10px 0}.composer textarea{width:100%;min-height:78px;resize:none;border:0;outline:0;font-size:16px}.composer-bottom{display:flex;justify-content:flex-end}.smallbtn{border:0;border-radius:11px;padding:9px 15px;background:var(--p);color:#fff;font-weight:700}\n.post-head,.person{display:flex;align-items:center;gap:11px}.post-head .avatar,.person .avatar{width:42px;height:42px;font-size:15px}.post-name{font-weight:750}.handle,.time{font-size:12px;color:var(--muted)}.post-content{white-space:pre-wrap;line-height:1.45;margin:12px 0}.actions{display:flex;gap:8px;border-top:1px solid var(--line);padding-top:9px}.action{border:0;background:none;color:var(--muted);padding:7px 9px;border-radius:9px}.action.liked{color:#e44}\n.search{display:flex;gap:8px}.search .field{margin:0}.search button{width:auto;padding:0 17px}\n.request{background:var(--soft)}.request button{margin-top:8px}\n.friend-row{display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--line)}.friend-row:last-child{border-bottom:0}.chat-select{margin-bottom:8px}\n.chatbox{height:52vh;min-height:300px;max-height:520px;overflow:auto;background:#f0f2f8;border-radius:18px;padding:12px}.bubble{max-width:82%;padding:10px 13px;border-radius:16px;margin:7px 0;background:#fff;box-shadow:0 2px 8px #00000008;line-height:1.35}.bubble.me{margin-left:auto;background:var(--p);color:#fff;border-bottom-right-radius:5px}.bubble.them{border-bottom-left-radius:5px}.sendrow{display:flex;gap:8px;margin-top:8px}.sendrow .field{margin:0}.sendrow button{width:58px;border:0;border-radius:13px;background:var(--p);color:#fff;font-weight:800}\n.profile-card{text-align:center;padding:25px}.big-avatar{width:82px;height:82px;border-radius:50%;background:var(--soft);color:var(--p);display:grid;place-items:center;font-size:30px;font-weight:800;margin:0 auto 12px}\n.bottom{position:fixed;bottom:0;left:50%;transform:translateX(-50%);width:min(520px,100%);height:68px;background:#fff;border-top:1px solid var(--line);display:flex;justify-content:space-around;padding:7px 6px calc(7px + env(safe-area-inset-bottom));z-index:5}.nav{flex:1;border:0;background:none;color:var(--muted);font-size:11px;font-weight:650;border-radius:13px}.nav span{display:block;font-size:20px;line-height:24px}.nav.active{color:var(--p);background:var(--soft)}\n.empty{text-align:center;padding:28px 12px;color:var(--muted)}.toast{position:fixed;top:16px;left:50%;transform:translateX(-50%);background:#182033;color:#fff;padding:10px 15px;border-radius:12px;display:none;z-index:20;font-size:13px}\n@media(min-width:521px){body{background:#eceef5}.shell{background:var(--bg)}}\n</style>\n</head>\n<body>\n<div class=\"shell\">\n<section id=\"auth\" class=\"auth\">\n<div class=\"auth-card\">\n<div class=\"logo\">SC</div>\n<h1>Social Chat</h1><p class=\"sub\">Connect, share and chat with your friends.</p>\n<div id=\"loginPane\">\n<input id=\"li\" class=\"field\" placeholder=\"Username or email\" autocomplete=\"username\">\n<input id=\"lp\" class=\"field\" type=\"password\" placeholder=\"Password\" autocomplete=\"current-password\">\n<button class=\"primary\" onclick=\"login()\">Log in</button><p id=\"le\" class=\"err\"></p>\n<p class=\"muted\">New here? <button class=\"linkbtn\" onclick=\"toggleAuth(true)\">Create account</button></p>\n</div>\n<div id=\"signupPane\" style=\"display:none\">\n<input id=\"sn\" class=\"field\" placeholder=\"Full name\">\n<input id=\"su\" class=\"field\" placeholder=\"Username\">\n<input id=\"se\" class=\"field\" type=\"email\" placeholder=\"Email\">\n<input id=\"sp\" class=\"field\" type=\"password\" placeholder=\"Password (8+ characters)\">\n<button class=\"primary\" onclick=\"signup()\">Create account</button><p id=\"se2\" class=\"err\"></p>\n<p class=\"muted\">Already have an account? <button class=\"linkbtn\" onclick=\"toggleAuth(false)\">Log in</button></p>\n</div>\n</div>\n</section>\n\n<section id=\"app\" class=\"app\">\n<header class=\"top\"><div class=\"brand\">Social Chat</div><button class=\"iconbtn\" onclick=\"refreshCurrent()\">↻</button></header>\n<div class=\"page\">\n<div id=\"home\" class=\"view active\">\n<div class=\"profile-mini\"><div id=\"miniAvatar\" class=\"avatar\"></div><div><div id=\"miniName\"></div><div id=\"miniHandle\" class=\"muted\"></div></div></div>\n<div class=\"card composer\"><textarea id=\"postText\" maxlength=\"2000\" placeholder=\"What's on your mind?\"></textarea><div class=\"composer-bottom\"><button class=\"smallbtn\" onclick=\"createPost()\">Post</button></div></div>\n<div id=\"feed\"></div>\n</div>\n\n<div id=\"friendsView\" class=\"view\">\n<div class=\"card\"><h2>Find people</h2><p class=\"muted\">Search by username and send a friend request.</p><div class=\"search\"><input id=\"find\" class=\"field\" placeholder=\"@username\"><button class=\"smallbtn\" onclick=\"addFriend()\">Add</button></div></div>\n<div id=\"requests\"></div><div class=\"card\"><h2>Your friends</h2><div id=\"friends\"></div></div>\n</div>\n\n<div id=\"chatView\" class=\"view\">\n<div class=\"card\"><h2>Messages</h2><select id=\"with\" class=\"field chat-select\" onchange=\"loadMessages()\"></select><div id=\"chat\" class=\"chatbox\"></div><div class=\"sendrow\"><input id=\"msg\" class=\"field\" placeholder=\"Write a message...\" onkeydown=\"if(event.key==='Enter')send()\"><button onclick=\"send()\">➤</button></div></div>\n</div>\n\n<div id=\"profileView\" class=\"view\">\n<div class=\"card profile-card\"><div id=\"bigAvatar\" class=\"big-avatar\"></div><h2 id=\"profileName\"></h2><p id=\"profileHandle\" class=\"muted\"></p><p id=\"profileEmail\" class=\"muted\"></p><button class=\"primary\" onclick=\"logout()\">Log out</button></div>\n</div>\n</div>\n<nav class=\"bottom\">\n<button class=\"nav active\" data-view=\"home\" onclick=\"navTo('home')\"><span>⌂</span>Home</button>\n<button class=\"nav\" data-view=\"friendsView\" onclick=\"navTo('friendsView')\"><span>♧</span>Friends</button>\n<button class=\"nav\" data-view=\"chatView\" onclick=\"navTo('chatView')\"><span>◌</span>Chat</button>\n<button class=\"nav\" data-view=\"profileView\" onclick=\"navTo('profileView')\"><span>◎</span>Profile</button>\n</nav>\n</section>\n<div id=\"toast\" class=\"toast\"></div>\n</div>\n\n<script>\nlet me=null,friendCache=[];\nconst $=id=>document.getElementById(id);\nasync function api(u,o){try{const r=await fetch(u,o);return await r.json()}catch(e){return{ok:false,error:'Network error'}}}\nfunction toggleAuth(sign){$('loginPane').style.display=sign?'none':'block';$('signupPane').style.display=sign?'block':'none'}\nfunction initials(n){return String(n||'?').split(/\\s+/).map(x=>x[0]).slice(0,2).join('').toUpperCase()}\nfunction esc(s){return String(s||'').replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]))}\nfunction toast(t){$('toast').textContent=t;$('toast').style.display='block';setTimeout(()=>{$('toast').style.display='none'},1800)}\nfunction navTo(id){document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));$(id).classList.add('active');document.querySelectorAll('.nav').forEach(n=>n.classList.toggle('active',n.dataset.view===id));if(id==='home')loadPosts();if(id==='friendsView')loadFriends();if(id==='chatView')loadMessages()}\nfunction enter(){localStorage.setItem('social_user',JSON.stringify(me));$('auth').style.display='none';$('app').style.display='block';$('miniName').textContent=me.display_name;$('miniHandle').textContent='@'+me.username;$('miniAvatar').textContent=initials(me.display_name);$('bigAvatar').textContent=initials(me.display_name);$('profileName').textContent=me.display_name;$('profileHandle').textContent='@'+me.username;$('profileEmail').textContent=me.email;loadPosts();loadFriends()}\nasync function signup(){const d=await api('/api/signup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:$('sn').value,username:$('su').value,email:$('se').value,password:$('sp').value,phone:'web'})});if(!d.ok){$('se2').textContent=d.error;return}me=d.user;enter()}\nasync function login(){const d=await api('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({identity:$('li').value,password:$('lp').value})});if(!d.ok){$('le').textContent=d.error;return}me=d.user;enter()}\nfunction logout(){me=null;localStorage.removeItem('social_user');$('app').style.display='none';$('auth').style.display='flex';toggleAuth(false)}\nasync function loadPosts(){if(!me)return;const d=await api('/api/posts?user_id='+encodeURIComponent(me.id));$('feed').innerHTML=(d.posts||[]).map(p=>'<article class=\"card\"><div class=\"post-head\"><div class=\"avatar\">'+initials(p.display_name)+'</div><div><div class=\"post-name\">'+esc(p.display_name)+'</div><div class=\"handle\">@'+esc(p.username)+' · '+esc(p.created_at)+'</div></div></div><div class=\"post-content\">'+esc(p.content)+'</div><div class=\"actions\"><button class=\"action '+(Number(p.liked)?'liked':'')+'\" onclick=\"likePost(\\''+p.id+'\\')\">♥ '+p.like_count+'</button><button class=\"action\">💬 '+p.comment_count+'</button></div></article>').join('')||'<div class=\"empty\">No posts yet. Be the first to share something!</div>'}\nasync function createPost(){
  const box=$('postText'),btn=document.querySelector('.composer .smallbtn');
  const t=box.value.trim();
  if(!t){toast('Write something first');return}
  if(!me||!me.id){toast('Please log in again');return}
  const draft=t;
  sessionStorage.setItem('pending_post',draft);
  if(btn){btn.disabled=true;btn.textContent='Posting...'}
  const d=await api('/api/posts',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user_id:me.id,content:draft})});
  if(btn){btn.disabled=false;btn.textContent='Post'}
  if(!d.ok){
    box.value=draft;
    sessionStorage.setItem('pending_post',draft);
    toast(d.error||'Post failed');
    return
  }
  await loadPosts();
  const feed=document.getElementById('feed');
  const visible=feed&&feed.textContent.includes(draft);
  if(visible){
    box.value='';
    sessionStorage.removeItem('pending_post');
    toast('Post published');
  }else{
    box.value=draft;
    toast('Post saved, but feed refresh failed. Text kept.');
  }
}\nasync function likePost(id){const d=await api('/api/posts/'+id+'/like',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user_id:me.id})});if(d.ok)loadPosts()}\nasync function loadFriends(){if(!me)return;const d=await api('/api/friends?user_id='+me.id);friendCache=d.friends||[];$('requests').innerHTML=(d.requests||[]).map(x=>'<div class=\"card request\"><div class=\"person\"><div class=\"avatar\">'+initials(x.display_name)+'</div><div><b>'+esc(x.display_name)+'</b><div class=\"handle\">@'+esc(x.username)+'</div></div></div><button class=\"smallbtn\" onclick=\"accept(\\''+x.id+'\\')\">Accept request</button></div>').join('');$('friends').innerHTML=friendCache.map(x=>'<div class=\"friend-row\"><div class=\"person\"><div class=\"avatar\">'+initials(x.display_name)+'</div><div><b>'+esc(x.display_name)+'</b><div class=\"handle\">@'+esc(x.username)+'</div></div></div><button class=\"action\" onclick=\"openChat(\\''+x.id+'\\')\">Chat</button></div>').join('')||'<div class=\"empty\">No friends yet.</div>';$('with').innerHTML=friendCache.map(x=>'<option value=\"'+x.id+'\">'+esc(x.display_name)+' @'+esc(x.username)+'</option>').join('')||'<option value=\"\">Add a friend to start chatting</option>'}\nasync function addFriend(){const u=$('find').value.trim().replace(/^@/,'').toLowerCase();if(!u)return;const d=await api('/api/users');const x=(d.users||[]).find(v=>v.username===u);if(!x){toast('User not found');return}const r=await api('/api/friends/request',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({sender_id:me.id,receiver_id:x.id})});toast(r.ok?'Friend request sent':r.error);if(r.ok)$('find').value='';loadFriends()}\nasync function accept(id){const r=await api('/api/friends/accept',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({request_id:id,user_id:me.id})});toast(r.ok?'Friend added':r.error);loadFriends()}\nfunction openChat(id){$('with').value=id;navTo('chatView');loadMessages()}\nasync function loadMessages(){const x=$('with').value;if(!x||!me){$('chat').innerHTML='<div class=\"empty\">Choose a friend to start chatting.</div>';return}const d=await api('/api/messages?user_id='+me.id+'&with_user_id='+x);$('chat').innerHTML=(d.messages||[]).map(m=>'<div class=\"bubble '+(m.sender_id===me.id?'me':'them')+'\">'+esc(m.content)+'</div>').join('')||'<div class=\"empty\">Start the conversation.</div>';$('chat').scrollTop=$('chat').scrollHeight}\nasync function send(){const x=$('with').value,t=$('msg').value.trim();if(!x||!t)return;const r=await api('/api/messages',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({sender_id:me.id,receiver_id:x,content:t})});if(!r.ok){toast(r.error);return}$('msg').value='';loadMessages()}\nfunction refreshCurrent(){const v=document.querySelector('.view.active');if(v)navTo(v.id)}\ntry{const saved=localStorage.getItem('social_user');if(saved){me=JSON.parse(saved);enter()}}catch(e){}\n</script>\n</body>\n</html>";