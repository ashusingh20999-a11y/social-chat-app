const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json; charset=utf-8","Access-Control-Allow-Origin":"*","Access-Control-Allow-Methods":"GET,POST,OPTIONS","Access-Control-Allow-Headers":"Content-Type"}});
const BUILD_VERSION="2026-08-31-noassets-10";
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
  if(alters.length) await db.batch(alters);
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
        return json({ok:true,build:BUILD_VERSION,messages:await env.DB.prepare("PRAGMA table_info(messages)").all()});

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
        const r=await env.DB.prepare("SELECT p.id,p.user_id,p.content,p.created_at,u.username,u.display_name,u.avatar_url,(SELECT COUNT(*) FROM likes l WHERE l.post_id=p.id) like_count,(SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id) comment_count,(SELECT COUNT(*) FROM likes l2 WHERE l2.post_id=p.id AND l2.user_id=?) liked FROM posts p JOIN users u ON u.id=p.user_id ORDER BY p.created_at DESC LIMIT 50").bind(me).all();
        return json({posts:r.results||[]});
      }

      if(url.pathname==="/api/posts"&&request.method==="POST"){
        const b=await request.json(),content=String(b.content||"").trim(),userId=String(b.user_id||"");
        if(!userId||!content) return json({ok:false,error:"Post cannot be empty."},400);
        if(content.length>2000) return json({ok:false,error:"Post is too long."},400);
        const u=await env.DB.prepare("SELECT id FROM users WHERE id=?").bind(userId).first();
        if(!u) return json({ok:false,error:"User not found."},404);
        const id=uid();
        await env.DB.prepare("INSERT INTO posts(id,user_id,content) VALUES(?,?,?)").bind(id,userId,content).run();
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
        await env.DB.prepare("INSERT INTO messages(id,conversation_id,sender_id,receiver_id,sender_device_id,receiver_device_id,content) VALUES(?,?,?,?,?,?,?)").bind(id,conversationId,sender,receiver,senderDeviceId,receiverDeviceId,content).run();
        return json({ok:true,id,conversation_id:conversationId},201);
      }

      return json({ok:false,error:"API route not found."},404);
    }catch(e){
      return json({ok:false,error:"Server error: "+(e?.message||"unknown"),build:BUILD_VERSION},500);
    }
  }
  return new Response(FRONTEND_HTML, {headers: {"Content-Type":"text/html;charset=UTF-8"}});
}};

const FRONTEND_HTML = "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Social Chat</title><style>body{font-family:system-ui;margin:0;background:#f5f7fb;color:#172033}main{max-width:520px;margin:auto;padding:20px}input,button,textarea,select{width:100%;box-sizing:border-box;padding:12px;margin:6px 0;border:1px solid #d8dce5;border-radius:10px;font-size:16px}button{background:#2563eb;color:white;border:0;font-weight:600}.card{background:white;padding:16px;border-radius:14px;margin:12px 0;box-shadow:0 2px 10px #00000010}.hide{display:none}.msg{padding:9px 12px;background:#eef2ff;border-radius:10px;margin:6px 0}.right{text-align:right}.err{color:#b42318}</style></head><body><main><section id=\"auth\"><div class=\"card\"><h1>Social Chat</h1><h3>Login</h3><input id=\"li\" placeholder=\"Username or email\"><input id=\"lp\" type=\"password\" placeholder=\"Password\"><button onclick=\"login()\">Login</button><p id=\"le\" class=\"err\"></p><hr><h3>Create account</h3><input id=\"sn\" placeholder=\"Full name\"><input id=\"su\" placeholder=\"Username\"><input id=\"se\" type=\"email\" placeholder=\"Email\"><input id=\"sp\" type=\"password\" placeholder=\"Password (8+ chars)\"><button onclick=\"signup()\">Sign Up</button><p id=\"se2\" class=\"err\"></p></div></section><section id=\"app\" class=\"hide\"><div class=\"card\"><h2>Social Chat</h2><p id=\"welcome\"></p><button onclick=\"logout()\">Logout</button></div><div class=\"card\"><h3>Friends</h3><input id=\"find\" placeholder=\"Search username\"><button onclick=\"addFriend()\">Add Friend</button><div id=\"requests\"></div><div id=\"friends\"></div></div><div class=\"card\"><h3>Chat</h3><select id=\"with\" onchange=\"loadMessages()\"></select><div id=\"chat\"></div><input id=\"msg\" placeholder=\"Type a message...\" onkeydown=\"if(event.key==='Enter')send()\"><button onclick=\"send()\">Send</button></div></section></main><script>let me=null;const $=id=>document.getElementById(id);async function api(u,o){const r=await fetch(u,o);return r.json()}function show(){$('auth').classList.add('hide');$('app').classList.remove('hide');$('welcome').textContent='Welcome, '+me.display_name;loadFriends()}async function signup(){const d=await api('/api/signup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:$('sn').value,username:$('su').value,email:$('se').value,password:$('sp').value,phone:'web'})});if(!d.ok){$('se2').textContent=d.error;return}me=d.user;show()}async function login(){const d=await api('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({identity:$('li').value,password:$('lp').value})});if(!d.ok){$('le').textContent=d.error;return}me=d.user;show()}function logout(){me=null;$('app').classList.add('hide');$('auth').classList.remove('hide')}async function loadFriends(){const d=await api('/api/friends?user_id='+encodeURIComponent(me.id));$('requests').innerHTML=(d.requests||[]).map(x=>'<div class=\"card\">'+x.display_name+' @'+x.username+'<button onclick=\"accept(\\\\''+x.id+'\\\\')\">Accept</button></div>').join('');$('friends').innerHTML=(d.friends||[]).map(x=>'<div>'+x.display_name+' @'+x.username+'</div>').join('')||'<p>No friends yet.</p>';$('with').innerHTML=(d.friends||[]).map(x=>'<option value=\"'+x.id+'\">'+x.display_name+' @'+x.username+'</option>').join('');if((d.friends||[]).length)loadMessages()}async function addFriend(){const u=$('find').value.trim().replace(/^@/,'').toLowerCase();if(!u)return;const d=await api('/api/users');const x=(d.users||[]).find(v=>v.username===u);if(!x)return alert('User not found');const r=await api('/api/friends/request',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({sender_id:me.id,receiver_id:x.id})});alert(r.ok?'Friend request sent':r.error);loadFriends()}async function accept(id){const r=await api('/api/friends/accept',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({request_id:id,user_id:me.id})});if(!r.ok)alert(r.error);loadFriends()}async function loadMessages(){const x=$('with').value;if(!x)return;const d=await api('/api/messages?user_id='+me.id+'&with_user_id='+x);$('chat').innerHTML=(d.messages||[]).map(m=>'<div class=\"msg '+(m.sender_id===me.id?'right':'')+'\">'+(m.sender_id===me.id?'You':'Them')+': '+esc(m.content)+'</div>').join('')||'<p>Start the conversation.</p>'}function esc(s){return String(s).replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]))}async function send(){const x=$('with').value,t=$('msg').value.trim();if(!x||!t)return;const r=await api('/api/messages',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({sender_id:me.id,receiver_id:x,content:t})});if(!r.ok)return alert(r.error);$('msg').value='';loadMessages()}</script></body></html>";