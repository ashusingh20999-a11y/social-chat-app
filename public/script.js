const tabs=document.querySelectorAll(".tab");const forms=document.querySelectorAll(".form");const message=document.getElementById("message");
function show(target){forms.forEach(f=>f.classList.remove("active"));document.getElementById(target).classList.add("active");tabs.forEach(t=>t.classList.toggle("active",t.dataset.target===target));message.classList.remove("show");}
tabs.forEach(t=>t.addEventListener("click",()=>show(t.dataset.target)));
document.querySelectorAll(".switch-tab").forEach(b=>b.addEventListener("click",()=>show(b.dataset.target)));
document.querySelectorAll(".show-pass").forEach(b=>b.addEventListener("click",()=>{const i=document.getElementById(b.dataset.for);i.type=i.type==="password"?"text":"password";b.textContent=i.type==="password"?"Show":"Hide"}));
function notify(text){message.textContent=text;message.classList.add("show");window.scrollTo({top:0,behavior:"smooth"})}
document.getElementById("login").addEventListener("submit",e=>{e.preventDefault();notify("Login UI is ready. Connect the authentication backend next.");});
document.getElementById("signup").addEventListener("submit",e=>{e.preventDefault();const p=document.getElementById("password").value,c=document.getElementById("confirmPassword").value;if(p!==c){notify("Passwords do not match.");document.getElementById("confirmPassword").classList.add("shake");setTimeout(()=>document.getElementById("confirmPassword").classList.remove("shake"),600);return}notify("Signup UI is ready. OTP and secure account creation will be connected next.");});
document.getElementById("forgotBtn").addEventListener("click",()=>show("forgot"));
document.getElementById("resetBtn").addEventListener("click",()=>{const e=document.getElementById("resetEmail");if(!e.value){e.focus();return}notify("Reset-code UI is ready. Email/OTP delivery will be connected next.");});
document.getElementById("googleBtn").addEventListener("click",()=>notify("Google authentication will be connected after the backend is added."));
document.getElementById("googleSignupBtn").addEventListener("click",()=>notify("Google authentication will be connected after the backend is added."));