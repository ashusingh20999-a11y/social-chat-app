const API_BASE = "/api";
const tabs = document.querySelectorAll(".tab");
const forms = document.querySelectorAll(".form");
const message = document.getElementById("message");

function show(target) {
  forms.forEach(f => f.classList.remove("active"));
  document.getElementById(target).classList.add("active");
  tabs.forEach(t => t.classList.toggle("active", t.dataset.target === target));
  message.classList.remove("show");
}
tabs.forEach(t => t.addEventListener("click", () => show(t.dataset.target)));
document.querySelectorAll(".switch-tab").forEach(b => b.addEventListener("click", () => show(b.dataset.target)));
document.querySelectorAll(".show-pass").forEach(b => b.addEventListener("click", () => {
  const i = document.getElementById(b.dataset.for);
  i.type = i.type === "password" ? "text" : "password";
  b.textContent = i.type === "password" ? "Show" : "Hide";
}));

function notify(text) {
  message.textContent = text;
  message.classList.add("show");
  window.scrollTo({ top: 0, behavior: "smooth" });
}

async function api(path, body) {
  const response = await fetch(API_BASE + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Something went wrong.");
  return data;
}

document.getElementById("login").addEventListener("submit", async e => {
  e.preventDefault();
  try {
    const data = await api("/login", {
      identity: document.getElementById("loginIdentity").value,
      password: document.getElementById("loginPassword").value
    });
    sessionStorage.setItem("socialChatUser", JSON.stringify(data.user));
    notify("Login successful. Welcome back!");
  } catch (error) {
    notify(error.message);
  }
});

document.getElementById("signup").addEventListener("submit", async e => {
  e.preventDefault();

  const password = document.getElementById("password").value;
  const confirm = document.getElementById("confirmPassword").value;

  if (password !== confirm) {
    notify("Passwords do not match.");
    document.getElementById("confirmPassword").classList.add("shake");
    setTimeout(() => document.getElementById("confirmPassword").classList.remove("shake"), 600);
    return;
  }

  try {
    const data = await api("/signup", {
      name: document.getElementById("name").value,
      username: document.getElementById("username").value,
      email: document.getElementById("email").value,
      phone: document.getElementById("phone").value,
      password
    });

    sessionStorage.setItem("socialChatUser", JSON.stringify(data.user));
    notify("Account created successfully!");
    e.target.reset();
  } catch (error) {
    notify(error.message);
  }
});

document.getElementById("forgotBtn").addEventListener("click", () => show("forgot"));

document.getElementById("resetBtn").addEventListener("click", () => {
  const e = document.getElementById("resetEmail");
  if (!e.value) {
    e.focus();
    return;
  }
  notify("Password reset/OTP delivery will be connected next.");
});

document.getElementById("googleBtn").addEventListener("click", () =>
  notify("Google authentication will be connected after the core account flow.")
);

document.getElementById("googleSignupBtn").addEventListener("click", () =>
  notify("Google authentication will be connected after the core account flow.")
);