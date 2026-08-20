/* STATE MANAGEMENT */
let currentUser = null;
let activeTab = "tasks";
let isProfileVerification = false;

/* UTILITIES */
function escapeHtml(str) {
  return String(str || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function api(url, options = {}) {
  const res = await fetch(url, {
    credentials: "same-origin",
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });

  let data = null;
  try { data = await res.json(); } catch {}

  if (!res.ok) {
    throw new Error(data?.error || "An unexpected error occurred.");
  }
  return data;
}

function showAuthMessage(msg, type = "error") {
  const box = document.getElementById("authMessage");
  if (!msg) {
    box.classList.add("hidden");
    return;
  }
  box.className = "notice " + type;
  box.textContent = msg;
  box.classList.remove("hidden");
}

/* AUTHENTICATION & VIEWS CONTROL */
function openAuth(mode = "login") {
  document.getElementById("homeArea").classList.add("hidden");
  document.getElementById("appArea").classList.add("hidden");
  document.getElementById("authArea").classList.remove("hidden");
  showAuthMode(mode);
}

function showAuthMode(mode) {
  document.getElementById("loginForm").classList.toggle("hidden", mode !== "login");
  document.getElementById("registerForm").classList.toggle("hidden", mode !== "register");
  document.getElementById("loginTab").classList.toggle("active", mode === "login");
  document.getElementById("registerTab").classList.toggle("active", mode === "register");
  showAuthMessage("");
  renderGoogleButtons();
}

function updateNavigationUI() {
  const isLoggedIn = !!currentUser;
  document.getElementById("mainNav").style.display = isLoggedIn ? "flex" : "none";
  document.getElementById("headerProfile").style.display = isLoggedIn ? "block" : "none";
  
  const bottom = document.getElementById("mobileBottomNav");
  if (isLoggedIn) {
    bottom.classList.add("logged-in");
    document.getElementById("headerAvatarInitials").textContent = (currentUser.name || "U").charAt(0).toUpperCase();
    document.getElementById("profilePanelName").textContent = currentUser.name || "User";
    document.getElementById("profilePanelEmail").textContent = currentUser.email || "";
  } else {
    bottom.classList.remove("logged-in");
  }
}

function toggleProfilePanel(e) {
  e.stopPropagation();
  document.getElementById("profilePanel").classList.toggle("open");
}

window.addEventListener("click", () => {
  const panel = document.getElementById("profilePanel");
  if (panel) panel.classList.remove("open");
});

/* GOOGLE AUTHENTICATION */
async function renderGoogleButtons() {
  if (!window.google || !window.google.accounts) return;
  try {
    const { clientId } = await api("/api/google-config");
    if (!clientId) return;

    window.google.accounts.id.initialize({
      client_id: clientId,
      callback: async (res) => {
        if (res.credential) {
          try {
            showAuthMessage("Signing in with Google...", "success");
            const data = await api("/api/auth/google", {
              method: "POST",
              body: JSON.stringify({ credential: res.credential })
            });
            currentUser = data.user;
            updateNavigationUI();
            renderTasksView();
          } catch (err) {
            showAuthMessage(err.message);
          }
        }
      }
    });

    const lBtn = document.getElementById("googleLoginButton");
    const rBtn = document.getElementById("googleRegisterButton");
    if (lBtn) { lBtn.innerHTML = ""; window.google.accounts.id.renderButton(lBtn, { theme: "outline", size: "large" }); }
    if (rBtn) { rBtn.innerHTML = ""; window.google.accounts.id.renderButton(rBtn, { theme: "outline", size: "large" }); }
  } catch {}
}

/* REGISTER & LOGIN HANDLERS */
async function registerUser(e) {
  e.preventDefault();
  const btn = document.getElementById("btnRegisterSubmit");
  btn.disabled = true; btn.textContent = "Creating Account...";

  try {
    const data = await api("/api/register", {
      method: "POST",
      body: JSON.stringify({
        name: document.getElementById("registerName").value,
        email: document.getElementById("registerEmail").value,
        mobile: document.getElementById("registerMobile").value,
        city: document.getElementById("registerCity").value,
        password: document.getElementById("registerPassword").value
      })
    });

    if (data.verificationRequired) {
      isProfileVerification = false;
      openOtpModal(data.step, data.email, data.mobile);
    }
  } catch (err) {
    showAuthMessage(err.message);
  } finally {
    btn.disabled = false; btn.textContent = "Create Account";
  }
}

async function loginUser(e) {
  e.preventDefault();
  const btn = document.getElementById("btnLoginSubmit");
  btn.disabled = true; btn.textContent = "Logging in...";

  try {
    const data = await api("/api/login", {
      method: "POST",
      body: JSON.stringify({
        email: document.getElementById("loginEmail").value,
        password: document.getElementById("loginPassword").value,
        remember: document.getElementById("loginRemember").checked
      })
    });

    if (data.user) {
      currentUser = data.user;
      updateNavigationUI();
      renderTasksView();
      return;
    }

    if (data.verificationRequired) {
      isProfileVerification = false;
      openOtpModal(data.step, data.email, data.mobile);
    }
  } catch (err) {
    showAuthMessage(err.message);
  } finally {
    btn.disabled = false; btn.textContent = "Login";
  }
}

/* OTP MODAL & VERIFICATION */
function openOtpModal(step, email, mobile) {
  const title = document.getElementById("otpTitle");
  const msg = document.getElementById("otpMessage");

  if (step === "email") {
    title.textContent = "Verify Email Address";
    msg.textContent = `A 6-digit OTP code has been sent to ${email}.`;
  } else {
    title.textContent = "Verify Mobile Number";
    msg.textContent = `A 6-digit OTP code has been sent to ${mobile}.`;
  }

  document.getElementById("otpInput").value = "";
  document.getElementById("otpModal").classList.add("open");
}

function closeOtpModal() {
  document.getElementById("otpModal").classList.remove("open");
}

async function verifyOtp() {
  const otp = document.getElementById("otpInput").value.trim();
  if (!/^\d{6}$/.test(otp)) {
    alert("Please enter a valid 6-digit OTP.");
    return;
  }

  const btn = document.getElementById("btnVerifyOtp");
  btn.disabled = true; btn.textContent = "Verifying...";

  const endpoint = isProfileVerification ? "/api/profile/verify-otp" : "/api/verify-otp";

  try {
    const data = await api(endpoint, {
      method: "POST",
      body: JSON.stringify({ otp })
    });

    if (data.step === "mobile") {
      openOtpModal("mobile", data.email, data.mobile);
      return;
    }

    if (data.user) {
      currentUser = data.user;
      closeOtpModal();
      updateNavigationUI();
      if (isProfileVerification) {
        alert("Mobile number verified successfully!");
        renderProfileView();
      } else {
        renderTasksView();
      }
    }
  } catch (err) {
    alert(err.message);
  } finally {
    btn.disabled = false; btn.textContent = "Verify OTP";
  }
}

async function resendOtp() {
  const endpoint = isProfileVerification ? "/api/profile/resend-otp" : "/api/resend-otp";
  try {
    const data = await api(endpoint, { method: "POST" });
    alert(data.message || "OTP resent successfully.");
  } catch (err) {
    alert(err.message);
  }
}

/* ROUTING & VIEWS RENDERING */
function setActiveNav(tab) {
  activeTab = tab;
  document.querySelectorAll(".nav button").forEach(b => b.classList.remove("active"));
  document.querySelectorAll(".bottom-item").forEach(b => b.classList.remove("active"));

  const navBtn = document.getElementById("nav" + tab.charAt(0).toUpperCase() + tab.slice(1));
  const mbBtn = document.getElementById("mb" + tab.charAt(0).toUpperCase() + tab.slice(1));
  if (navBtn) navBtn.classList.add("active");
  if (mbBtn) mbBtn.classList.add("active");

  document.getElementById("homeArea").classList.add("hidden");
  document.getElementById("authArea").classList.add("hidden");
  document.getElementById("appArea").classList.remove("hidden");
}

/* 1. TASKS VIEW */
async function renderTasksView() {
  if (!currentUser) return openAuth("login");
  setActiveNav("tasks");

  const app = document.getElementById("appContent");
  app.innerHTML = `
    <div class="card">
      <h2>Available Tasks 📋</h2>
      <p class="muted">Complete any task below and submit it for approval.</p>
    </div>
    <div id="tasksList">Loading available tasks...</div>
  `;

  try {
    const tasks = await api("/api/tasks");
    const container = document.getElementById("tasksList");

    if (!tasks || !tasks.length) {
      container.innerHTML = `<div class="card"><p class="muted">No active tasks available right now.</p></div>`;
      return;
    }

    container.innerHTML = `<div class="grid">` + tasks.map(t => `
      <div class="card" style="display:flex; flex-direction:column; justify-content:space-between;">
        <div>
          <span class="badge pending">${escapeHtml(t.type || "General")}</span>
          <h3 style="margin:10px 0 5px;">${escapeHtml(t.title)}</h3>
          <p class="muted" style="font-size:14px; margin-bottom:15px;">${escapeHtml(t.description)}</p>
        </div>
        <div>
          <div class="reward">₹${Number(t.reward).toFixed(2)}</div>
          <button class="primary" onclick="submitTask(${t.id}, this)">Submit Task</button>
        </div>
      </div>
    `).join("") + `</div>`;
  } catch (err) {
    app.innerHTML = `<div class="notice error">${escapeHtml(err.message)}</div>`;
  }
}

async function submitTask(taskId, btn) {
  btn.disabled = true; btn.textContent = "Submitting...";
  try {
    const data = await api(`/api/tasks/${taskId}/submit`, { method: "POST" });
    alert(data.message || "Task submitted successfully.");
    renderSubmissionsView();
  } catch (err) {
    alert(err.message);
    btn.disabled = false; btn.textContent = "Submit Task";
  }
}

/* 2. SUBMISSIONS VIEW */
async function renderSubmissionsView() {
  if (!currentUser) return openAuth("login");
  setActiveNav("submissions");

  const app = document.getElementById("appContent");
  app.innerHTML = `
    <div class="card">
      <h2>My Submissions 📜</h2>
      <p class="muted">Track the review status of your completed tasks.</p>
    </div>
    <div id="submissionsList">Loading submissions...</div>
  `;

  try {
    const list = await api("/api/my-submissions");
    const container = document.getElementById("submissionsList");

    if (!list || !list.length) {
      container.innerHTML = `<div class="card"><p class="muted">You haven't submitted any tasks yet.</p></div>`;
      return;
    }

    container.innerHTML = list.map(s => `
      <div class="card" style="display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:10px;">
        <div>
          <h4 style="margin:0 0 5px;">${escapeHtml(s.taskTitle)}</h4>
          <span class="muted" style="font-size:12px;">Submitted: ${new Date(s.submittedAt).toLocaleString()}</span>
        </div>
        <div style="text-align:right;">
          <div class="reward" style="font-size:18px;">+₹${Number(s.reward).toFixed(2)}</div>
          <span class="badge ${s.status}">${escapeHtml(s.status)}</span>
        </div>
      </div>
    `).join("");
  } catch (err) {
    app.innerHTML = `<div class="notice error">${escapeHtml(err.message)}</div>`;
  }
}

/* 3. WALLET VIEW & WITHDRAWAL */
async function renderWalletView() {
  if (!currentUser) return openAuth("login");
  setActiveNav("wallet");

  const app = document.getElementById("appContent");
  app.innerHTML = `
    <div class="card">
      <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:15px;">
        <div>
          <span class="muted">Wallet Balance</span>
          <h1 style="margin:5px 0; font-size:36px; color:#13a05a;">₹<span id="walletBalance">0.00</span></h1>
        </div>
        <button class="primary" style="width:auto; padding:12px 24px;" onclick="openWithdrawModal()">Request Withdrawal</button>
      </div>
    </div>

    <div class="card">
      <h3>Withdrawal History</h3>
      <div id="withdrawalsList">Loading history...</div>
    </div>

    <!-- WITHDRAW MODAL -->
    <div id="withdrawModal" class="modal">
      <div class="modal-box">
        <div class="modal-head">
          <h3 style="margin:0;">Withdraw Funds</h3>
          <button class="close" onclick="closeWithdrawModal()">×</button>
        </div>
        <form onsubmit="handleWithdraw(event)">
          <label>Amount (₹) (Min ₹100)</label>
          <input id="withdrawAmount" type="number" min="100" step="1" required placeholder="100">
          <br><br>
          <label>Payment Method</label>
          <select id="withdrawMethod" onchange="togglePaymentFields()">
            <option value="UPI">UPI</option>
            <option value="Bank Account">Bank Account</option>
          </select>
          <br><br>

          <div id="upiFields">
            <label>UPI ID</label>
            <input id="withdrawUpiId" type="text" placeholder="username@upi">
          </div>

          <div id="bankFields" class="hidden">
            <label>Account Holder Name</label>
            <input id="withdrawBankName" type="text" placeholder="John Doe">
            <br><br>
            <label>Account Number</label>
            <input id="withdrawAccNo" type="text" placeholder="1234567890">
            <br><br>
            <label>IFSC Code</label>
            <input id="withdrawIfsc" type="text" placeholder="SBIN0001234">
            <br><br>
            <label>Bank Name</label>
            <input id="withdrawBank" type="text" placeholder="State Bank of India">
          </div>
          <br>
          <button class="primary" type="submit" id="btnWithdrawSubmit">Submit Request</button>
        </form>
      </div>
    </div>
  `;

  try {
    const data = await api("/api/wallet");
    currentUser.balance = data.balance;
    document.getElementById("walletBalance").textContent = Number(data.balance || 0).toFixed(2);

    const historyBox = document.getElementById("withdrawalsList");
    if (!data.withdrawals || !data.withdrawals.length) {
      historyBox.innerHTML = `<p class="muted">No withdrawal history found.</p>`;
      return;
    }

    historyBox.innerHTML = data.withdrawals.map(w => `
      <div style="padding:12px 0; border-bottom:1px solid #eee; display:flex; justify-content:space-between; align-items:center;">
        <div>
          <strong>₹${Number(w.amount).toFixed(2)} via ${escapeHtml(w.method)}</strong>
          <div class="muted" style="font-size:12px;">${new Date(w.createdAt).toLocaleString()}</div>
        </div>
        <span class="badge ${w.status}">${escapeHtml(w.status)}</span>
      </div>
    `).join("");
  } catch (err) {
    app.innerHTML = `<div class="notice error">${escapeHtml(err.message)}</div>`;
  }
}

function openWithdrawModal() { document.getElementById("withdrawModal").classList.add("open"); }
function closeWithdrawModal() { document.getElementById("withdrawModal").classList.remove("open"); }

function togglePaymentFields() {
  const method = document.getElementById("withdrawMethod").value;
  document.getElementById("upiFields").classList.toggle("hidden", method !== "UPI");
  document.getElementById("bankFields").classList.toggle("hidden", method !== "Bank Account");
}

async function handleWithdraw(e) {
  e.preventDefault();
  const btn = document.getElementById("btnWithdrawSubmit");
  btn.disabled = true; btn.textContent = "Processing...";

  const method = document.getElementById("withdrawMethod").value;
  const amount = Number(document.getElementById("withdrawAmount").value);
  
  let paymentDetails = {};
  if (method === "UPI") {
    paymentDetails = { upiId: document.getElementById("withdrawUpiId").value };
  } else {
    paymentDetails = {
      accountHolderName: document.getElementById("withdrawBankName").value,
      accountNumber: document.getElementById("withdrawAccNo").value,
      ifscCode: document.getElementById("withdrawIfsc").value,
      bankName: document.getElementById("withdrawBank").value
    };
  }

  try {
    const res = await api("/api/withdraw", {
      method: "POST",
      body: JSON.stringify({ amount, method, paymentDetails })
    });
    alert(res.message);
    closeWithdrawModal();
    renderWalletView();
  } catch (err) {
    alert(err.message);
  } finally {
    btn.disabled = false; btn.textContent = "Submit Request";
  }
}

/* 4. PROFILE VIEW & UPDATES */
async function renderProfileView() {
  if (!currentUser) return openAuth("login");
  setActiveNav("profile");

  const app = document.getElementById("appContent");
  app.innerHTML = `
    <div class="card" style="max-width:600px; margin:0 auto;">
      <h2>User Profile 👤</h2>
      <div id="profileNotice" class="hidden"></div>
      
      <form onsubmit="saveProfile(event)">
        <label>Full Name</label>
        <input id="profName" type="text" required value="${escapeHtml(currentUser.name)}">
        <br><br>
        <label>Email Address</label>
        <input type="text" disabled value="${escapeHtml(currentUser.email)}" style="background:#f1f3f7;">
        <span class="muted" style="font-size:12px;">Email cannot be changed directly.</span>
        <br><br>
        <label>Mobile Number</label>
        <input id="profMobile" type="tel" value="${escapeHtml(currentUser.mobile)}" placeholder="+919876543210">
        <span class="muted" style="font-size:12px;">
          Status: ${currentUser.mobileVerified ? '✅ Verified' : '❌ Not Verified'}
        </span>
        <br><br>
        <label>City</label>
        <input id="profCity" type="text" required value="${escapeHtml(currentUser.city)}">
        <br><br>
        <button class="primary" type="submit" id="btnSaveProfile">Save Profile</button>
      </form>
    </div>
  `;
}

async function saveProfile(e) {
  e.preventDefault();
  const btn = document.getElementById("btnSaveProfile");
  btn.disabled = true; btn.textContent = "Saving...";

  try {
    const data = await api("/api/profile", {
      method: "PUT",
      body: JSON.stringify({
        name: document.getElementById("profName").value,
        mobile: document.getElementById("profMobile").value,
        city: document.getElementById("profCity").value
      })
    });

    if (data.verificationRequired) {
      isProfileVerification = true;
      openOtpModal("mobile", currentUser.email, document.getElementById("profMobile").value);
    } else {
      currentUser = data.user;
      alert(data.message || "Profile updated.");
      renderProfileView();
    }
  } catch (err) {
    alert(err.message);
  } finally {
    btn.disabled = false; btn.textContent = "Save Profile";
  }
}

/* SESSION, LOGOUT & LOGO NAVIGATION */
async function logoutUser() {
  try { await api("/api/logout", { method: "POST" }); } catch {}
  currentUser = null;
  updateNavigationUI();
  document.getElementById("appArea").classList.add("hidden");
  document.getElementById("authArea").classList.add("hidden");
  document.getElementById("homeArea").classList.remove("hidden");
}

function handleLogoClick() {
  if (currentUser) {
    renderTasksView();
  } else {
    document.getElementById("appArea").classList.add("hidden");
    document.getElementById("authArea").classList.add("hidden");
    document.getElementById("homeArea").classList.remove("hidden");
  }
}

async function checkSession() {
  try {
    const user = await api("/api/me");
    if (user && user.id) {
      currentUser = user;
      updateNavigationUI();
      renderTasksView();
    } else {
      currentUser = null;
      updateNavigationUI();
      document.getElementById("appArea").classList.add("hidden");
      document.getElementById("authArea").classList.add("hidden");
      document.getElementById("homeArea").classList.remove("hidden");
    }
  } catch {
    currentUser = null;
    updateNavigationUI();
    document.getElementById("appArea").classList.add("hidden");
    document.getElementById("authArea").classList.add("hidden");
    document.getElementById("homeArea").classList.remove("hidden");
  }
}

document.addEventListener("DOMContentLoaded", () => {
  checkSession();
});
