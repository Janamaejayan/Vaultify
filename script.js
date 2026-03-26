/* ============================================================
   VAULTIFY — script.js
   Secure Password Manager · SPA connected to Flask REST API
   All auth via JWT (stored in sessionStorage).
   No plaintext passwords ever stored client-side.
============================================================ */

'use strict';

/* ────────────────────────────────────────────────────────────
   API CONFIGURATION
   Change BASE_URL if your Flask server runs on a different port.
──────────────────────────────────────────────────────────── */
const BASE_URL = 'http://localhost:5000/api';

/* ────────────────────────────────────────────────────────────
   SESSION HELPERS
   JWT stored in sessionStorage (cleared on tab close).
──────────────────────────────────────────────────────────── */
function getToken()              { return sessionStorage.getItem('vaultify_token'); }
function getUsername()           { return sessionStorage.getItem('vaultify_username'); }
function setSession(token, user) {
  sessionStorage.setItem('vaultify_token',    token);
  sessionStorage.setItem('vaultify_username', user);
}
function clearSession() {
  sessionStorage.removeItem('vaultify_token');
  sessionStorage.removeItem('vaultify_username');
}

/* ────────────────────────────────────────────────────────────
   API FETCH HELPER
──────────────────────────────────────────────────────────── */
/**
 * Wrapper around fetch() that:
 *  - Sets Content-Type: application/json
 *  - Adds Authorization: Bearer <token> if available
 *  - Returns the parsed JSON body (or throws on HTTP errors)
 * @param {string} path        — relative path e.g. '/auth/login'
 * @param {object} [options]   — standard fetch options
 */
async function apiFetch(path, options = {}) {
  const token = getToken();
  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
    ...(options.headers || {}),
  };

  const response = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers,
  });

  // Try to parse JSON even on error responses
  let data;
  try { data = await response.json(); } catch { data = {}; }

  if (!response.ok) {
    // Normalize: use data.error or a generic message
    throw new Error(data.error || `Request failed (${response.status})`);
  }
  return data;
}

/* ────────────────────────────────────────────────────────────
   TOAST NOTIFICATIONS
──────────────────────────────────────────────────────────── */
const TOAST_ICONS = {
  success: 'fa-circle-check',
  error:   'fa-circle-xmark',
  info:    'fa-circle-info',
  warning: 'fa-triangle-exclamation',
};

function showToast(type, message, duration = 3500) {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `<i class="fas ${TOAST_ICONS[type]}"></i><span>${message}</span>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.classList.add('fade-out');
    toast.addEventListener('animationend', () => toast.remove());
  }, duration);
}

/* ────────────────────────────────────────────────────────────
   PASSWORD STRENGTH CHECKER
──────────────────────────────────────────────────────────── */
function checkStrength(password) {
  if (!password) return { score: 0, label: '', color: '' };
  let score = 0;
  if (password.length >= 8)          score++;
  if (password.length >= 12)         score++;
  if (/[A-Z]/.test(password))        score++;
  if (/[0-9]/.test(password))        score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;

  const map = [
    { label: '',            color: '' },
    { label: 'Very Weak',   color: '#e74c3c' },
    { label: 'Weak',        color: '#e67e22' },
    { label: 'Medium',      color: '#f39c12' },
    { label: 'Strong',      color: '#2ecc71' },
    { label: 'Very Strong', color: '#1abc9c' },
  ];
  return { score, ...map[score] };
}

function updateStrengthUI(barId, labelId, password) {
  const bar   = document.getElementById(barId);
  const label = document.getElementById(labelId);
  if (!bar || !label) return;
  const { score, label: lbl, color } = checkStrength(password);
  bar.style.width      = `${score === 0 ? 0 : (score / 5) * 100}%`;
  bar.style.background = color;
  label.textContent    = lbl;
  label.style.color    = color;
}

/* ────────────────────────────────────────────────────────────
   TOGGLE PASSWORD VISIBILITY
──────────────────────────────────────────────────────────── */
function initToggleButtons() {
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('.toggle-pw');
    if (!btn) return;
    const targetId = btn.dataset.target;
    if (!targetId) return;
    const input = document.getElementById(targetId);
    if (!input) return;
    const isHidden = input.type === 'password';
    input.type = isHidden ? 'text' : 'password';
    const icon = btn.querySelector('i');
    icon.classList.toggle('fa-eye',       !isHidden);
    icon.classList.toggle('fa-eye-slash',  isHidden);
  });
}

/* ────────────────────────────────────────────────────────────
   SPA NAVIGATION
──────────────────────────────────────────────────────────── */
const PAGE_MAP = {
  'add-password':   { sectionId: 'page-add-password',  title: 'Add Password'       },
  'view-passwords': { sectionId: 'page-view-passwords', title: 'Stored Passwords'   },
  'generator':      { sectionId: 'page-generator',      title: 'Password Generator' },
  'activity-logs':  { sectionId: 'page-activity-logs',  title: 'Activity Logs'      },
};

// In-memory activity log (session-scoped — not persisted to backend)
const activityLog = [];

function addLog(type, message) {
  activityLog.unshift({ type, message, time: new Date().toISOString() });
  if (activityLog.length > 200) activityLog.pop();
}

function navigateTo(page) {
  document.querySelectorAll('.page-section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const target = PAGE_MAP[page];
  if (!target) return;
  document.getElementById(target.sectionId)?.classList.add('active');
  document.querySelector(`.nav-item[data-page="${page}"]`)?.classList.add('active');
  const titleEl = document.getElementById('topbar-title');
  if (titleEl) titleEl.textContent = target.title;
  document.getElementById('sidebar')?.classList.remove('open');
  if (page === 'view-passwords') loadPasswordTable();
  if (page === 'activity-logs')  renderLogs();
}

/* ────────────────────────────────────────────────────────────
   DASHBOARD
──────────────────────────────────────────────────────────── */
function showDashboard(username) {
  document.getElementById('auth-wrapper').classList.add('hidden');
  document.getElementById('dashboard').classList.remove('hidden');
  document.getElementById('topbar-username').textContent = username;
  addLog('success', `Logged in as "${username}".`);
  navigateTo('add-password');
}

function logout() {
  addLog('info', `User "${getUsername()}" logged out.`);
  clearSession();
  document.getElementById('dashboard').classList.add('hidden');
  document.getElementById('auth-wrapper').classList.remove('hidden');
  showAuthPage('login');
  document.getElementById('login-form').reset();
  clearFieldErrors('login');
  showToast('info', 'You have been logged out.');
}

/* ────────────────────────────────────────────────────────────
   AUTH — LOGIN
──────────────────────────────────────────────────────────── */
function initLoginForm() {
  const form = document.getElementById('login-form');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    clearFieldErrors('login');
    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value;
    let valid = true;
    if (!username) { setFieldError('login-username-err', 'Username is required.'); valid = false; }
    if (!password) { setFieldError('login-password-err', 'Password is required.'); valid = false; }
    if (!valid) return;

    const btn     = document.getElementById('login-btn');
    const alertEl = document.getElementById('login-alert');
    btn.disabled  = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Logging in…';

    try {
      const data = await apiFetch('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      });
      setSession(data.token, data.username);
      showAlert(alertEl, 'success', '✓ Login successful! Redirecting…');
      showToast('success', `Welcome back, ${data.username}!`);
      addLog('success', `Login successful for "${username}".`);
      setTimeout(() => showDashboard(data.username), 700);
    } catch (err) {
      showAlert(alertEl, 'error', `✗ ${err.message}`);
      showToast('error', err.message);
      addLog('error', `Failed login attempt for "${username}": ${err.message}`);
    } finally {
      btn.disabled  = false;
      btn.innerHTML = '<i class="fas fa-right-to-bracket"></i> Login';
    }
  });
}

/* ────────────────────────────────────────────────────────────
   AUTH — REGISTER
──────────────────────────────────────────────────────────── */
function initRegisterForm() {
  const pwInput = document.getElementById('reg-password');
  pwInput.addEventListener('input', () => updateStrengthUI('strength-bar', 'strength-label', pwInput.value));

  const form = document.getElementById('register-form');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    clearFieldErrors('reg');
    const username = document.getElementById('reg-username').value.trim();
    const password = document.getElementById('reg-password').value;
    const confirm  = document.getElementById('reg-confirm').value;
    let valid = true;

    if (!username || username.length < 3) { setFieldError('reg-username-err', 'At least 3 characters required.'); valid = false; }
    if (!password || password.length < 6) { setFieldError('reg-password-err', 'At least 6 characters required.'); valid = false; }
    if (password !== confirm)             { setFieldError('reg-confirm-err',  'Passwords do not match.'); valid = false; }

    const { score } = checkStrength(password);
    if (score < 2) {
      setFieldError('reg-password-err', 'Password too weak. Add uppercase, numbers or symbols.');
      showToast('warning', 'Please choose a stronger password.');
      valid = false;
    }
    if (!valid) return;

    const alertEl = document.getElementById('register-alert');
    try {
      await apiFetch('/auth/register', {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      });
      addLog('success', `New account registered: "${username}".`);
      showToast('success', 'Account created! You can now log in.');
      form.reset();
      updateStrengthUI('strength-bar', 'strength-label', '');
      showAuthPage('login');
    } catch (err) {
      showAlert(alertEl, 'error', `✗ ${err.message}`);
      showToast('error', err.message);
    }
  });
}

/* ── Field / Alert helpers ── */
function showAuthPage(page) {
  document.querySelectorAll('.auth-card').forEach(c => c.classList.remove('active'));
  document.getElementById(`page-${page}`)?.classList.add('active');
}
function setFieldError(id, msg)   { const el = document.getElementById(id); if (el) el.textContent = msg; }
function clearFieldErrors(prefix) {
  document.querySelectorAll(`[id^="${prefix}-"][id$="-err"]`).forEach(el => el.textContent = '');
  ['login-alert', 'register-alert'].forEach(id => document.getElementById(id)?.classList.add('hidden'));
}
function showAlert(el, type, message) {
  el.className = `alert ${type}`;
  el.textContent = message;
  el.classList.remove('hidden');
}

/* ────────────────────────────────────────────────────────────
   ADD PASSWORD
──────────────────────────────────────────────────────────── */
function initAddPasswordForm() {
  const apPass = document.getElementById('ap-pass');
  apPass.addEventListener('input', () => updateStrengthUI('ap-strength-bar', 'ap-strength-label', apPass.value));

  const form = document.getElementById('add-password-form');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const site     = document.getElementById('ap-site').value.trim();
    const username = document.getElementById('ap-user').value.trim();
    const password = document.getElementById('ap-pass').value;
    const alertEl  = document.getElementById('add-password-alert');

    ['ap-site-err', 'ap-user-err', 'ap-pass-err'].forEach(id => { document.getElementById(id).textContent = ''; });
    let valid = true;
    if (!site)     { document.getElementById('ap-site-err').textContent = 'Website name is required.'; valid = false; }
    if (!username) { document.getElementById('ap-user-err').textContent = 'Username is required.';     valid = false; }
    if (!password) { document.getElementById('ap-pass-err').textContent = 'Password is required.';     valid = false; }
    if (!valid) return;

    const { score } = checkStrength(password);
    if (score < 2) showToast('warning', 'Password saved, but it is weak. Consider using the generator!');

    try {
      await apiFetch('/passwords', {
        method:  'POST',
        body: JSON.stringify({ site, site_username: username, password }),
      });
      addLog('success', `Password added for "${site}" (user: ${username}).`);
      showToast('success', `🔒 Password for ${site} encrypted & saved!`);
      showAlert(alertEl, 'success', '🔒 Password encrypted and saved successfully!');
      form.reset();
      updateStrengthUI('ap-strength-bar', 'ap-strength-label', '');
      setTimeout(() => alertEl.classList.add('hidden'), 4000);
    } catch (err) {
      showAlert(alertEl, 'error', `✗ ${err.message}`);
      showToast('error', err.message);
    }
  });
}

/* ────────────────────────────────────────────────────────────
   VIEW PASSWORDS  (from API)
──────────────────────────────────────────────────────────── */
let _passwords = [];          // local cache from last GET /api/passwords
let _visibleIds = new Set();  // track which rows are revealed

async function loadPasswordTable() {
  const tbody  = document.getElementById('pw-table-body');
  const empty  = document.getElementById('pw-empty');
  const table  = document.getElementById('pw-table');
  tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:2rem;color:var(--text-muted)"><i class="fas fa-spinner fa-spin"></i> Loading…</td></tr>';

  try {
    const data = await apiFetch('/passwords');
    _passwords = data.passwords || [];
    renderPasswordTable(document.getElementById('pw-search').value);
  } catch (err) {
    tbody.innerHTML = '';
    table.classList.add('hidden');
    empty.classList.remove('hidden');
    showToast('error', `Could not load passwords: ${err.message}`);
  }
}

function renderPasswordTable(filter = '') {
  const tbody = document.getElementById('pw-table-body');
  const empty = document.getElementById('pw-empty');
  const table = document.getElementById('pw-table');
  tbody.innerHTML = '';

  const filtered = filter
    ? _passwords.filter(p =>
        p.site.toLowerCase().includes(filter.toLowerCase()) ||
        p.site_username.toLowerCase().includes(filter.toLowerCase()))
    : _passwords;

  if (filtered.length === 0) {
    table.classList.add('hidden');
    empty.classList.remove('hidden');
    return;
  }
  table.classList.remove('hidden');
  empty.classList.add('hidden');

  filtered.forEach((entry, i) => {
    const isVisible = _visibleIds.has(entry.id);
    const masked    = '•'.repeat(Math.min((entry.password || '').length, 12));
    const initial   = (entry.site || '?').charAt(0).toUpperCase();

    const tr = document.createElement('tr');
    tr.dataset.id = entry.id;
    tr.innerHTML = `
      <td>${i + 1}</td>
      <td><span class="site-badge"><span class="favicon">${initial}</span>${escHtml(entry.site)}</span></td>
      <td>${escHtml(entry.site_username)}</td>
      <td>
        <div class="pw-cell">
          <span class="pw-text ${isVisible ? '' : 'pw-hidden'}" id="pw-text-${entry.id}">
            ${isVisible ? escHtml(entry.password) : masked}
          </span>
          <button class="toggle-pw" data-row-id="${entry.id}" title="${isVisible ? 'Hide' : 'Show'}">
            <i class="fas ${isVisible ? 'fa-eye-slash' : 'fa-eye'}"></i>
          </button>
        </div>
      </td>
      <td>
        <div class="action-btns">
          <button class="btn-table btn-view"  data-action="toggle" data-id="${entry.id}"><i class="fas fa-eye"></i> View</button>
          <button class="btn-table btn-edit"  data-action="edit"   data-id="${entry.id}"><i class="fas fa-pen"></i> Edit</button>
          <button class="btn-table btn-del"   data-action="delete" data-id="${entry.id}"><i class="fas fa-trash"></i> Delete</button>
        </div>
      </td>`;
    tbody.appendChild(tr);
  });
}

function initPasswordTable() {
  document.getElementById('pw-search').addEventListener('input', (e) => renderPasswordTable(e.target.value));

  document.getElementById('pw-table-body').addEventListener('click', (e) => {
    // Row-level toggle (eye icon inside the password cell)
    const toggleBtn = e.target.closest('[data-row-id]');
    if (toggleBtn) { toggleRow(parseInt(toggleBtn.dataset.rowId)); return; }

    const btn = e.target.closest('[data-action]');
    if (!btn) return;
    const id = parseInt(btn.dataset.id);
    if (btn.dataset.action === 'toggle') toggleRow(id);
    if (btn.dataset.action === 'edit')   openEditModal(id);
    if (btn.dataset.action === 'delete') deleteEntry(id);
  });

  document.getElementById('edit-modal-close').addEventListener('click', closeEditModal);
  document.getElementById('edit-modal').addEventListener('click', (e) => {
    if (e.target === document.getElementById('edit-modal')) closeEditModal();
  });

  document.getElementById('edit-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const id   = parseInt(document.getElementById('edit-idx').value);
    const site = document.getElementById('edit-site').value.trim();
    const user = document.getElementById('edit-user').value.trim();
    const pass = document.getElementById('edit-pass').value;
    if (!site || !user || !pass) { showToast('error', 'All fields are required.'); return; }

    try {
      await apiFetch(`/passwords/${id}`, {
        method: 'PUT',
        body: JSON.stringify({ site, site_username: user, password: pass }),
      });
      // Update local cache
      const entry = _passwords.find(p => p.id === id);
      if (entry) { entry.site = site; entry.site_username = user; entry.password = pass; }
      addLog('info', `Password entry for "${site}" updated.`);
      showToast('info', `✏️ Entry for ${site} updated.`);
      closeEditModal();
      renderPasswordTable(document.getElementById('pw-search').value);
    } catch (err) {
      showToast('error', err.message);
    }
  });
}

function toggleRow(id) {
  _visibleIds.has(id) ? _visibleIds.delete(id) : _visibleIds.add(id);
  renderPasswordTable(document.getElementById('pw-search').value);
}

async function deleteEntry(id) {
  const entry = _passwords.find(p => p.id === id);
  if (!entry) return;
  if (!confirm(`Delete password for "${entry.site}"? This cannot be undone.`)) return;
  try {
    await apiFetch(`/passwords/${id}`, { method: 'DELETE' });
    _passwords = _passwords.filter(p => p.id !== id);
    _visibleIds.delete(id);
    addLog('warning', `Password for "${entry.site}" deleted.`);
    showToast('warning', `🗑️ Password for ${entry.site} deleted.`);
    renderPasswordTable(document.getElementById('pw-search').value);
  } catch (err) {
    showToast('error', err.message);
  }
}

function openEditModal(id) {
  const entry = _passwords.find(p => p.id === id);
  if (!entry) return;
  document.getElementById('edit-idx').value  = id;
  document.getElementById('edit-site').value = entry.site;
  document.getElementById('edit-user').value = entry.site_username;
  document.getElementById('edit-pass').value = entry.password;
  document.getElementById('edit-modal').classList.remove('hidden');
}
function closeEditModal() {
  document.getElementById('edit-modal').classList.add('hidden');
}

function escHtml(str = '') {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/* ────────────────────────────────────────────────────────────
   PASSWORD GENERATOR  (fully client-side — no API needed)
──────────────────────────────────────────────────────────── */
const CHAR_SETS = {
  upper:   'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lower:   'abcdefghijklmnopqrstuvwxyz',
  numbers: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.<>?/',
};

function generatePassword(length, upper, lower, numbers, symbols) {
  let pool = '';
  let required = '';
  if (upper)   { pool += CHAR_SETS.upper;   required += CHAR_SETS.upper[Math.floor(Math.random() * CHAR_SETS.upper.length)]; }
  if (lower)   { pool += CHAR_SETS.lower;   required += CHAR_SETS.lower[Math.floor(Math.random() * CHAR_SETS.lower.length)]; }
  if (numbers) { pool += CHAR_SETS.numbers; required += CHAR_SETS.numbers[Math.floor(Math.random() * CHAR_SETS.numbers.length)]; }
  if (symbols) { pool += CHAR_SETS.symbols; required += CHAR_SETS.symbols[Math.floor(Math.random() * CHAR_SETS.symbols.length)]; }
  if (!pool) pool = CHAR_SETS.lower + CHAR_SETS.upper + CHAR_SETS.numbers;

  const arr = new Uint32Array(length);
  crypto.getRandomValues(arr);
  let pw = Array.from(arr).map(n => pool[n % pool.length]).join('');

  // Guarantee at least one char from each enabled set, then shuffle
  const req = required.split('').sort(() => Math.random() - .5);
  pw = (req.join('') + pw.slice(req.length)).split('');
  for (let i = pw.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [pw[i], pw[j]] = [pw[j], pw[i]];
  }
  return pw.slice(0, length).join('');
}

function initGenerator() {
  const lenInput = document.getElementById('gen-length');
  const lenVal   = document.getElementById('gen-length-val');
  const output   = document.getElementById('gen-output');
  const copyBtn  = document.getElementById('copy-gen-btn');

  lenInput.addEventListener('input', () => lenVal.textContent = lenInput.value);

  document.getElementById('generate-btn').addEventListener('click', () => {
    const upper   = document.getElementById('inc-upper').checked;
    const lower   = document.getElementById('inc-lower').checked;
    const numbers = document.getElementById('inc-numbers').checked;
    const symbols = document.getElementById('inc-symbols').checked;
    if (!upper && !lower && !numbers && !symbols) {
      showToast('warning', 'Select at least one character type.'); return;
    }
    const pw = generatePassword(parseInt(lenInput.value, 10), upper, lower, numbers, symbols);
    output.value = pw;
    updateStrengthUI('gen-strength-bar', 'gen-strength-label', pw);
    addLog('info', `Generated a ${lenInput.value}-character password.`);
  });

  copyBtn.addEventListener('click', () => {
    if (!output.value) { showToast('warning', 'Generate a password first!'); return; }
    copyToClipboard(output.value, 'Password copied to clipboard!');
  });
}

async function copyToClipboard(text, successMsg = 'Copied!') {
  try {
    await navigator.clipboard.writeText(text);
    showToast('success', successMsg);
  } catch {
    const ta = Object.assign(document.createElement('textarea'), { value: text });
    ta.style.cssText = 'position:fixed;opacity:0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    showToast('success', successMsg);
  }
}

/* ────────────────────────────────────────────────────────────
   ACTIVITY LOGS  (in-memory, session-scoped)
──────────────────────────────────────────────────────────── */
const LOG_ICONS = {
  success: 'fa-circle-check',
  error:   'fa-circle-xmark',
  info:    'fa-circle-info',
  warning: 'fa-triangle-exclamation',
};

function formatTime(isoString) {
  return new Date(isoString).toLocaleString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

function renderLogs() {
  const list  = document.getElementById('logs-list');
  const empty = document.getElementById('logs-empty');
  list.innerHTML = '';
  if (activityLog.length === 0) { empty.classList.remove('hidden'); return; }
  empty.classList.add('hidden');
  activityLog.forEach(log => {
    const li = document.createElement('li');
    li.className = `log-item ${log.type}`;
    li.innerHTML = `
      <div class="log-icon"><i class="fas ${LOG_ICONS[log.type] || 'fa-circle-info'}"></i></div>
      <div class="log-body">
        <span class="log-message">${escHtml(log.message)}</span>
        <span class="log-time"><i class="fas fa-clock" style="font-size:.7rem;opacity:.6;"></i> ${formatTime(log.time)}</span>
      </div>
      <span class="log-badge">${log.type}</span>`;
    list.appendChild(li);
  });
}

function initLogs() {
  document.getElementById('clear-logs-btn').addEventListener('click', () => {
    if (!confirm('Clear all activity logs?')) return;
    activityLog.length = 0;
    showToast('info', 'Activity logs cleared.');
    renderLogs();
  });
}

/* ────────────────────────────────────────────────────────────
   SIDEBAR & NAVIGATION
──────────────────────────────────────────────────────────── */
function initNavigation() {
  document.querySelectorAll('.nav-item[data-page]').forEach(item => {
    item.addEventListener('click', (e) => { e.preventDefault(); navigateTo(item.dataset.page); });
  });
  document.getElementById('logout-btn').addEventListener('click', logout);

  const hamburger = document.getElementById('hamburger');
  const sidebar   = document.getElementById('sidebar');
  hamburger.addEventListener('click', () => sidebar.classList.toggle('open'));
  document.addEventListener('click', (e) => {
    if (sidebar.classList.contains('open') &&
        !sidebar.contains(e.target) &&
        !hamburger.contains(e.target)) sidebar.classList.remove('open');
  });
}

function initAuthSwitchers() {
  document.getElementById('go-register').addEventListener('click', (e) => { e.preventDefault(); showAuthPage('register'); });
  document.getElementById('go-login').addEventListener('click',    (e) => { e.preventDefault(); showAuthPage('login'); });
}

function initKeyboardShortcuts() {
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeEditModal();
    if (e.ctrlKey && e.key === 'g' && !document.getElementById('dashboard').classList.contains('hidden')) {
      e.preventDefault(); navigateTo('generator');
    }
  });
}

/* ────────────────────────────────────────────────────────────
   SESSION RESTORE
──────────────────────────────────────────────────────────── */
async function restoreSession() {
  const token    = getToken();
  const username = getUsername();
  if (token && username) {
    // Ping the API to check token is still valid
    try {
      await apiFetch('/passwords');         // any protected endpoint works
      showDashboard(username);
      return;
    } catch {
      // Token expired or invalid — drop it and show login
      clearSession();
    }
  }
  showAuthPage('login');
}

/* ────────────────────────────────────────────────────────────
   INIT
──────────────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  initToggleButtons();
  initAuthSwitchers();
  initLoginForm();
  initRegisterForm();
  initNavigation();
  initAddPasswordForm();
  initPasswordTable();
  initGenerator();
  initLogs();
  initKeyboardShortcuts();
  restoreSession();

  console.log('Vaultify initialised. API:', BASE_URL);
});
