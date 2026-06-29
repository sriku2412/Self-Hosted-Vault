"use strict";

const app = document.getElementById("app");
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const csrfCookieName = "sv_csrf";

const state = {
  config: null,
  user: null,
  encKey: null,
  privateKey: null,
  folders: [],
  collections: [],
  items: [],
  decryptedFolders: new Map(),
  decryptedCollections: new Map(),
  collectionKeys: new Map(),
  decryptedItems: [],
  selectedItemId: null,
  filter: "all",
  search: "",
  authMode: "login",
  pendingTotp: null
};

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => {
    const map = { "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" };
    return map[char];
  });
}

function bytesToB64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.slice(i, i + 0x8000));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function b64ToBytes(value) {
  let normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  while (normalized.length % 4) normalized += "=";
  const binary = atob(normalized);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function randomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function concatBytes(...chunks) {
  const length = chunks.reduce((total, chunk) => total + chunk.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

async function api(path, options = {}) {
  const method = options.method || "GET";
  const headers = {};
  if (options.body) headers["Content-Type"] = "application/json";
  if (["POST", "PUT", "PATCH", "DELETE"].includes(method.toUpperCase())) {
    const csrfToken = readCookie(csrfCookieName);
    if (csrfToken) headers["X-CSRF-Token"] = csrfToken;
  }
  const response = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: Object.keys(headers).length ? headers : undefined,
    body: options.body ? JSON.stringify(options.body) : undefined
  });
  const text = await response.text();
  const data = text ? JSON.parse(text) : {};
  if (!response.ok) {
    throw new Error(data.detail || data.message || `Request failed: ${response.status}`);
  }
  return data;
}

function readCookie(name) {
  const prefix = `${name}=`;
  const cookie = document.cookie
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(prefix));
  return cookie ? decodeURIComponent(cookie.slice(prefix.length)) : "";
}

function showToast(message) {
  let toast = document.querySelector(".toast");
  if (!toast) {
    toast = document.createElement("div");
    toast.className = "toast";
    document.body.appendChild(toast);
  }
  toast.textContent = message;
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => toast.remove(), 3600);
}

async function deriveKeys(password, saltB64, iterations) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        hash: "SHA-256",
        salt: b64ToBytes(saltB64),
        iterations
      },
      baseKey,
      512
    )
  );
  const encRaw = bits.slice(0, 32);
  const authRaw = bits.slice(32, 64);
  const encKey = await crypto.subtle.importKey("raw", encRaw, "AES-GCM", false, [
    "encrypt",
    "decrypt"
  ]);
  const authDigest = new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
      concatBytes(encoder.encode("selfhosted-vault-auth-v1"), authRaw)
    )
  );
  return { encKey, authHash: bytesToB64(authDigest) };
}

async function encryptBytes(key, bytes) {
  const iv = randomBytes(12);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, bytes));
  return { v: 1, alg: "AES-GCM", iv: bytesToB64(iv), ct: bytesToB64(ciphertext) };
}

async function decryptBytes(key, blob) {
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64ToBytes(blob.iv) },
    key,
    b64ToBytes(blob.ct)
  );
  return new Uint8Array(plaintext);
}

async function encryptJson(key, value) {
  return encryptBytes(key, encoder.encode(JSON.stringify(value)));
}

async function decryptJson(key, blob) {
  const plaintext = await decryptBytes(key, blob);
  return JSON.parse(decoder.decode(plaintext));
}

async function generateKeyPair() {
  return crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["encrypt", "decrypt"]
  );
}

async function importPublicKey(publicKeyB64) {
  return crypto.subtle.importKey(
    "spki",
    b64ToBytes(publicKeyB64),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"]
  );
}

async function importPrivateKey(privateKeyBytes) {
  return crypto.subtle.importKey(
    "pkcs8",
    privateKeyBytes,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["decrypt"]
  );
}

async function decryptPrivateKey(user, encKey) {
  const privateKeyBytes = await decryptBytes(encKey, user.encryptedPrivateKey);
  return importPrivateKey(privateKeyBytes);
}

async function wrapCollectionKey(collectionKey, publicKeyB64) {
  const publicKey = await importPublicKey(publicKeyB64);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", collectionKey));
  const wrapped = new Uint8Array(
    await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, raw)
  );
  return bytesToB64(wrapped);
}

async function unwrapCollectionKey(collection) {
  if (state.collectionKeys.has(collection.id)) return state.collectionKeys.get(collection.id);
  const raw = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      state.privateKey,
      b64ToBytes(collection.encryptedCollectionKey)
    )
  );
  const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", true, ["encrypt", "decrypt"]);
  state.collectionKeys.set(collection.id, key);
  return key;
}

async function init() {
  state.config = await api("/api/config");
  document.title = state.config.appName;
  document.addEventListener("click", handleClick);
  document.addEventListener("submit", handleSubmit);
  document.addEventListener("input", handleInput);
  try {
    const me = await api("/api/me");
    renderUnlock(me.user);
  } catch {
    renderAuth();
  }
}

function renderAuth(mode = state.authMode) {
  state.authMode = mode;
  const isLogin = mode === "login";
  app.innerHTML = `
    <main class="auth-shell">
      <section class="auth-panel">
        <h1 class="brand">${escapeHtml(state.config.appName)}</h1>
        <div class="muted">Encrypted self-hosted vault</div>
        <div class="auth-tabs">
          <button type="button" class="${isLogin ? "active" : ""}" data-auth-tab="login">Sign in</button>
          <button type="button" class="${!isLogin ? "active" : ""}" data-auth-tab="register">Create account</button>
        </div>
        ${
          isLogin
            ? `
          <form id="loginForm" class="form-grid">
            <label>Email <input name="email" type="email" autocomplete="username" required /></label>
            <label>Master password <input name="password" type="password" autocomplete="current-password" required /></label>
            <label class="hidden" id="loginTotpLabel">TOTP code <input name="totp" inputmode="numeric" autocomplete="one-time-code" /></label>
            <button class="primary" type="submit">Sign in</button>
            <div class="error" id="authError"></div>
          </form>`
            : `
          <form id="registerForm" class="form-grid">
            <label>Email <input name="email" type="email" autocomplete="username" required /></label>
            <label>Display name <input name="displayName" autocomplete="name" /></label>
            <label>Master password <input name="password" type="password" autocomplete="new-password" minlength="12" required /></label>
            <label>Confirm master password <input name="confirmPassword" type="password" autocomplete="new-password" minlength="12" required /></label>
            <button class="primary" type="submit">Create account</button>
            <div class="notice">The first registered user becomes the administrator. Keep the master password offline; it cannot be recovered.</div>
            <div class="error" id="authError"></div>
          </form>`
        }
      </section>
    </main>
  `;
}

function renderUnlock(user) {
  app.innerHTML = `
    <main class="auth-shell">
      <section class="auth-panel">
        <h1 class="brand">${escapeHtml(state.config.appName)}</h1>
        <p class="muted">${escapeHtml(user.email)}</p>
        <form id="unlockForm" class="form-grid">
          <label>Master password <input name="password" type="password" autocomplete="current-password" required autofocus /></label>
          <button class="primary" type="submit">Unlock vault</button>
          <button type="button" id="logoutBtn">Sign out</button>
          <div class="error" id="authError"></div>
        </form>
      </section>
    </main>
  `;
  state.user = user;
}

async function completeUnlock(user, encKey) {
  state.user = user;
  state.encKey = encKey;
  state.privateKey = await decryptPrivateKey(user, encKey);
  renderShell();
  await reloadVault();
}

function renderShell() {
  app.innerHTML = `
    <div class="shell">
      <header class="topbar">
        <h1>${escapeHtml(state.config.appName)}</h1>
        <div class="topbar-user">
          <span>${escapeHtml(state.user.email)}</span>
          <button type="button" class="small" id="securityBtn">Security</button>
          ${state.user.isAdmin ? '<button type="button" class="small" id="adminBtn">Admin</button>' : ""}
          <button type="button" class="small" id="lockBtn">Lock</button>
          <button type="button" class="small" id="logoutBtn">Sign out</button>
        </div>
      </header>
      <div class="layout">
        <aside class="sidebar" id="sidebar"></aside>
        <main class="main">
          <div class="toolbar">
            <div class="toolbar-left">
              <input class="search" id="searchInput" placeholder="Search vault" value="${escapeHtml(state.search)}" />
            </div>
            <div class="toolbar-right">
              <button type="button" id="addFolderBtn">New folder</button>
              <button type="button" id="addCollectionBtn">New shared vault</button>
              <button type="button" class="primary" id="addItemBtn">New item</button>
            </div>
          </div>
          <div class="content">
            <section class="item-list" id="itemList"></section>
            <section class="detail" id="detail"></section>
          </div>
        </main>
      </div>
    </div>
  `;
}

async function reloadVault() {
  const [foldersData, collectionsData] = await Promise.all([
    api("/api/folders"),
    api("/api/collections")
  ]);
  state.folders = foldersData.folders;
  state.collections = collectionsData.collections;
  state.decryptedFolders = new Map();
  state.decryptedCollections = new Map();
  state.collectionKeys = new Map();

  for (const folder of state.folders) {
    try {
      const name = await decryptJson(state.encKey, folder.encryptedName);
      state.decryptedFolders.set(folder.id, name.name || "Folder");
    } catch {
      state.decryptedFolders.set(folder.id, "Locked folder");
    }
  }

  for (const collection of state.collections) {
    try {
      const key = await unwrapCollectionKey(collection);
      const name = await decryptJson(key, collection.encryptedName);
      state.decryptedCollections.set(collection.id, name.name || "Shared vault");
    } catch {
      state.decryptedCollections.set(collection.id, "Locked shared vault");
    }
  }

  const itemsData = await api("/api/items");
  state.items = itemsData.items;
  state.decryptedItems = [];
  for (const item of state.items) {
    try {
      const key = item.collectionId ? await unwrapCollectionKey(findCollection(item.collectionId)) : state.encKey;
      const payload = await decryptJson(key, item.encryptedPayload);
      state.decryptedItems.push({ ...item, payload });
    } catch {
      state.decryptedItems.push({
        ...item,
        payload: { title: "Locked item", username: "", url: "", notes: "", password: "" },
        locked: true
      });
    }
  }
  renderSidebar();
  renderList();
  renderDetailDefault();
}

function findCollection(id) {
  return state.collections.find((collection) => collection.id === Number(id));
}

function renderSidebar() {
  const personalCount = state.decryptedItems.filter((item) => !item.collectionId).length;
  const allCount = state.decryptedItems.length;
  const folderButtons = state.folders
    .map((folder) => {
      const count = state.decryptedItems.filter((item) => item.folderId === folder.id).length;
      return navButton(`folder:${folder.id}`, state.decryptedFolders.get(folder.id), count);
    })
    .join("");
  const collectionButtons = state.collections
    .map((collection) => {
      const count = state.decryptedItems.filter((item) => item.collectionId === collection.id).length;
      return navButton(`collection:${collection.id}`, state.decryptedCollections.get(collection.id), count);
    })
    .join("");

  document.getElementById("sidebar").innerHTML = `
    <div class="nav-section">
      ${navButton("all", "All items", allCount)}
      ${navButton("personal", "Personal", personalCount)}
    </div>
    <div class="nav-section">
      <div class="nav-heading"><span>Folders</span><button class="small" type="button" id="addFolderBtnSide">Add</button></div>
      ${folderButtons || '<div class="muted">No folders</div>'}
    </div>
    <div class="nav-section">
      <div class="nav-heading"><span>Shared vaults</span><button class="small" type="button" id="addCollectionBtnSide">Add</button></div>
      ${collectionButtons || '<div class="muted">No shared vaults</div>'}
    </div>
  `;
}

function navButton(filter, label, count) {
  return `
    <button type="button" class="nav-item ${state.filter === filter ? "active" : ""}" data-filter="${escapeHtml(filter)}">
      <span>${escapeHtml(label)}</span>
      <span class="count">${count}</span>
    </button>
  `;
}

function filteredItems() {
  const query = state.search.trim().toLowerCase();
  return state.decryptedItems.filter((item) => {
    if (state.filter === "personal" && item.collectionId) return false;
    if (state.filter.startsWith("folder:") && item.folderId !== Number(state.filter.split(":")[1])) return false;
    if (state.filter.startsWith("collection:") && item.collectionId !== Number(state.filter.split(":")[1])) return false;
    if (!query) return true;
    const haystack = [item.payload.title, item.payload.username, item.payload.url, item.payload.notes]
      .join(" ")
      .toLowerCase();
    return haystack.includes(query);
  });
}

function renderList() {
  const rows = filteredItems()
    .map((item) => {
      const subtitle = item.collectionId
        ? state.decryptedCollections.get(item.collectionId)
        : item.payload.username || item.payload.url || state.decryptedFolders.get(item.folderId) || "Personal";
      return `
        <button type="button" class="item-row ${state.selectedItemId === item.id ? "active" : ""}" data-item-id="${item.id}">
          <span class="item-title">${escapeHtml(item.payload.title || "Untitled")}</span>
          <span class="item-subtitle">${escapeHtml(subtitle || "")}</span>
        </button>
      `;
    })
    .join("");
  document.getElementById("itemList").innerHTML = rows || '<div class="empty">No items match this view.</div>';
}

function renderDetailDefault() {
  const detail = document.getElementById("detail");
  if (!detail) return;
  if (state.filter.startsWith("collection:")) {
    renderCollectionDetail(Number(state.filter.split(":")[1]));
    return;
  }
  detail.innerHTML = '<div class="empty">Select an item or create a new one.</div>';
}

function renderItemDetail(item = null) {
  const isNew = !item;
  const payload = item?.payload || { title: "", username: "", password: "", url: "", notes: "" };
  const inferredCollection = state.filter.startsWith("collection:") ? Number(state.filter.split(":")[1]) : null;
  const collectionId = item?.collectionId || inferredCollection;
  const folderId = item?.folderId || (state.filter.startsWith("folder:") ? Number(state.filter.split(":")[1]) : "");
  const scopeOptions = [
    `<option value="personal" ${collectionId ? "" : "selected"}>Personal</option>`,
    ...state.collections.map((collection) => {
      const selected = collection.id === collectionId ? "selected" : "";
      return `<option value="collection:${collection.id}" ${selected}>${escapeHtml(state.decryptedCollections.get(collection.id))}</option>`;
    })
  ].join("");
  const folderOptions = [
    '<option value="">No folder</option>',
    ...state.folders.map((folder) => {
      const selected = folder.id === folderId ? "selected" : "";
      return `<option value="${folder.id}" ${selected}>${escapeHtml(state.decryptedFolders.get(folder.id))}</option>`;
    })
  ].join("");

  document.getElementById("detail").innerHTML = `
    <form id="itemForm" class="detail-panel" data-item-id="${item?.id || ""}">
      <div class="split">
        <label>Location
          <select name="scope" ${isNew ? "" : "disabled"}>${scopeOptions}</select>
        </label>
        <label>Folder
          <select name="folderId" ${collectionId ? "disabled" : ""}>${folderOptions}</select>
        </label>
      </div>
      <label>Title <input name="title" value="${escapeHtml(payload.title)}" autocomplete="off" required /></label>
      <div class="split">
        <label>Username <input name="username" value="${escapeHtml(payload.username)}" autocomplete="off" /></label>
        <label>Website <input name="url" value="${escapeHtml(payload.url)}" autocomplete="off" /></label>
      </div>
      <label>Password
        <div class="row">
          <input id="passwordField" name="password" value="${escapeHtml(payload.password)}" autocomplete="off" />
          <button type="button" id="copyPasswordBtn">Copy</button>
        </div>
      </label>
      <section class="panel">
        <h3>Password generator</h3>
        <div class="generator-row">
          <label>Length <input id="generatorLength" type="number" min="12" max="80" value="24" /></label>
          <label><input id="generatorSymbols" type="checkbox" checked /> Symbols</label>
          <button type="button" id="generatePasswordBtn">Generate</button>
        </div>
      </section>
      <label>Notes <textarea name="notes">${escapeHtml(payload.notes)}</textarea></label>
      <div class="actions">
        <button class="primary" type="submit">${isNew ? "Create item" : "Save changes"}</button>
        ${isNew ? "" : '<button class="danger" type="button" id="deleteItemBtn">Delete</button>'}
      </div>
    </form>
  `;
}

function renderCollectionDetail(collectionId) {
  const collection = findCollection(collectionId);
  if (!collection) {
    document.getElementById("detail").innerHTML = '<div class="empty">Shared vault not found.</div>';
    return;
  }
  const canAdmin = ["owner", "admin"].includes(collection.role);
  const rows = collection.members
    .map(
      (member) => `
        <tr>
          <td>${escapeHtml(member.email)}</td>
          <td>${escapeHtml(member.displayName)}</td>
          <td>${escapeHtml(member.role)}</td>
          <td>
            ${
              canAdmin && member.userId !== state.user.id
                ? `<button class="small danger" type="button" data-remove-member="${member.userId}" data-collection-id="${collection.id}">Remove</button>`
                : ""
            }
          </td>
        </tr>`
    )
    .join("");
  document.getElementById("detail").innerHTML = `
    <section class="detail-panel">
      <div class="panel">
        <h2>${escapeHtml(state.decryptedCollections.get(collection.id))}</h2>
        <p class="muted">Your role: ${escapeHtml(collection.role)}</p>
      </div>
      <div class="panel">
        <h3>Members</h3>
        <table class="table">
          <thead><tr><th>Email</th><th>Name</th><th>Role</th><th></th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      ${
        canAdmin
          ? `
        <form id="collectionMemberForm" class="panel form-grid" data-collection-id="${collection.id}">
          <h3>Add or update member</h3>
          <label>Email <input name="email" type="email" required /></label>
          <label>Role
            <select name="role">
              <option value="member">Member</option>
              <option value="read_only">Read only</option>
              <option value="admin">Admin</option>
            </select>
          </label>
          <button class="primary" type="submit">Share vault</button>
        </form>`
          : ""
      }
    </section>
  `;
}

function renderSecurityPanel() {
  const enabled = state.user.totpEnabled;
  const pending = state.pendingTotp;
  document.getElementById("detail").innerHTML = `
    <section class="detail-panel">
      <div class="panel">
        <h2>Security</h2>
        <p class="muted">Two-factor authentication status: ${enabled ? "enabled" : "disabled"}</p>
      </div>
      ${
        enabled
          ? `
        <form id="totpDisableForm" class="panel form-grid">
          <h3>Disable TOTP</h3>
          <label>TOTP code <input name="code" inputmode="numeric" required /></label>
          <button class="danger" type="submit">Disable</button>
        </form>`
          : `
        <div class="panel form-grid">
          <h3>Enable TOTP</h3>
          <button type="button" class="primary" id="totpSetupBtn">Start setup</button>
        </div>`
      }
      ${
        pending
          ? `
        <form id="totpConfirmForm" class="panel form-grid">
          <h3>Confirm authenticator</h3>
          <label>Secret <input readonly value="${escapeHtml(pending.secret)}" /></label>
          <label>Provisioning URI <textarea readonly>${escapeHtml(pending.provisioningUri)}</textarea></label>
          <label>Current code <input name="code" inputmode="numeric" required /></label>
          <button class="primary" type="submit">Enable TOTP</button>
        </form>`
          : ""
      }
    </section>
  `;
}

async function renderAdminPanel() {
  document.getElementById("detail").innerHTML = '<div class="empty">Loading admin panel...</div>';
  const [stats, users, settings, audit, backups] = await Promise.all([
    api("/api/admin/stats"),
    api("/api/admin/users"),
    api("/api/admin/settings"),
    api("/api/admin/audit"),
    api("/api/admin/backups")
  ]);
  const userRows = users.users
    .map(
      (user) => `
        <tr>
          <td>${escapeHtml(user.email)}</td>
          <td>${user.isAdmin ? "yes" : "no"}</td>
          <td>${user.isDisabled ? "disabled" : "active"}</td>
          <td>${user.totpEnabled ? "yes" : "no"}</td>
          <td>
            <button class="small" type="button" data-admin-toggle="admin" data-user-id="${user.id}" data-value="${!user.isAdmin}">${user.isAdmin ? "Revoke admin" : "Grant admin"}</button>
            <button class="small danger" type="button" data-admin-toggle="disabled" data-user-id="${user.id}" data-value="${!user.isDisabled}">${user.isDisabled ? "Enable" : "Disable"}</button>
          </td>
        </tr>`
    )
    .join("");
  const auditRows = audit.events
    .slice(0, 20)
    .map(
      (event) => `
        <tr>
          <td>${escapeHtml(event.createdAt)}</td>
          <td>${escapeHtml(event.email || "")}</td>
          <td>${escapeHtml(event.action)}</td>
          <td>${escapeHtml(event.ip || "")}</td>
        </tr>`
    )
    .join("");
  const backupRows = backups.backups
    .map(
      (backup) => `
        <tr>
          <td>${escapeHtml(backup.name)}</td>
          <td>${Math.round(backup.size / 1024)} KB</td>
        </tr>`
    )
    .join("");

  document.getElementById("detail").innerHTML = `
    <section class="detail-panel">
      <div class="panel">
        <h2>Admin</h2>
        <div class="split">
          <div>Users: <strong>${stats.stats.users}</strong></div>
          <div>Items: <strong>${stats.stats.items}</strong></div>
          <div>Shared vaults: <strong>${stats.stats.collections}</strong></div>
          <div>Folders: <strong>${stats.stats.folders}</strong></div>
        </div>
      </div>
      <form id="adminSettingsForm" class="panel form-grid">
        <h3>Settings</h3>
        <label><input type="checkbox" name="registrationEnabled" ${settings.settings.registrationEnabled ? "checked" : ""} /> Registration enabled</label>
        <button class="primary" type="submit">Save settings</button>
      </form>
      <div class="panel">
        <h3>Backups</h3>
        <button class="primary" type="button" id="adminBackupBtn">Create verified backup</button>
        <table class="table">
          <thead><tr><th>Name</th><th>Size</th></tr></thead>
          <tbody>${backupRows || '<tr><td colspan="2">No backups</td></tr>'}</tbody>
        </table>
      </div>
      <div class="panel">
        <h3>Users</h3>
        <table class="table">
          <thead><tr><th>Email</th><th>Admin</th><th>Status</th><th>TOTP</th><th></th></tr></thead>
          <tbody>${userRows}</tbody>
        </table>
      </div>
      <div class="panel">
        <h3>Audit</h3>
        <table class="table">
          <thead><tr><th>Time</th><th>User</th><th>Action</th><th>IP</th></tr></thead>
          <tbody>${auditRows}</tbody>
        </table>
      </div>
    </section>
  `;
}

async function handleClick(event) {
  const target = event.target.closest("button");
  if (!target) return;

  if (target.dataset.authTab) {
    renderAuth(target.dataset.authTab);
    return;
  }
  if (target.id === "logoutBtn") {
    await api("/api/auth/logout", { method: "POST" }).catch(() => ({}));
    location.reload();
    return;
  }
  if (target.id === "lockBtn") {
    state.encKey = null;
    state.privateKey = null;
    renderUnlock(state.user);
    return;
  }
  if (target.dataset.filter) {
    state.filter = target.dataset.filter;
    state.selectedItemId = null;
    renderSidebar();
    renderList();
    renderDetailDefault();
    return;
  }
  if (target.id === "addItemBtn") {
    state.selectedItemId = null;
    renderItemDetail(null);
    return;
  }
  if (target.id === "addFolderBtn" || target.id === "addFolderBtnSide") {
    await createFolder();
    return;
  }
  if (target.id === "addCollectionBtn" || target.id === "addCollectionBtnSide") {
    await createCollection();
    return;
  }
  if (target.classList.contains("item-row")) {
    const item = state.decryptedItems.find((row) => row.id === Number(target.dataset.itemId));
    state.selectedItemId = item.id;
    renderList();
    renderItemDetail(item);
    return;
  }
  if (target.id === "generatePasswordBtn") {
    document.getElementById("passwordField").value = generatePassword();
    return;
  }
  if (target.id === "copyPasswordBtn") {
    await navigator.clipboard.writeText(document.getElementById("passwordField").value || "");
    showToast("Password copied");
    return;
  }
  if (target.id === "deleteItemBtn") {
    await deleteSelectedItem();
    return;
  }
  if (target.id === "securityBtn") {
    state.selectedItemId = null;
    state.pendingTotp = null;
    renderSecurityPanel();
    return;
  }
  if (target.id === "totpSetupBtn") {
    state.pendingTotp = await api("/api/me/totp/setup", { method: "POST" });
    renderSecurityPanel();
    return;
  }
  if (target.id === "adminBtn") {
    state.selectedItemId = null;
    await renderAdminPanel();
    return;
  }
  if (target.id === "adminBackupBtn") {
    target.disabled = true;
    await api("/api/admin/backups", { method: "POST" });
    showToast("Backup created and verified");
    await renderAdminPanel();
    return;
  }
  if (target.dataset.adminToggle) {
    await patchAdminUser(target);
    return;
  }
  if (target.dataset.removeMember) {
    await api(`/api/collections/${target.dataset.collectionId}/members/${target.dataset.removeMember}`, {
      method: "DELETE"
    });
    showToast("Member removed");
    await reloadVault();
    state.filter = `collection:${target.dataset.collectionId}`;
    renderCollectionDetail(Number(target.dataset.collectionId));
  }
}

async function handleSubmit(event) {
  event.preventDefault();
  const form = event.target;
  try {
    if (form.id === "loginForm") await submitLogin(form);
    if (form.id === "registerForm") await submitRegister(form);
    if (form.id === "unlockForm") await submitUnlock(form);
    if (form.id === "itemForm") await submitItem(form);
    if (form.id === "collectionMemberForm") await submitCollectionMember(form);
    if (form.id === "totpConfirmForm") await submitTotpConfirm(form);
    if (form.id === "totpDisableForm") await submitTotpDisable(form);
    if (form.id === "adminSettingsForm") await submitAdminSettings(form);
  } catch (error) {
    const errorNode = document.getElementById("authError");
    if (errorNode) errorNode.textContent = error.message;
    showToast(error.message);
  }
}

function handleInput(event) {
  if (event.target.id === "searchInput") {
    state.search = event.target.value;
    renderList();
  }
  if (event.target.name === "scope") {
    const folder = document.querySelector("select[name='folderId']");
    if (folder) folder.disabled = event.target.value !== "personal";
  }
}

async function submitLogin(form) {
  const email = form.email.value.trim().toLowerCase();
  const password = form.password.value;
  const prelogin = await api(`/api/auth/prelogin?email=${encodeURIComponent(email)}`);
  if (!prelogin.exists) throw new Error("Account not found");
  const derived = await deriveKeys(password, prelogin.kdfSalt, prelogin.kdfIterations);
  const body = { email, authHash: derived.authHash };
  if (form.totp.value) body.totpCode = form.totp.value;
  const result = await api("/api/auth/login", { method: "POST", body });
  if (result.requiresTotp) {
    document.getElementById("loginTotpLabel").classList.remove("hidden");
    form.totp.focus();
    throw new Error("Enter your authenticator code");
  }
  await completeUnlock(result.user, derived.encKey);
}

async function submitRegister(form) {
  if (!state.config.registrationEnabled) throw new Error("Registration is disabled");
  if (form.password.value !== form.confirmPassword.value) throw new Error("Passwords do not match");
  if (form.password.value.length < 12) throw new Error("Use at least 12 characters");
  const salt = bytesToB64(randomBytes(16));
  const derived = await deriveKeys(form.password.value, salt, state.config.kdfIterations);
  const pair = await generateKeyPair();
  const publicKey = bytesToB64(new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey)));
  const privateBytes = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  const encryptedPrivateKey = await encryptBytes(derived.encKey, privateBytes);
  await api("/api/auth/register", {
    method: "POST",
    body: {
      email: form.email.value.trim().toLowerCase(),
      displayName: form.displayName.value.trim(),
      authHash: derived.authHash,
      kdfSalt: salt,
      kdfIterations: state.config.kdfIterations,
      publicKey,
      encryptedPrivateKey
    }
  });
  const loginResult = await api("/api/auth/login", {
    method: "POST",
    body: { email: form.email.value.trim().toLowerCase(), authHash: derived.authHash }
  });
  await completeUnlock(loginResult.user, derived.encKey);
}

async function submitUnlock(form) {
  const derived = await deriveKeys(form.password.value, state.user.kdfSalt, state.user.kdfIterations);
  await completeUnlock(state.user, derived.encKey);
}

async function submitItem(form) {
  const itemId = form.dataset.itemId ? Number(form.dataset.itemId) : null;
  const currentItem = itemId ? state.decryptedItems.find((item) => item.id === itemId) : null;
  const scope = currentItem?.collectionId
    ? `collection:${currentItem.collectionId}`
    : currentItem
      ? "personal"
      : form.scope.value;
  const collectionId = scope.startsWith("collection:") ? Number(scope.split(":")[1]) : null;
  const folderId = collectionId ? null : form.folderId.value ? Number(form.folderId.value) : null;
  const key = collectionId ? await unwrapCollectionKey(findCollection(collectionId)) : state.encKey;
  const encryptedPayload = await encryptJson(key, {
    title: form.title.value.trim() || "Untitled",
    username: form.username.value,
    password: form.password.value,
    url: form.url.value,
    notes: form.notes.value,
    updatedAt: new Date().toISOString()
  });
  const result = await api(itemId ? `/api/items/${itemId}` : "/api/items", {
    method: itemId ? "PATCH" : "POST",
    body: { folderId, collectionId, encryptedPayload }
  });
  state.selectedItemId = itemId || result.id;
  await reloadVault();
  const selected = state.decryptedItems.find((item) => item.id === state.selectedItemId);
  if (selected) renderItemDetail(selected);
  showToast("Item saved");
}

async function submitCollectionMember(form) {
  const collectionId = Number(form.dataset.collectionId);
  const collection = findCollection(collectionId);
  const lookup = await api(`/api/users/lookup?email=${encodeURIComponent(form.email.value.trim())}`);
  const key = await unwrapCollectionKey(collection);
  const encryptedCollectionKey = await wrapCollectionKey(key, lookup.user.publicKey);
  await api(`/api/collections/${collectionId}/members`, {
    method: "POST",
    body: {
      email: lookup.user.email,
      role: form.role.value,
      encryptedCollectionKey
    }
  });
  showToast("Shared vault updated");
  await reloadVault();
  state.filter = `collection:${collectionId}`;
  renderCollectionDetail(collectionId);
}

async function submitTotpConfirm(form) {
  await api("/api/me/totp/confirm", { method: "POST", body: { code: form.code.value } });
  const me = await api("/api/me");
  state.user = me.user;
  state.pendingTotp = null;
  renderSecurityPanel();
  showToast("TOTP enabled");
}

async function submitTotpDisable(form) {
  await api("/api/me/totp/disable", { method: "POST", body: { code: form.code.value } });
  const me = await api("/api/me");
  state.user = me.user;
  renderSecurityPanel();
  showToast("TOTP disabled");
}

async function submitAdminSettings(form) {
  await api("/api/admin/settings", {
    method: "PUT",
    body: { registrationEnabled: form.registrationEnabled.checked }
  });
  showToast("Settings saved");
  await renderAdminPanel();
}

async function patchAdminUser(button) {
  const body =
    button.dataset.adminToggle === "admin"
      ? { isAdmin: button.dataset.value === "true" }
      : { isDisabled: button.dataset.value === "true" };
  await api(`/api/admin/users/${button.dataset.userId}`, { method: "PATCH", body });
  showToast("User updated");
  await renderAdminPanel();
}

async function createFolder() {
  const name = prompt("Folder name");
  if (!name) return;
  const encryptedName = await encryptJson(state.encKey, { name });
  await api("/api/folders", { method: "POST", body: { encryptedName } });
  await reloadVault();
  showToast("Folder created");
}

async function createCollection() {
  const name = prompt("Shared vault name");
  if (!name) return;
  const collectionKey = await crypto.subtle.generateKey("AES-GCM", true, ["encrypt", "decrypt"]);
  const encryptedName = await encryptJson(collectionKey, { name });
  const encryptedCollectionKey = await wrapCollectionKey(collectionKey, state.user.publicKey);
  const result = await api("/api/collections", {
    method: "POST",
    body: { encryptedName, encryptedCollectionKey }
  });
  state.filter = `collection:${result.id}`;
  await reloadVault();
  renderCollectionDetail(result.id);
  showToast("Shared vault created");
}

async function deleteSelectedItem() {
  if (!state.selectedItemId) return;
  if (!confirm("Delete this item?")) return;
  await api(`/api/items/${state.selectedItemId}`, { method: "DELETE" });
  state.selectedItemId = null;
  await reloadVault();
  showToast("Item deleted");
}

function generatePassword() {
  const length = Math.min(80, Math.max(12, Number(document.getElementById("generatorLength").value) || 24));
  const includeSymbols = document.getElementById("generatorSymbols").checked;
  const groups = [
    "ABCDEFGHJKLMNPQRSTUVWXYZ",
    "abcdefghijkmnopqrstuvwxyz",
    "23456789"
  ];
  if (includeSymbols) groups.push("!@#$%^&*()-_=+[]{};:,.?");
  const all = groups.join("");
  const chars = groups.map((group) => group[randomInt(group.length)]);
  while (chars.length < length) chars.push(all[randomInt(all.length)]);
  for (let i = chars.length - 1; i > 0; i -= 1) {
    const j = randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join("");
}

function randomInt(max) {
  const limit = Math.floor(256 / max) * max;
  const byte = new Uint8Array(1);
  do {
    crypto.getRandomValues(byte);
  } while (byte[0] >= limit);
  return byte[0] % max;
}

init().catch((error) => {
  app.innerHTML = `<main class="auth-shell"><section class="auth-panel"><h1 class="brand">Startup failed</h1><p class="error">${escapeHtml(error.message)}</p></section></main>`;
});
