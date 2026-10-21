"use strict";

const state = {
  token: null,
  user: null,
  permissions: [],
  roles: [],
  permissionCatalog: [],
  documents: [],
  requests: [],
  liveTimer: null,
  permissionUserId: null,
};

const $ = (selector) => document.querySelector(selector);
const notice = $("#notice");

function showNotice(message, isError = false) {
  notice.textContent = message;
  notice.classList.toggle("error", isError);
  notice.classList.remove("hidden");
  window.clearTimeout(showNotice.timeout);
  showNotice.timeout = window.setTimeout(() => notice.classList.add("hidden"), 6500);
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (state.token) headers.set("Authorization", `Bearer ${state.token}`);
  if (options.body && !(options.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const response = await fetch(path, { ...options, headers });
  if (!response.ok) {
    let message = `Request failed (${response.status}).`;
    try {
      const body = await response.json();
      if (body.error) message = body.error;
    } catch {
      // Keep the HTTP status message when the response is not JSON.
    }
    if (response.status === 401 && state.token) {
      clearSession();
      showNotice("Your session expired or was revoked. Please sign in again.", true);
    }
    throw new Error(message);
  }
  return response;
}

async function apiJson(path, method, payload) {
  const response = await api(path, {
    method,
    body: JSON.stringify(payload),
  });
  return response.json();
}

function clearSession() {
  window.clearInterval(state.liveTimer);
  state.liveTimer = null;
  state.token = null;
  state.user = null;
  state.permissions = [];
  state.roles = [];
  state.documents = [];
  state.requests = [];
  $("#auth-panel").classList.remove("hidden");
  $("#app-panel").classList.add("hidden");
  $("#logout-button").classList.add("hidden");
  document.body.classList.remove("dashboard-mode");
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function setAuthMode(mode) {
  $("#auth-form").dataset.mode = mode;
  $("#auth-submit").textContent = {
    login: "Sign in",
    register: "Create account",
    bootstrap: "Set up first admin",
  }[mode];
  $("#bootstrap-help").classList.toggle("hidden", mode !== "bootstrap");
  $("#auth-password").autocomplete = mode === "login" ? "current-password" : "new-password";
  document.querySelectorAll("[data-auth-tab]").forEach((tab) => {
    const active = tab.dataset.authTab === mode;
    tab.classList.toggle("active", active);
    tab.setAttribute("aria-selected", String(active));
  });
}

async function login(email, password) {
  const result = await apiJson("/api/auth/login", "POST", { email, password });
  state.token = result.access_token;
  await loadDashboard(result.user);
  showNotice(`Signed in as ${result.user.email}.`);
}

function renderPermissions() {
  const list = $("#permission-list");
  list.replaceChildren();
  if (!state.permissions.length) {
    list.append(element("span", "empty-state", "No permissions assigned."));
    return;
  }
  state.permissions.forEach((permission) => {
    list.append(element("span", "permission-tag", permission));
  });
}

function fillRoleSelect(select, roles) {
  const selectedValue = select.value;
  select.replaceChildren();
  const placeholder = element("option", "", "Select a role");
  placeholder.value = "";
  placeholder.disabled = true;
  select.append(placeholder);
  roles.forEach((role) => {
    const option = element("option", "", `${role.name} (ID ${role.id})`);
    option.value = String(role.id);
    select.append(option);
  });
  select.value = roles.some((role) => String(role.id) === selectedValue) ? selectedValue : "";
}

function renderPermissionPicker(selector = "#permission-picker") {
  const picker = $(selector);
  picker.replaceChildren();
  state.permissionCatalog.forEach((permission) => {
    const label = element("label", "check-option");
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.value = permission.name;
    const description = element("span", "", `${permission.name} — ${permission.description}`);
    label.append(checkbox, description);
    picker.append(label);
  });
}

function selectedPermissions(selector) {
  return Array.from($(selector).querySelectorAll("input:checked"))
    .map((checkbox) => checkbox.value);
}

function setPermissionChoices(selector, checked) {
  $(selector).querySelectorAll("input[type=checkbox]").forEach((checkbox) => {
    checkbox.checked = checked;
  });
}

async function loadAdminTools() {
  const [rolesResult, permissionsResult] = await Promise.all([
    api("/api/admin/roles").then((response) => response.json()),
    api("/api/admin/permissions").then((response) => response.json()),
  ]);
  state.roles = rolesResult.roles;
  state.permissionCatalog = permissionsResult.permissions;
  renderPermissionPicker();
  renderPermissionPicker("#new-user-permission-picker");
  renderPermissionPicker("#edit-user-permission-picker");
  fillRoleSelect($("#new-user-role"), state.roles);
  fillRoleSelect($("#assign-user-role"), state.roles);
}

async function loadDocuments() {
  const container = $("#document-list");
  if (!state.permissions.includes("documents.list")) {
    state.documents = [];
    $("#document-count").textContent = "—";
    container.replaceChildren();
    container.append(element("p", "empty-state", "Your role does not allow listing documents."));
    return;
  }
  const result = await api("/api/documents").then((response) => response.json());
  state.documents = result.documents;
  $("#document-count").textContent = String(state.documents.length);
  renderDocuments();
}

function renderDocuments() {
  const container = $("#document-list");
  const query = $("#document-search").value.trim().toLocaleLowerCase();
  const documents = state.documents.filter((document) =>
    document.filename.toLocaleLowerCase().includes(query),
  );
  container.replaceChildren();
  if (!documents.length) {
    const message = state.documents.length
      ? "No files match your search."
      : "No documents yet. Upload a file to get started.";
    container.append(element("p", "empty-state", message));
    return;
  }
  const table = element("div", "document-table");
  const header = element("div", "document-table-header");
  ["Name", "Owner", "Added", ""].forEach((heading) => {
    header.append(element("span", "", heading));
  });
  table.append(header);
  documents.forEach((document) => {
    const row = element("article", "document-row");
    const extension = document.filename.includes(".")
      ? document.filename.split(".").pop().slice(0, 4).toUpperCase()
      : "FILE";
    const icon = element("span", `file-icon file-${extension.toLowerCase()}`, extension.slice(0, 3));
    icon.setAttribute("aria-hidden", "true");
    const info = element("div", "document-info");
    info.append(
      element("strong", "", document.filename),
      element("span", "", `ID ${document.id.slice(0, 8)}`),
    );
    const owner = element("span", "document-owner", Number(document.owner_id) === Number(state.user.id) ? "You" : `User #${document.owner_id}`);
    const date = element("span", "document-date", new Date(document.created_at).toLocaleDateString());
    const actions = element("div", "row-actions");
    if (state.permissions.includes("documents.download")) {
      const download = element("button", "small-button", "Download");
      download.type = "button";
      download.addEventListener("click", () => downloadDocument(document.id, document.filename));
      actions.append(download);
    }
    row.append(icon, info, owner, date, actions);
    table.append(row);
  });
  container.append(table);
}

async function downloadDocument(documentId, filename) {
  try {
    const response = await api(`/api/documents/${encodeURIComponent(documentId)}/download`);
    const blob = await response.blob();
    const objectUrl = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = objectUrl;
    link.download = filename;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(objectUrl);
  } catch (error) {
    showNotice(error.message, true);
  }
}

async function loadAccessRequests() {
  const result = await api("/api/access-requests").then((response) => response.json());
  state.requests = result.access_requests;
  $("#request-count").textContent = String(state.requests.length);
  const container = $("#request-list");
  container.replaceChildren();
  if (!state.requests.length) {
    container.append(element("p", "empty-state", "No access requests to show."));
    return;
  }
  state.requests.forEach((request) => {
    const row = element("article", "request-row");
    const info = element("div", "request-info");
    info.append(
      element("strong", "", `${request.filename} · ${request.status}`),
      element("span", "", `${request.requester_email} · ${request.reason}`),
    );
    row.append(info);
    if (request.status === "pending" &&
        state.permissions.includes("access_requests.review") &&
        request.requester_id !== state.user.id) {
      ["approve", "reject"].forEach((decision) => {
        const button = element("button", `small-button${decision === "reject" ? " danger" : ""}`, decision);
        button.type = "button";
        button.addEventListener("click", () => reviewRequest(request.id, decision));
        row.append(button);
      });
    } else {
      row.append(element("span", `state-pill state-${request.status}`, request.status));
    }
    container.append(row);
  });
}

async function loadAuditLog() {
  const result = await api("/api/admin/audit-log").then((response) => response.json());
  const container = $("#audit-list");
  container.replaceChildren();
  if (!result.events.length) {
    container.append(element("p", "empty-state", "No audit events yet."));
    return;
  }
  result.events.forEach((event) => {
    const row = element("article", "request-row");
    const info = element("div", "request-info");
    info.append(
      element("strong", "", event.action.replaceAll(".", " ")),
      element("span", "", `${event.resource_type} ${event.resource_id || ""} · ${new Date(event.created_at).toLocaleString()}`),
    );
    row.append(info);
    container.append(row);
  });
}

async function reviewRequest(requestId, decision) {
  try {
    await apiJson(`/api/access-requests/${encodeURIComponent(requestId)}/${decision}`, "POST", {});
    await loadAccessRequests();
    showNotice(`Access request ${decision === "approve" ? "approved" : "rejected"}.`);
  } catch (error) {
    showNotice(error.message, true);
  }
}

async function loadDashboard(currentUser = null) {
  const user = currentUser || await api("/api/auth/me").then((response) => response.json()).then((result) => result.user);
  state.user = user;
  state.permissions = user.permissions || [];
  $("#auth-panel").classList.add("hidden");
  $("#app-panel").classList.remove("hidden");
  $("#logout-button").classList.remove("hidden");
  document.body.classList.add("dashboard-mode");
  $("#profile-email").textContent = user.email;
  $("#profile-role").textContent = user.role;
  $("#profile-avatar").textContent = (user.email[0] || "U").toUpperCase();
  $("#dashboard-greeting").textContent = `Good ${new Date().getHours() < 12 ? "morning" : new Date().getHours() < 18 ? "afternoon" : "evening"}`;
  $("#role-stat").textContent = user.role.replaceAll("_", " ");
  $("#permission-count").textContent = String(state.permissions.length);
  renderPermissions();
  const canManageRoles = state.permissions.includes("roles.manage");
  const canReadAudit = state.permissions.includes("audit.read");
  $("#admin-panel").classList.toggle("hidden", !canManageRoles);
  $("#admin-nav").classList.toggle("hidden", !canManageRoles);
  const canListRequests = state.permissions.includes("access_requests.list");
  const canCreateRequests = state.permissions.includes("access_requests.create");
  const canListDocuments = state.permissions.includes("documents.list");
  $("#requests-panel").classList.toggle("hidden", !canListRequests && !canCreateRequests);
  $("#requests-refresh").classList.toggle("hidden", !canListRequests);
  if (!canListRequests) $("#request-count").textContent = "—";
  $("#audit-section").classList.toggle("hidden", !state.permissions.includes("audit.read"));
  $("#audit-nav").classList.toggle("hidden", !canReadAudit);
  $("#requests-nav").classList.toggle("hidden", !canListRequests && !canCreateRequests);
  $("#access-request-form").classList.toggle("hidden", !canCreateRequests);
  $("#upload-form").classList.toggle("hidden", !state.permissions.includes("documents.upload"));
  $(".search-box").classList.toggle("hidden", !canListDocuments);

  const jobs = [loadDocuments()];
  if (state.permissions.includes("roles.manage")) jobs.push(loadAdminTools());
  if (canListRequests) jobs.push(loadAccessRequests());
  const results = await Promise.allSettled(jobs);
  const failed = results.find((item) => item.status === "rejected");
  if (failed) showNotice(failed.reason.message, true);
  window.clearInterval(state.liveTimer);
  state.liveTimer = window.setInterval(() => {
    refreshLiveData().catch((error) => {
      $("#sync-label").textContent = state.token ? "Sync issue" : "Sign in required";
      if (state.token) showNotice(error.message, true);
    });
  }, 15000);
  $("#sync-label").textContent = "Synced just now";
}

async function refreshLiveData() {
  if (!state.token || document.visibilityState !== "visible") return;
  if (state.permissions.includes("auth.profile")) {
    const current = await api("/api/auth/me").then((response) => response.json());
    const latestPermissions = current.user.permissions || [];
    const permissionsChanged =
      current.user.role !== state.user.role ||
      latestPermissions.join("\0") !== state.permissions.join("\0");
    if (permissionsChanged) {
      await loadDashboard();
      return;
    }
  }
  const jobs = [loadDocuments()];
  if (state.permissions.includes("access_requests.list")) jobs.push(loadAccessRequests());
  const results = await Promise.allSettled(jobs);
  const failed = results.find((item) => item.status === "rejected");
  if (failed) {
    $("#sync-label").textContent = "Sync issue";
    showNotice(failed.reason.message, true);
    return;
  }
  $("#sync-label").textContent = `Synced ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
}

document.querySelectorAll("[data-auth-tab]").forEach((tab) => {
  tab.addEventListener("click", () => setAuthMode(tab.dataset.authTab));
});

$("#auth-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const mode = form.dataset.mode;
  const email = $("#auth-email").value.trim();
  const password = $("#auth-password").value;
  const button = $("#auth-submit");
  button.disabled = true;
  try {
    if (mode === "bootstrap") {
      const result = await apiJson("/api/auth/bootstrap-admin", "POST", { email, password });
      $("#auth-password").value = "";
      setAuthMode("login");
      $("#auth-email").value = result.user.email;
      showNotice("First admin created. Sign in with those credentials.");
    } else if (mode === "register") {
      const result = await apiJson("/api/auth/register", "POST", { email, password });
      $("#auth-password").value = "";
      setAuthMode("login");
      $("#auth-email").value = result.user.email;
      showNotice("Account created. Sign in to continue.");
    } else {
      await login(email, password);
    }
  } catch (error) {
    if (mode === "bootstrap" && error.message === "Administrator setup has already been completed.") {
      setAuthMode("register");
      showNotice("Administrator setup is complete. Select Create account to register a regular account.");
    } else {
      showNotice(error.message, true);
    }
  } finally {
    button.disabled = false;
  }
});

$("#role-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const permissions = selectedPermissions("#permission-picker");
  try {
    const created = await apiJson("/api/admin/roles", "POST", {
      name: form.get("name"),
      description: form.get("description"),
    });
    if (permissions.length) {
      await apiJson(`/api/admin/roles/${created.role.id}/permissions`, "PUT", { permissions });
    }
    event.currentTarget.reset();
    await loadAdminTools();
    $("#new-user-role").value = String(created.role.id);
    showNotice(`Role "${created.role.name}" created with ${permissions.length} permission(s).`);
  } catch (error) {
    showNotice(error.message, true);
  }
});

$("#custom-user-permissions").addEventListener("change", (event) => {
  $("#new-user-permissions-fieldset").classList.toggle("hidden", !event.currentTarget.checked);
});

$("#inherit-role-permissions").addEventListener("change", (event) => {
  $("#edit-user-permissions-fieldset").classList.toggle("hidden", event.currentTarget.checked);
});

$("#user-permissions-form [name='user_id']").addEventListener("input", () => {
  state.permissionUserId = null;
  $("#save-user-permissions").disabled = true;
  $("#permission-user-summary").textContent = "Load this user before changing permissions.";
});

$("#load-user-permissions").addEventListener("click", async () => {
  const userId = Number($("#user-permissions-form [name='user_id']").value);
  if (!userId) return;
  try {
    const result = await api(`/api/admin/users/${userId}`).then((response) => response.json());
    const user = result.user;
    state.permissionUserId = user.id;
    $("#inherit-role-permissions").checked = user.inherits_role;
    $("#edit-user-permissions-fieldset").classList.toggle("hidden", user.inherits_role);
    const permissions = new Set(user.permissions);
    $("#edit-user-permission-picker").querySelectorAll("input[type=checkbox]").forEach((checkbox) => {
      checkbox.checked = permissions.has(checkbox.value);
    });
    $("#permission-user-summary").textContent = `${user.email} · ${user.role} · ${user.permissions.length} effective permissions${user.inherits_role ? " (from role)" : " (individual override)"}`;
    $("#save-user-permissions").disabled = false;
  } catch (error) {
    state.permissionUserId = null;
    $("#save-user-permissions").disabled = true;
    showNotice(error.message, true);
  }
});

[["#new-user-select-all", "#new-user-permission-picker", true],
  ["#new-user-clear", "#new-user-permission-picker", false],
  ["#edit-user-select-all", "#edit-user-permission-picker", true],
  ["#edit-user-clear", "#edit-user-permission-picker", false]].forEach(([buttonSelector, pickerSelector, checked]) => {
  $(buttonSelector).addEventListener("click", () => setPermissionChoices(pickerSelector, checked));
});

$("#user-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const roleId = Number(form.get("role_id"));
  const customPermissions = $("#custom-user-permissions").checked;
  const payload = {
    email: form.get("email"),
    password: form.get("password"),
    role_id: roleId,
  };
  if (customPermissions) payload.permissions = selectedPermissions("#new-user-permission-picker");
  try {
    const result = await apiJson("/api/admin/users", "POST", payload);
    event.currentTarget.reset();
    $("#new-user-permissions-fieldset").classList.add("hidden");
    showNotice(`Created ${result.user.email} (ID ${result.user.id}) with ${result.user.permissions.length} permission(s).`);
  } catch (error) {
    showNotice(error.message, true);
  }
});

$("#user-permissions-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const userId = Number(form.get("user_id"));
  if (state.permissionUserId !== userId) {
    showNotice("Load the user before saving permissions.", true);
    return;
  }
  const inheritRole = $("#inherit-role-permissions").checked;
  const payload = inheritRole
    ? { inherit_role: true }
    : { permissions: selectedPermissions("#edit-user-permission-picker") };
  try {
    const result = await apiJson(`/api/admin/users/${userId}/permissions`, "PUT", payload);
    state.permissionUserId = result.user.id;
    $("#inherit-role-permissions").checked = result.user.inherits_role;
    $("#edit-user-permissions-fieldset").classList.toggle("hidden", result.user.inherits_role);
    const permissions = new Set(result.user.permissions);
    $("#edit-user-permission-picker").querySelectorAll("input[type=checkbox]").forEach((checkbox) => {
      checkbox.checked = permissions.has(checkbox.value);
    });
    $("#permission-user-summary").textContent = `${result.user.email} · ${result.user.role} · ${result.user.permissions.length} effective permissions${result.user.inherits_role ? " (from role)" : " (individual override)"}`;
    showNotice(`Updated ${result.user.email}: ${result.user.permissions.length} effective permission(s).`);
  } catch (error) {
    showNotice(error.message, true);
  }
});

$("#assign-role-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  try {
    const result = await apiJson(
      `/api/admin/users/${Number(form.get("user_id"))}/role`,
      "POST",
      { role_id: Number(form.get("role_id")) },
    );
    showNotice(`Updated ${result.user.email} to role "${result.user.role}".`);
  } catch (error) {
    showNotice(error.message, true);
  }
});

$("#upload-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const file = $("#upload-file").files[0];
  if (!file) return;
  if (file.size > 16 * 1024 * 1024) {
    showNotice("File exceeds the 16 MiB upload limit.", true);
    return;
  }
  const body = new FormData();
  body.append("file", file);
  try {
    const result = await api("/api/documents", { method: "POST", body }).then((response) => response.json());
    event.currentTarget.reset();
    await loadDocuments();
    showNotice(`Uploaded ${result.document.filename}.`);
  } catch (error) {
    showNotice(error.message, true);
  }
});

$("#access-request-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const documentId = String(form.get("document_id")).trim();
  try {
    await apiJson(`/api/documents/${encodeURIComponent(documentId)}/access-requests`, "POST", {
      reason: form.get("reason"),
    });
    event.currentTarget.reset();
    await loadAccessRequests();
    showNotice("Access request submitted for owner review.");
  } catch (error) {
    showNotice(error.message, true);
  }
});

$("#logout-button").addEventListener("click", async () => {
  if (!state.permissions.includes("auth.logout")) {
    clearSession();
    showNotice("Signed out on this device. This permission set cannot revoke the server token.");
    return;
  }
  try {
    await api("/api/auth/logout", { method: "POST" });
    clearSession();
    showNotice("You have been logged out.");
  } catch (error) {
    showNotice(error.message, true);
  }
});

$("#refresh-button").addEventListener("click", async () => {
  try {
    await loadDashboard(state.permissions.includes("auth.profile") ? null : state.user);
    showNotice("Workspace refreshed.");
  } catch (error) {
    showNotice(error.message, true);
  }
});

$("#requests-refresh").addEventListener("click", async () => {
  try {
    await loadAccessRequests();
  } catch (error) {
    showNotice(error.message, true);
  }
});

$("#document-search").addEventListener("input", renderDocuments);

document.querySelectorAll(".nav-link").forEach((link) => {
  link.addEventListener("click", () => {
    document.querySelectorAll(".nav-link").forEach((item) => item.classList.remove("active"));
    link.classList.add("active");
  });
});

$("#audit-refresh").addEventListener("click", async () => {
  try {
    await loadAuditLog();
  } catch (error) {
    showNotice(error.message, true);
  }
});

setAuthMode("login");
