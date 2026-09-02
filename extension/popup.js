/*
 * tvault popup.
 *
 * Talks to the local native host (com.tvault.host) with one-shot messages.
 * Chrome spawns a fresh host process per message, so the popup batches:
 * one `list` call for metadata, one `codes` call for every visible code,
 * and per-entry `credentials` only on an explicit click.
 *
 * Nothing is written to chrome.storage — no secret outlives this popup.
 * QR scanning screenshots the tab and hands the image to the native host,
 * so decoding happens locally and the seed never touches the browser until
 * it is already in the vault.
 */

const HOST = "com.tvault.host";

const el = (id) => document.getElementById(id);
const views = ["loading", "error", "locked", "list", "scan"];

let entries = [];
let codes = {};          // id -> { code, remaining, period, fetchedAt }
let currentDomain = "";
let tickTimer = null;

/* ---------- native messaging ---------- */

function send(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendNativeMessage(HOST, message, (response) => {
      const err = chrome.runtime.lastError;
      if (err) return reject(new Error(err.message));
      if (!response) return reject(new Error("empty response from native host"));
      resolve(response);
    });
  });
}

/* ---------- view switching ---------- */

function show(name) {
  for (const v of views) el(`view-${v}`).hidden = v !== name;
}

function showError(title, detail, hint) {
  el("error-title").textContent = title;
  el("error-detail").textContent = detail || "";
  el("error-hint").textContent = hint || "";
  el("error-hint").hidden = !hint;
  show("error");
}

let toastTimer = null;
function toast(text) {
  const node = el("toast");
  node.textContent = text;
  node.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { node.hidden = true; }, 1400);
}

/* ---------- startup ---------- */

async function activeTabDomain() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url) return "";
    const url = new URL(tab.url);
    if (!/^https?:$/.test(url.protocol)) return "";
    return url.hostname.replace(/^www\./, "");
  } catch {
    return "";
  }
}

async function start() {
  currentDomain = await activeTabDomain();
  el("site").textContent = currentDomain || "";

  let status;
  try {
    status = await send({ type: "status" });
  } catch (e) {
    showError(
      "Native host not reachable",
      "Chrome could not start the tvault helper.",
      `${e.message}\n\nFix: run\n  tvault install-chrome\nthen reload this extension.`
    );
    return;
  }

  if (!status.vault_exists) {
    showError("No vault yet", `Nothing at ${status.vault}`, "Create one:\n  tvault init");
    return;
  }
  if (!status.unlocked) return showLocked();
  await loadEntries();
}

function showLocked() {
  show("locked");
  el("lock").hidden = true;
  setTimeout(() => el("master").focus(), 30);
}

el("unlock-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = el("unlock-btn");
  const field = el("master");
  const errorNode = el("unlock-error");

  button.disabled = true;
  button.textContent = "Unlocking…";
  errorNode.hidden = true;

  try {
    const reply = await send({ type: "unlock", password: field.value });
    field.value = "";
    if (!reply.ok) {
      errorNode.textContent = reply.error || "Unlock failed";
      errorNode.hidden = false;
      return;
    }
    await loadEntries();
  } catch (e) {
    errorNode.textContent = e.message;
    errorNode.hidden = false;
  } finally {
    button.disabled = false;
    button.textContent = "Unlock";
  }
});

el("lock").addEventListener("click", async () => {
  await send({ type: "lock" }).catch(() => {});
  entries = [];
  codes = {};
  stopTicking();
  showLocked();
});

/* ---------- entry list ---------- */

async function loadEntries() {
  const reply = await send({ type: "list", domain: currentDomain });
  if (!reply.ok) {
    if (reply.locked) return showLocked();
    return showError("Could not read the vault", reply.error);
  }
  entries = reply.entries || [];
  el("lock").hidden = false;
  show("list");
  render();
  await refreshCodes();
  startTicking();
}

async function refreshCodes() {
  const ids = entries.filter((e) => e.has_totp).map((e) => e.id);
  if (!ids.length) return;
  try {
    const reply = await send({ type: "codes", ids });
    if (!reply.ok) return;
    const now = Date.now();
    for (const [id, value] of Object.entries(reply.codes)) {
      codes[id] = { ...value, fetchedAt: now };
    }
    paintCodes();
  } catch {
    /* leave the previous codes in place */
  }
}

function remainingFor(id) {
  const entry = codes[id];
  if (!entry || entry.error) return null;
  const elapsed = (Date.now() - entry.fetchedAt) / 1000;
  return entry.remaining - elapsed;
}

function startTicking() {
  stopTicking();
  tickTimer = setInterval(async () => {
    paintCodes();
    // Refresh as soon as any visible code has rolled over.
    const stale = Object.keys(codes).some((id) => {
      const left = remainingFor(id);
      return left !== null && left <= 0;
    });
    if (stale) await refreshCodes();
  }, 500);
}

function stopTicking() {
  if (tickTimer) clearInterval(tickTimer);
  tickTimer = null;
}

addEventListener("unload", stopTicking);

function paintCodes() {
  for (const entry of entries) {
    if (!entry.has_totp) continue;
    const codeNode = document.querySelector(`[data-code="${entry.id}"]`);
    const ring = document.querySelector(`[data-ring="${entry.id}"]`);
    if (!codeNode) continue;

    const record = codes[entry.id];
    if (!record) continue;
    if (record.error) {
      codeNode.textContent = "error";
      codeNode.title = record.error;
      continue;
    }

    const left = Math.max(0, remainingFor(entry.id));
    const period = record.period || 30;
    codeNode.textContent = groupCode(record.code);
    codeNode.classList.toggle("expiring", left <= 5);

    if (ring) {
      const head = ring.querySelector(".head");
      const circumference = 2 * Math.PI * 6;
      head.style.strokeDasharray = String(circumference);
      head.style.strokeDashoffset = String(circumference * (1 - left / period));
      ring.classList.toggle("expiring", left <= 5);
      ring.setAttribute("title", `${Math.ceil(left)}s left`);
    }
  }
}

function groupCode(code) {
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  return code;
}

function render() {
  const query = el("search").value.trim().toLowerCase();
  const visible = entries.filter((e) => {
    if (!query) return true;
    return [e.label, e.name, e.issuer, e.username, (e.urls || []).join(" ")]
      .join(" ")
      .toLowerCase()
      .includes(query);
  });

  const container = el("entries");
  container.textContent = "";
  el("empty").hidden = visible.length > 0;

  const matches = visible.filter((e) => e.matches_site);
  const others = visible.filter((e) => !e.matches_site);

  if (matches.length) {
    container.append(groupLabel(`For ${currentDomain}`));
    for (const entry of matches) container.append(renderEntry(entry, true));
  }
  if (others.length) {
    if (matches.length) container.append(groupLabel("All entries"));
    for (const entry of others) container.append(renderEntry(entry, false));
  }
  paintCodes();
}

function groupLabel(text) {
  const node = document.createElement("div");
  node.className = "group-label";
  node.textContent = text;
  return node;
}

function renderEntry(entry, isMatch) {
  const root = document.createElement("div");
  root.className = "entry" + (isMatch ? " match" : "");

  const top = document.createElement("div");
  top.className = "entry-top";

  const identity = document.createElement("div");
  identity.className = "entry-id";
  const name = document.createElement("div");
  name.className = "entry-name";
  name.textContent = entry.issuer || entry.name;
  identity.append(name);
  if (entry.username) {
    const user = document.createElement("div");
    user.className = "entry-user";
    user.textContent = entry.username;
    identity.append(user);
  }
  top.append(identity);

  if (entry.has_totp) {
    const code = document.createElement("button");
    code.className = "code";
    code.dataset.code = entry.id;
    code.textContent = "••• •••";
    code.title = "Copy code";
    code.addEventListener("click", () => copyCode(entry));
    top.append(code, ring(entry.id));
  }

  root.append(top);

  const actions = document.createElement("div");
  actions.className = "actions";
  let any = false;

  if (entry.has_password || entry.username) {
    actions.append(button("Fill", () => fill(entry, false)));
    any = true;
  }
  if (entry.has_password && entry.has_totp) {
    actions.append(button("Fill + code", () => fill(entry, true)));
  }
  if (entry.has_password) {
    actions.append(button("Copy password", () => copyPassword(entry)));
    any = true;
  }
  if (any) root.append(actions);

  return root;
}

function button(text, handler) {
  const node = document.createElement("button");
  node.className = "action";
  node.textContent = text;
  node.addEventListener("click", handler);
  return node;
}

function ring(id) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", "ring");
  svg.setAttribute("viewBox", "0 0 16 16");
  svg.dataset.ring = id;
  for (const cls of ["track", "head"]) {
    const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    circle.setAttribute("class", cls);
    circle.setAttribute("cx", "8");
    circle.setAttribute("cy", "8");
    circle.setAttribute("r", "6");
    if (cls === "head") circle.setAttribute("transform", "rotate(-90 8 8)");
    svg.append(circle);
  }
  return svg;
}

el("search").addEventListener("input", render);

/* ---------- scanning a QR code off the page ---------- */

let pendingImage = null;   // base64 PNG awaiting confirmation; cleared after use

el("scan").addEventListener("click", async () => {
  const button = el("scan");
  button.disabled = true;
  button.textContent = "Scanning…";
  try {
    // captureVisibleTab is allowed by activeTab, granted when the popup opens.
    const dataUrl = await chrome.tabs.captureVisibleTab({ format: "png" });
    const image = dataUrl.slice(dataUrl.indexOf(",") + 1);

    const reply = await send({ type: "scan_qr", image, save: false });
    if (!reply.ok) {
      if (reply.locked) return showLocked();
      return toast(reply.error || "Nothing found");
    }
    pendingImage = image;
    renderFound(reply.found || []);
    show("scan");
  } catch (e) {
    toast(e.message);
  } finally {
    button.disabled = false;
    button.textContent = "Scan QR";
  }
});

function renderFound(found) {
  const container = el("scan-found");
  container.textContent = "";
  for (const item of found) {
    const row = document.createElement("div");
    row.className = "found";

    const name = document.createElement("div");
    name.className = "entry-name";
    name.textContent = item.issuer || "Unnamed";
    row.append(name);

    if (item.username) {
      const user = document.createElement("div");
      user.className = "entry-user";
      user.textContent = item.username;
      row.append(user);
    }
    container.append(row);
  }
  const plural = found.length === 1 ? "account" : "accounts";
  el("scan-note").textContent =
    `${found.length} ${plural} on this page` +
    (currentDomain ? `, will be linked to ${currentDomain}.` : ".");
}

el("scan-cancel").addEventListener("click", () => {
  pendingImage = null;
  show("list");
});

el("scan-save").addEventListener("click", async () => {
  if (!pendingImage) return show("list");
  const button = el("scan-save");
  button.disabled = true;
  button.textContent = "Adding…";
  try {
    const reply = await send({
      type: "scan_qr",
      image: pendingImage,
      save: true,
      domain: currentDomain,
    });
    if (!reply.ok) {
      if (reply.locked) return showLocked();
      return toast(reply.error || "Failed");
    }
    const added = reply.added || [];
    const skipped = reply.skipped || [];
    toast(
      added.length
        ? `Added ${added.length}${skipped.length ? `, ${skipped.length} already there` : ""}`
        : "Already in the vault"
    );
    pendingImage = null;
    await loadEntries();
  } catch (e) {
    toast(e.message);
  } finally {
    button.disabled = false;
    button.textContent = "Add to vault";
  }
});

/* ---------- actions ---------- */

async function copyCode(entry) {
  const record = codes[entry.id];
  const code = record && !record.error ? record.code : null;
  if (!code) return toast("No code available");
  await navigator.clipboard.writeText(code);
  toast("Code copied");
}

async function copyPassword(entry) {
  try {
    const reply = await send({ type: "credentials", id: entry.id });
    if (!reply.ok) return toast(reply.error || "Failed");
    await navigator.clipboard.writeText(reply.password || "");
    toast("Password copied");
  } catch (e) {
    toast(e.message);
  }
}

async function fill(entry, withCode) {
  let reply;
  try {
    reply = await send({ type: "credentials", id: entry.id, include_code: !!withCode });
  } catch (e) {
    return toast(e.message);
  }
  if (!reply.ok) return toast(reply.error || "Failed");

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return toast("No active tab");

  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId: tab.id, allFrames: true },
      func: fillForm,
      args: [reply.username || "", reply.password || "", reply.code || ""],
    });
    const filled = results
      .map((r) => r && r.result)
      .filter(Boolean)
      .reduce((acc, r) => ({
        username: acc.username || r.username,
        password: acc.password || r.password,
        code: acc.code || r.code,
      }), { username: false, password: false, code: false });

    const parts = [];
    if (filled.username) parts.push("username");
    if (filled.password) parts.push("password");
    if (filled.code) parts.push("code");
    toast(parts.length ? `Filled ${parts.join(" + ")}` : "No matching fields found");
    if (parts.length) window.close();
  } catch (e) {
    toast(`Can't fill here: ${e.message}`);
  }
}

/*
 * Injected into the page. Must be fully self-contained — it is serialised
 * and evaluated in the page's world, so it can close over nothing.
 */
function fillForm(username, password, code) {
  const report = { username: false, password: false, code: false };

  const isVisible = (node) => {
    if (!node || node.disabled || node.readOnly) return false;
    const rect = node.getBoundingClientRect();
    if (rect.width < 4 || rect.height < 4) return false;
    const style = getComputedStyle(node);
    return style.visibility !== "hidden" && style.display !== "none" && style.opacity !== "0";
  };

  // Bypass React/Vue value tracking by using the native setter.
  const setValue = (node, value) => {
    const proto = node instanceof HTMLTextAreaElement
      ? HTMLTextAreaElement.prototype
      : HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(proto, "value").set;
    node.focus();
    setter.call(node, value);
    node.dispatchEvent(new Event("input", { bubbles: true }));
    node.dispatchEvent(new Event("change", { bubbles: true }));
    node.dispatchEvent(new KeyboardEvent("keyup", { bubbles: true }));
  };

  const inputs = Array.from(document.querySelectorAll("input")).filter(isVisible);
  const describe = (node) =>
    [node.name, node.id, node.getAttribute("autocomplete"), node.placeholder,
     node.getAttribute("aria-label"), node.className]
      .filter(Boolean).join(" ").toLowerCase();

  /* --- one-time code --- */
  const otpPattern = /(one.?time|otp|totp|2fa|mfa|auth.?code|verif|token|passcode|security.?code)/i;
  const otpBoxes = inputs.filter(
    (n) => n.maxLength === 1 && /^(text|tel|number|password)$/.test(n.type)
  );

  if (code) {
    if (otpBoxes.length >= code.length) {
      // Split digit boxes, as used by many 2FA screens.
      otpBoxes.slice(0, code.length).forEach((node, i) => setValue(node, code[i]));
      report.code = true;
    } else {
      const otpField = inputs.find(
        (n) => n.getAttribute("autocomplete") === "one-time-code" || otpPattern.test(describe(n))
      );
      if (otpField) {
        setValue(otpField, code);
        report.code = true;
      }
    }
  }

  /* --- password --- */
  const passwordField = inputs.find((n) => n.type === "password" && !otpPattern.test(describe(n)));
  if (password && passwordField) {
    setValue(passwordField, password);
    report.password = true;
  }

  /* --- username --- */
  if (username) {
    const userPattern = /(user|email|login|account|identifi|phone|mobile)/i;
    let userField = inputs.find(
      (n) => /^(text|email|tel)$/.test(n.type) &&
             (["username", "email"].includes(n.getAttribute("autocomplete")) ||
              userPattern.test(describe(n))) &&
             !otpPattern.test(describe(n)) &&
             n.maxLength !== 1
    );
    // Fall back to the last text input before the password field.
    if (!userField && passwordField) {
      const before = inputs.slice(0, inputs.indexOf(passwordField));
      userField = before.reverse().find(
        (n) => /^(text|email|tel)$/.test(n.type) && n.maxLength !== 1
      );
    }
    if (userField) {
      setValue(userField, username);
      report.username = true;
    }
  }

  return report;
}

start();
