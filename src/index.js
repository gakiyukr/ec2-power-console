const SESSION_COOKIE = "ec2_session";

export const TARGETS = [
  { region: "us-west-2", instanceId: "i-0d50f2b47b60208cb", name: "SEA-1" },

];

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function base64ToBytes(text) {
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function toBase64Url(text) {
  return bytesToBase64(new TextEncoder().encode(text))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function fromBase64Url(text) {
  const padded = text.replace(/-/g, "+").replace(/_/g, "/");
  const padLength = (4 - (padded.length % 4 || 4)) % 4;
  return new TextDecoder().decode(base64ToBytes(padded + "=".repeat(padLength)));
}

async function signText(text, secret) {
  const data = new TextEncoder().encode(secret);
  const key = await crypto.subtle.importKey(
    "raw",
    data,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(text),
  );
  return bytesToBase64(new Uint8Array(signature))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

async function createSessionValue(password, secret) {
  const payload = toBase64Url(JSON.stringify({ password, issuedAt: Date.now() }));
  const signature = await signText(payload, secret);
  return `${payload}.${signature}`;
}

async function verifySessionValue(sessionValue, secret, expectedPassword) {
  if (!sessionValue || !sessionValue.includes(".")) {
    return false;
  }

  const [payload, signature] = sessionValue.split(".", 2);
  const expectedSignature = await signText(payload, secret);
  if (signature !== expectedSignature) {
    return false;
  }

  try {
    const parsed = JSON.parse(fromBase64Url(payload));
    return parsed.password === expectedPassword;
  } catch {
    return false;
  }
}

function getSessionFromRequest(request) {
  const cookieHeader = request.headers.get("cookie") || "";
  const cookies = cookieHeader.split(/;\s*/).filter(Boolean);
  for (const cookie of cookies) {
    const [name, ...rest] = cookie.split("=");
    if (name === SESSION_COOKIE) {
      return decodeURIComponent(rest.join("="));
    }
  }
  return null;
}

function buildSessionCookie(sessionValue) {
  return `${SESSION_COOKIE}=${encodeURIComponent(sessionValue)}; Path=/; HttpOnly; SameSite=Strict; Secure`;
}

function buildClearedSessionCookie() {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Secure; Max-Age=0`;
}

function findTagValue(xml, tagName) {
  const match = xml.match(new RegExp(`<${tagName}>([^<]*)</${tagName}>`));
  return match ? match[1] : "";
}

function findAllTagValues(xml, tagName) {
  return [...xml.matchAll(new RegExp(`<${tagName}>([^<]*)</${tagName}>`, "g"))].map(
    (match) => match[1],
  );
}

function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text),
  );
  return bytesToHex(new Uint8Array(digest));
}

async function hmacSha256(keyBytes, text) {
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(text),
  );
  return new Uint8Array(signature);
}

async function deriveSigningKey(secretAccessKey, shortDate, region, service) {
  const kDate = await hmacSha256(
    new TextEncoder().encode(`AWS4${secretAccessKey}`),
    shortDate,
  );
  const kRegion = await hmacSha256(kDate, region);
  const kService = await hmacSha256(kRegion, service);
  return hmacSha256(kService, "aws4_request");
}

function isoNowParts(now = new Date()) {
  const iso = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  return {
    amzDate: iso,
    shortDate: iso.slice(0, 8),
  };
}

function buildEc2Endpoint(region) {
  return `https://ec2.${region}.amazonaws.com/`;
}

export function buildRegionGroups(targets = TARGETS) {
  const grouped = new Map();
  for (const target of targets) {
    if (!grouped.has(target.region)) {
      grouped.set(target.region, []);
    }
    grouped.get(target.region).push(target);
  }

  return [...grouped.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([region, items]) => ({
      region,
      items: items.map((item) => ({ ...item })),
    }));
}

function computeFallbackName(region, index) {
  return `${region} #${index + 1}`;
}

export function buildPlaceholderRegions(targets = TARGETS) {
  return buildRegionGroups(targets).map((group) => ({
    region: group.region,
    items: group.items.map((item, index) => ({
      displayName: item.name || computeFallbackName(group.region, index),
      instanceId: item.instanceId,
      region: item.region,
      state: "未刷新",
      publicDnsName: "未刷新",
      awsNameTag: "",
    })),
  }));
}

export function getTargetConfig(env) {
  return {
    region: env.AWS_REGION || "us-west-2",
    instanceId: env.EC2_INSTANCE_ID || "i-0d50f2b47b60208cb",
  };
}

function findTarget(region, instanceId, targets = TARGETS) {
  return targets.find(
    (target) => target.region === region && target.instanceId === instanceId,
  ) || null;
}

async function signedAwsRequest(region, env, action, instanceIds) {
  const service = "ec2";
  const method = "POST";
  const endpoint = buildEc2Endpoint(region);
  const { amzDate, shortDate } = isoNowParts();
  const bodyParams = new URLSearchParams({
    Action: action,
    Version: "2016-11-15",
  });
  instanceIds.forEach((instanceId, index) => {
    bodyParams.set(`InstanceId.${index + 1}`, instanceId);
  });
  const body = bodyParams.toString();
  const bodyHash = await sha256Hex(body);
  const host = `ec2.${region}.amazonaws.com`;
  const canonicalHeaders =
    `content-type:application/x-www-form-urlencoded; charset=utf-8\n` +
    `host:${host}\n` +
    `x-amz-date:${amzDate}\n`;
  const signedHeaders = "content-type;host;x-amz-date";
  const canonicalRequest = [
    method,
    "/",
    "",
    canonicalHeaders,
    signedHeaders,
    bodyHash,
  ].join("\n");
  const credentialScope = `${shortDate}/${region}/ec2/aws4_request`;
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    credentialScope,
    await sha256Hex(canonicalRequest),
  ].join("\n");
  const signingKey = await deriveSigningKey(
    env.AWS_SECRET_ACCESS_KEY,
    shortDate,
    region,
    "ec2",
  );
  const signature = bytesToHex(await hmacSha256(signingKey, stringToSign));
  const authorization =
    `AWS4-HMAC-SHA256 Credential=${env.AWS_ACCESS_KEY_ID}/${credentialScope}, ` +
    `SignedHeaders=${signedHeaders}, Signature=${signature}`;

  const fetchImpl = env.__testHooks?.fetch || fetch;
  return fetchImpl(endpoint, {
    method,
    headers: {
      "content-type": "application/x-www-form-urlencoded; charset=utf-8",
      "x-amz-date": amzDate,
      authorization,
    },
    body,
  });
}

function extractAwsNameTag(xml) {
  const names = findAllTagValues(xml, "value");
  return names[0] || "";
}

export function parseDescribeInstancesXml(xml) {
  return {
    instanceId: findTagValue(xml, "instanceId"),
    state: findTagValue(xml, "name"),
    publicDnsName: findTagValue(xml, "dnsName"),
    awsNameTag: extractAwsNameTag(xml),
  };
}

export async function getStatus(env) {
  if (env.__testHooks?.getStatus) {
    return env.__testHooks.getStatus();
  }

  const target = getTargetConfig(env);
  const response = await signedAwsRequest(
    target.region,
    env,
    "DescribeInstances",
    [target.instanceId],
  );
  if (!response.ok) {
    throw new Error(`AWS status request failed with ${response.status}`);
  }
  return parseDescribeInstancesXml(await response.text());
}

async function refreshTargets(env, targets = TARGETS) {
  if (env.__testHooks?.refreshTargets) {
    return env.__testHooks.refreshTargets(targets);
  }

  const groups = buildRegionGroups(targets);
  const results = [];

  for (const group of groups) {
    const response = await signedAwsRequest(
      group.region,
      env,
      "DescribeInstances",
      group.items.map((item) => item.instanceId),
    );

    if (!response.ok) {
      results.push({
        region: group.region,
        error: "查詢失敗",
        items: group.items.map((item, index) => ({
          displayName: item.name || computeFallbackName(group.region, index),
          instanceId: item.instanceId,
          region: item.region,
          state: "查詢失敗",
          publicDnsName: "查詢失敗",
          awsNameTag: "",
        })),
      });
      continue;
    }

    const xml = await response.text();
    const parsed = parseDescribeInstancesXml(xml);
    const lookup = new Map([[parsed.instanceId, parsed]]);

    results.push({
      region: group.region,
      items: group.items.map((item, index) => {
        const match = lookup.get(item.instanceId);
        const awsNameTag = match?.awsNameTag || "";
        return {
          displayName:
            item.name ||
            awsNameTag ||
            computeFallbackName(group.region, index),
          instanceId: item.instanceId,
          region: item.region,
          state: match?.state || "未找到",
          publicDnsName: match?.publicDnsName || "未找到",
          awsNameTag,
        };
      }),
    });
  }

  return { regions: results };
}

export async function performAction(env, action) {
  if (env.__testHooks?.performAction) {
    return env.__testHooks.performAction(action);
  }

  const target = getTargetConfig(env);
  const actionName = action === "start" ? "StartInstances" : "StopInstances";
  const response = await signedAwsRequest(
    target.region,
    env,
    actionName,
    [target.instanceId],
  );
  if (!response.ok) {
    throw new Error(`AWS action request failed with ${response.status}`);
  }

  if (action === "restart") {
    return {
      ok: true,
      action,
      phase: "stopping",
    };
  }

  return {
    ok: true,
    action,
  };
}

function escapeHtml(text) {
  return String(text)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function renderLoginPage(errorMessage = "") {
  const errorHtml = errorMessage
    ? `<p class="error">${escapeHtml(errorMessage)}</p>`
    : "";

  return `<!doctype html>
<html lang="zh-Hant">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>EC2 控制台登入</title>
    <style>
      :root {
        --bg: #f2eee4;
        --panel: #fffaf0;
        --ink: #162521;
        --accent: #0f766e;
        --accent-dark: #115e59;
        --error: #b42318;
      }
      body {
        margin: 0;
        min-height: 100vh;
        display: grid;
        place-items: center;
        background:
          radial-gradient(circle at top left, #fcd34d 0, transparent 32%),
          linear-gradient(145deg, #f3efe2, #dbe7dd);
        color: var(--ink);
        font-family: "Microsoft YaHei", "Microsoft JhengHei", sans-serif;
      }
      .card {
        width: min(92vw, 420px);
        background: var(--panel);
        border: 1px solid rgba(22, 37, 33, 0.12);
        border-radius: 20px;
        padding: 28px;
        box-shadow: 0 16px 48px rgba(22, 37, 33, 0.14);
      }
      h1 {
        margin-top: 0;
        margin-bottom: 12px;
        font-size: 2rem;
      }
      p {
        line-height: 1.5;
      }
      label {
        display: block;
        margin-top: 18px;
        margin-bottom: 8px;
        font-weight: 700;
      }
      input {
        box-sizing: border-box;
        width: 100%;
        padding: 12px 14px;
        border: 1px solid rgba(22, 37, 33, 0.2);
        border-radius: 12px;
        font: inherit;
      }
      button {
        margin-top: 18px;
        padding: 12px 18px;
        border: 0;
        border-radius: 999px;
        background: var(--accent);
        color: white;
        font: inherit;
        font-weight: 700;
        cursor: pointer;
      }
      button:hover {
        background: var(--accent-dark);
      }
      .error {
        color: var(--error);
        font-weight: 700;
      }
    </style>
  </head>
  <body>
    <main class="card">
      <h1>請輸入密碼</h1>
      <p>請使用共享密碼登入 WL EC2 控制台。</p>
      ${errorHtml}
      <form method="post" action="/login">
        <label for="password">密碼</label>
        <input id="password" name="password" type="password" required autofocus>
        <button type="submit">登入控制台</button>
      </form>
    </main>
  </body>
</html>`;
}

function renderRegionSections(regions) {
  return regions
    .map(
      (region) => `
        <section class="region-block" data-region="${escapeHtml(region.region)}">
          <header class="region-header">
            <h2>${escapeHtml(region.region)}</h2>
            <button type="button" class="secondary" data-refresh-region="${escapeHtml(region.region)}">刷新狀態</button>
          </header>
          <div class="machine-list">
            ${region.items
              .map(
                (item) => `
                  <article class="machine-card" data-region="${escapeHtml(item.region)}" data-instance-id="${escapeHtml(item.instanceId)}">
                    <div class="machine-main">
                      <div>
                        <strong class="machine-name">${escapeHtml(item.displayName)}</strong>
                        <div class="meta">${escapeHtml(item.instanceId)}</div>
                      </div>
                      <div class="meta">${escapeHtml(item.region)}</div>
                    </div>
                    <div class="machine-stats">
                      <div><span class="label">狀態</span><span class="value state">${escapeHtml(item.state)}</span></div>
                      <div><span class="label">公有 IPv4 DNS</span><span class="value dns">${escapeHtml(item.publicDnsName)}</span></div>
                    </div>
                    <div class="actions">
                      <button type="button" class="secondary" data-action="refresh-one">刷新狀態</button>
                      <button type="button" data-action="start">開機</button>
                      <button type="button" class="warn" data-action="stop">關機</button>
                      <button type="button" data-action="restart">重新啟動</button>
                    </div>
                  </article>
                `,
              )
              .join("")}
          </div>
        </section>
      `,
    )
    .join("");
}

function renderAppPage() {
  const placeholderRegions = buildPlaceholderRegions(TARGETS);

  return `<!doctype html>
<html lang="zh-Hant">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>EC2 控制台</title>
    <style>
      :root {
        --bg: #f2eee4;
        --panel: rgba(255, 250, 240, 0.94);
        --ink: #162521;
        --muted: #4b635d;
        --accent: #0f766e;
        --accent-dark: #115e59;
        --warn: #b54708;
      }
      body {
        margin: 0;
        min-height: 100vh;
        background:
          radial-gradient(circle at top left, rgba(252, 211, 77, 0.55) 0, transparent 28%),
          linear-gradient(160deg, #efe7d7, #d9e8e3);
        color: var(--ink);
        font-family: "Microsoft YaHei", "Microsoft JhengHei", sans-serif;
      }
      .shell {
        max-width: 1100px;
        margin: 0 auto;
        padding: 24px;
      }
      .hero,
      .panel,
      .region-block {
        background: var(--panel);
        border: 1px solid rgba(22, 37, 33, 0.12);
        border-radius: 24px;
        box-shadow: 0 18px 48px rgba(22, 37, 33, 0.14);
      }
      .hero {
        padding: 28px;
        margin-bottom: 20px;
      }
      .hero h1 {
        margin: 0 0 8px;
        font-size: clamp(2rem, 5vw, 3rem);
      }
      .hero p {
        margin: 0;
        color: var(--muted);
      }
      .panel {
        padding: 20px 24px;
        margin-bottom: 20px;
      }
      .region-block {
        padding: 20px;
        margin-bottom: 18px;
      }
      .region-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 12px;
        margin-bottom: 16px;
      }
      .region-header h2 {
        margin: 0;
      }
      .machine-list {
        display: grid;
        gap: 14px;
      }
      .machine-card {
        padding: 18px;
        border-radius: 18px;
        background: rgba(255, 255, 255, 0.66);
      }
      .machine-main,
      .machine-stats {
        display: flex;
        justify-content: space-between;
        gap: 16px;
        flex-wrap: wrap;
      }
      .machine-stats {
        margin-top: 12px;
      }
      .machine-name {
        font-size: 1.1rem;
      }
      .meta,
      .label,
      #message {
        color: var(--muted);
      }
      .label {
        display: block;
        font-size: 0.9rem;
      }
      .value {
        display: block;
        margin-top: 6px;
        font-weight: 700;
        word-break: break-word;
      }
      .actions {
        display: flex;
        flex-wrap: wrap;
        gap: 12px;
        margin-top: 16px;
      }
      button {
        padding: 12px 18px;
        border: 0;
        border-radius: 999px;
        background: var(--accent);
        color: white;
        font: inherit;
        font-weight: 700;
        cursor: pointer;
      }
      button.secondary {
        background: #264653;
      }
      button.warn {
        background: var(--warn);
      }
      form.inline {
        display: inline;
      }
      #message {
        min-height: 1.4em;
        margin-top: 14px;
      }
    </style>
  </head>
  <body>
    <div class="shell">
      <section class="hero">
        <h1>多地區 EC2 控制台</h1>
        <p>先列出機器清單，再由你手動刷新各地區狀態與公有 IPv4 DNS。</p>
      </section>
      <section class="panel">
        <div class="actions">
          <button type="button" class="secondary" id="refresh-all">全部刷新</button>
          <form class="inline" method="post" action="/logout">
            <button type="submit" class="secondary">登出</button>
          </form>
        </div>
        <p id="message"></p>
      </section>
      ${renderRegionSections(placeholderRegions)}
    </div>
    <script>
      const messageEl = document.getElementById("message");

      function updateCard(item) {
        const card = document.querySelector(
          '.machine-card[data-region="' + item.region + '"][data-instance-id="' + item.instanceId + '"]',
        );
        if (!card) return;
        card.querySelector(".machine-name").textContent = item.displayName;
        card.querySelector(".state").textContent = item.state;
        card.querySelector(".dns").textContent = item.publicDnsName;
      }

      function applyRefreshPayload(data) {
        for (const region of data.regions || []) {
          for (const item of region.items || []) {
            updateCard(item);
          }
        }
      }

      async function refreshAll() {
        messageEl.textContent = "刷新中...";
        const response = await fetch("/api/refresh", { method: "POST" });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
          messageEl.textContent = data.error || "刷新失敗。";
          return;
        }
        applyRefreshPayload(data);
        messageEl.textContent = "刷新完成。";
      }

      async function runAction(region, instanceId, action) {
        messageEl.textContent = "處理中...";
        const response = await fetch("/api/action", {
          method: "POST",
          headers: {
            "content-type": "application/json",
          },
          body: JSON.stringify({ region, instanceId, action }),
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
          messageEl.textContent = data.error || "操作失敗。";
          return;
        }
        messageEl.textContent = data.message || "已送出操作。";
      }

      document.getElementById("refresh-all").addEventListener("click", refreshAll);

      document.querySelectorAll("[data-refresh-region]").forEach((button) => {
        button.addEventListener("click", refreshAll);
      });

      document.querySelectorAll(".machine-card [data-action]").forEach((button) => {
        button.addEventListener("click", () => {
          const card = button.closest(".machine-card");
          const region = card.dataset.region;
          const instanceId = card.dataset.instanceId;
          const action = button.dataset.action;
          if (action === "refresh-one") {
            refreshAll();
            return;
          }
          runAction(region, instanceId, action);
        });
      });
    </script>
  </body>
</html>`;
}

function htmlResponse(html, init = {}) {
  return new Response(html, {
    ...init,
    headers: {
      "content-type": "text/html; charset=utf-8",
      ...(init.headers || {}),
    },
  });
}

function jsonResponse(data, init = {}) {
  return new Response(JSON.stringify(data), {
    ...init,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...(init.headers || {}),
    },
  });
}

async function isAuthenticated(request, env) {
  if (env.__testHooks?.verifySession) {
    return env.__testHooks.verifySession(request, env);
  }

  const sessionValue = getSessionFromRequest(request);
  return verifySessionValue(sessionValue, env.SESSION_SECRET, env.APP_PASSWORD);
}

async function handleLogin(request, env) {
  const formData = await request.formData();
  const password = String(formData.get("password") || "");
  if (password !== env.APP_PASSWORD) {
    return htmlResponse(renderLoginPage("密碼不正確。"), { status: 401 });
  }

  const sessionValue = await createSessionValue(password, env.SESSION_SECRET);
  return new Response(null, {
    status: 302,
    headers: {
      location: "/",
      "set-cookie": buildSessionCookie(sessionValue),
    },
  });
}

function handleLogout() {
  return new Response(null, {
    status: 302,
    headers: {
      location: "/",
      "set-cookie": buildClearedSessionCookie(),
    },
  });
}

async function requireAuth(request, env) {
  const ok = await isAuthenticated(request, env);
  if (!ok) {
    return jsonResponse({ error: "Unauthorized" }, { status: 401 });
  }
  return null;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/") {
      const ok = await isAuthenticated(request, env);
      if (!ok) {
        return htmlResponse(renderLoginPage());
      }
      return htmlResponse(renderAppPage());
    }

    if (request.method === "POST" && url.pathname === "/login") {
      return handleLogin(request, env);
    }

    if (request.method === "POST" && url.pathname === "/logout") {
      return handleLogout();
    }

    if (url.pathname === "/api/status") {
      const authError = await requireAuth(request, env);
      if (authError) {
        return authError;
      }

      if (request.method !== "GET") {
        return jsonResponse({ error: "Method not allowed" }, { status: 405 });
      }

      return jsonResponse(await getStatus(env));
    }

    if (url.pathname === "/api/refresh") {
      const authError = await requireAuth(request, env);
      if (authError) {
        return authError;
      }

      if (request.method !== "POST") {
        return jsonResponse({ error: "Method not allowed" }, { status: 405 });
      }

      return jsonResponse(await refreshTargets(env));
    }

    if (url.pathname === "/api/action") {
      const authError = await requireAuth(request, env);
      if (authError) {
        return authError;
      }

      if (request.method !== "POST") {
        return jsonResponse({ error: "Method not allowed" }, { status: 405 });
      }

      const body = await request.json().catch(() => null);
      if (!body || typeof body !== "object") {
        return jsonResponse({ error: "請求內容無效。" }, { status: 400 });
      }

      const { region, instanceId, action } = body;
      if (!findTarget(region, instanceId)) {
        return jsonResponse({ error: "指定的機器不在清單內。" }, { status: 400 });
      }
      if (!["start", "stop", "restart"].includes(action)) {
        return jsonResponse({ error: "不支援的操作。" }, { status: 400 });
      }

      if (env.__testHooks?.performAction) {
        await env.__testHooks.performAction(action);
      } else {
        const actionName = action === "start" ? "StartInstances" : "StopInstances";
        const response = await signedAwsRequest(
          region,
          env,
          actionName,
          [instanceId],
        );
        if (!response.ok) {
          return jsonResponse({ error: "操作失敗。" }, { status: 500 });
        }
      }

      return jsonResponse({
        ok: true,
        action,
        message:
          action === "start"
            ? "已送出開機請求。"
            : action === "stop"
              ? "已送出關機請求。"
              : "已送出重新啟動流程。",
      });
    }

    return new Response("Not Found", { status: 404 });
  },
};
