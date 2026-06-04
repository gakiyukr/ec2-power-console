const SESSION_COOKIE = "ec2_session";
const LOGIN_FAILURE_LIMIT = 5;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_BLOCK_MS = 15 * 60 * 1000;
const MAX_SESSION_AGE_MS = 24 * 60 * 60 * 1000;
const CLEANUP_INTERVAL_MS = 60 * 60 * 1000;
const loginFailures = new Map();
let lastCleanupTime = Date.now();

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

function constantTimeEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  let result = 0;
  for (let index = 0; index < a.length; index += 1) {
    result |= a.charCodeAt(index) ^ b.charCodeAt(index);
  }
  return result === 0;
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

async function createSessionValue(secret) {
  const payload = toBase64Url(JSON.stringify({ authenticated: true, issuedAt: Date.now() }));
  const signature = await signText(payload, secret);
  return `${payload}.${signature}`;
}

async function verifySessionValue(sessionValue, secret) {
  if (!sessionValue || !sessionValue.includes(".")) {
    return false;
  }

  const [payload, signature] = sessionValue.split(".", 2);
  const expectedSignature = await signText(payload, secret);
  if (!constantTimeEqual(signature, expectedSignature)) {
    return false;
  }

  try {
    const parsed = JSON.parse(fromBase64Url(payload));
    if (!parsed.authenticated) {
      return false;
    }
    const age = Date.now() - parsed.issuedAt;
    if (age > MAX_SESSION_AGE_MS || age < 0) {
      return false;
    }
    return true;
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

export function deriveIpFromPublicDns(publicDnsName) {
  const match = String(publicDnsName || "").match(
    /^ec2-(\d{1,3})-(\d{1,3})-(\d{1,3})-(\d{1,3})\.[a-z0-9-]+\.compute(?:-1)?\.amazonaws\.com(?:\.cn)?$/i,
  );
  if (!match) {
    return "";
  }

  const octets = match.slice(1).map(Number);
  if (octets.some((octet) => octet > 255)) {
    return "";
  }
  return octets.join(".");
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
      publicIpAddress: "未刷新",
      isWlInstance: false,
      awsNameTag: "",
    })),
  }));
}

export function getTargetConfig() {
  const [target] = TARGETS;
  if (target) {
    return {
      region: target.region,
      instanceId: target.instanceId,
    };
  }

  throw new Error("No EC2 targets configured");
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
  const nameTag = xml.match(
    /<item>\s*<key>Name<\/key>\s*<value>([^<]*)<\/value>\s*<\/item>/,
  );
  if (nameTag) {
    return nameTag[1];
  }

  const names = findAllTagValues(xml, "value");
  return names[0] || "";
}

export function parseDescribeInstancesXml(xml) {
  return parseDescribeInstancesXmlItems(xml)[0] || {
    instanceId: "",
    state: "",
    publicDnsName: "",
    publicIpAddress: "",
    isWlInstance: false,
    awsNameTag: "",
  };
}

export function parseDescribeInstancesXmlItems(xml) {
  const instanceMatches = [...xml.matchAll(/<instanceId>([^<]*)<\/instanceId>/g)];
  return instanceMatches.map((match, index) => {
    const nextMatch = instanceMatches[index + 1];
    const segment = xml.slice(match.index, nextMatch?.index ?? xml.length);
    const publicDnsName = findTagValue(segment, "dnsName");
    const awsPublicIpAddress = findTagValue(segment, "ipAddress");
    const derivedPublicIpAddress = deriveIpFromPublicDns(publicDnsName);
    const isWlInstance = Boolean(publicDnsName && !awsPublicIpAddress && derivedPublicIpAddress);
    return {
      instanceId: match[1],
      state: findTagValue(segment, "name"),
      publicDnsName,
      publicIpAddress: awsPublicIpAddress || derivedPublicIpAddress,
      isWlInstance,
      awsNameTag: extractAwsNameTag(segment),
    };
  });
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
    throw new Error("AWS request failed");
  }
  return parseDescribeInstancesXml(await response.text());
}

export async function refreshTargets(env, targets = TARGETS) {
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
          publicIpAddress: "查詢失敗",
          isWlInstance: false,
          awsNameTag: "",
        })),
      });
      continue;
    }

    const xml = await response.text();
    const parsedItems = parseDescribeInstancesXmlItems(xml);
    const lookup = new Map(
      parsedItems
        .filter((item) => item.instanceId)
        .map((item) => [item.instanceId, item]),
    );

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
          publicIpAddress: match?.publicIpAddress || "未找到",
          isWlInstance: Boolean(match?.isWlInstance),
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

  if (!["start", "stop"].includes(action)) {
    throw new Error(`Unsupported action: ${action}`);
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
    throw new Error("AWS request failed");
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

function getStateBadge(state) {
  const s = (state || "").toLowerCase().trim();
  let badgeClass = "badge-unknown";
  let text = state;
  
  if (s === "running") {
    badgeClass = "badge-running";
  } else if (s === "stopped") {
    badgeClass = "badge-stopped";
  } else if (["pending", "stopping", "shutting-down"].includes(s) || s.includes("中")) {
    badgeClass = "badge-pending";
  } else if (s === "查詢失敗") {
    badgeClass = "badge-failed";
  }
  
  return `<span class="state-badge ${badgeClass}"><span class="badge-dot"></span><span class="state">${escapeHtml(text)}</span></span>`;
}

function isCopyableValue(value) {
  return Boolean(value && value !== "未刷新" && value !== "查詢失敗" && value !== "未找到");
}

function renderCopyButton(value, title) {
  const displayStyle = isCopyableValue(value) ? "" : "display: none;";
  return `<button type="button" class="copy-btn" data-copy="${escapeHtml(value)}" style="${displayStyle}" title="${escapeHtml(title)}">
    <svg class="copy-icon" xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
    <svg class="check-icon" xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display: none;"><polyline points="20 6 9 17 4 12"></polyline></svg>
  </button>`;
}

function renderLoginPage(errorMessage = "") {
  const errorHtml = errorMessage
    ? `<div class="error-block">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
        <span>${escapeHtml(errorMessage)}</span>
       </div>`
    : "";

  return `<!doctype html>
<html lang="zh-Hant">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>EC2 控制台登入</title>
    <style>
      :root {
        --bg: #f8fafc;
        --card-bg: #ffffff;
        --text-primary: #0f172a;
        --text-secondary: #475569;
        --border: #e2e8f0;
        --primary: #0f172a;
        --primary-hover: #1e293b;
        --error-bg: #fef2f2;
        --error-text: #b91c1c;
        --error-border: #fecaca;
      }
      body {
        margin: 0;
        min-height: 100vh;
        display: grid;
        place-items: center;
        background: radial-gradient(at 0% 0%, #f1f5f9 0px, transparent 50%), radial-gradient(at 50% 0%, #e2e8f0 0px, transparent 50%), radial-gradient(at 100% 0%, #f8fafc 0px, transparent 50%), #fafafa;
        color: var(--text-primary);
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, "Microsoft YaHei", "Microsoft JhengHei", sans-serif;
      }
      .card {
        width: min(90vw, 380px);
        background: var(--card-bg);
        border: 1px solid var(--border);
        border-radius: 16px;
        padding: 32px;
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.05), 0 8px 10px -6px rgba(0, 0, 0, 0.03);
      }
      .icon-header {
        display: flex;
        justify-content: center;
        align-items: center;
        width: 48px;
        height: 48px;
        border-radius: 12px;
        background: #f1f5f9;
        color: #0f172a;
        margin-bottom: 24px;
      }
      h1 {
        margin-top: 0;
        margin-bottom: 8px;
        font-size: 1.5rem;
        font-weight: 600;
        color: var(--text-primary);
      }
      p {
        line-height: 1.5;
        color: var(--text-secondary);
        font-size: 0.9rem;
        margin-bottom: 24px;
        margin-top: 0;
      }
      label {
        display: block;
        margin-bottom: 8px;
        font-size: 0.85rem;
        font-weight: 600;
        color: var(--text-primary);
      }
      input {
        box-sizing: border-box;
        width: 100%;
        padding: 10px 14px;
        border: 1px solid var(--border);
        border-radius: 8px;
        font: inherit;
        font-size: 0.95rem;
        background-color: #ffffff;
        color: var(--text-primary);
        transition: all 0.2s ease;
      }
      input:focus {
        outline: none;
        border-color: #0f172a;
        box-shadow: 0 0 0 3px rgba(15, 23, 42, 0.08);
      }
      button {
        width: 100%;
        margin-top: 24px;
        padding: 10px 18px;
        border: 0;
        border-radius: 8px;
        background: var(--primary);
        color: white;
        font: inherit;
        font-weight: 500;
        font-size: 0.95rem;
        cursor: pointer;
        transition: all 0.2s ease;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
      }
      button:hover {
        background: var(--primary-hover);
        transform: translateY(-1px);
        box-shadow: 0 4px 12px rgba(15, 23, 42, 0.08);
      }
      button:active {
        transform: translateY(0);
      }
      .error-block {
        display: flex;
        align-items: center;
        gap: 8px;
        background: var(--error-bg);
        border: 1px solid var(--error-border);
        color: var(--error-text);
        padding: 10px 14px;
        border-radius: 8px;
        margin-bottom: 16px;
        font-size: 0.85rem;
        font-weight: 500;
      }
    </style>
  </head>
  <body>
    <main class="card">
      <div class="icon-header">
        <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lock-icon"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
      </div>
      <h1>請輸入密碼</h1>
      <p>請使用共享密碼登入 WL EC2 控制台。</p>
      ${errorHtml}
      <form method="post" action="/login">
        <label for="password">密碼</label>
        <input id="password" name="password" type="password" required autofocus>
        <button type="submit">
          <span>登入控制台</span>
          <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>
        </button>
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
            <div class="region-title">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color: var(--text-secondary);"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>
              <h2>${escapeHtml(region.region)}</h2>
            </div>
            <button type="button" class="secondary refresh-btn" data-refresh-region="${escapeHtml(region.region)}">
              <svg class="btn-icon" xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M23 4v6h-6"></path><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path></svg>
              <span>整理地區</span>
            </button>
          </header>
          <div class="machine-list">
            ${region.items
              .map(
                (item) => `
                  <article class="machine-card" data-region="${escapeHtml(item.region)}" data-instance-id="${escapeHtml(item.instanceId)}">
                    <div class="machine-header">
                      <div class="machine-icon">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect><rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect><line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line></svg>
                      </div>
                      <div class="machine-details">
                        <div class="machine-title-row">
                          <strong class="machine-name">${escapeHtml(item.displayName)}</strong>
                          <span class="wl-badge" style="${item.isWlInstance ? "" : "display: none;"}">WL</span>
                        </div>
                        <span class="machine-id">${escapeHtml(item.instanceId)}</span>
                      </div>
                      <span class="region-badge">${escapeHtml(item.region)}</span>
                    </div>
                    
                    <div class="machine-info-row">
                      <div class="info-item">
                        <span class="info-label">狀態</span>
                        ${getStateBadge(item.state)}
                      </div>
                      <div class="info-item">
                        <span class="info-label">公有 DNS</span>
                        <div class="dns-container">
                          <span class="info-value dns">${escapeHtml(item.publicDnsName)}</span>
                          ${renderCopyButton(item.publicDnsName, "複製公有 DNS")}
                        </div>
                      </div>
                      <div class="info-item">
                        <span class="info-label">公網 IP / 出站 IP</span>
                        <div class="dns-container">
                          <span class="info-value public-ip">${escapeHtml(item.publicIpAddress)}</span>
                          ${renderCopyButton(item.publicIpAddress, "複製公網 IP / 出站 IP")}
                        </div>
                      </div>
                    </div>
                    
                    <div class="card-actions">
                      <button type="button" class="secondary" data-action="refresh-one">
                        <svg class="btn-icon" xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M23 4v6h-6"></path><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path></svg>
                        <span>刷新</span>
                      </button>
                      <button type="button" class="start-btn" data-action="start">
                        <svg class="btn-icon" xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"></path><line x1="12" y1="2" x2="12" y2="12"></line></svg>
                        <span>開機</span>
                      </button>
                      <button type="button" class="warn stop-btn" data-action="stop">
                        <svg class="btn-icon" xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line></svg>
                        <span>關機</span>
                      </button>
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
        --bg: #f8fafc;
        --card-bg: #ffffff;
        --text-primary: #0f172a;
        --text-secondary: #475569;
        --border: #e2e8f0;
        --border-hover: #cbd5e1;
        --primary: #0f172a;
        --primary-hover: #1e293b;
        --secondary-bg: #f8fafc;
        --secondary-hover: #f1f5f9;
        
        --success-bg: #ecfdf5;
        --success-text: #047857;
        --success-border: #a7f3d0;
        
        --danger-bg: #fff1f2;
        --danger-text: #be123c;
        --danger-border: #fecdd3;
        
        --warning-bg: #fef3c7;
        --warning-text: #b45309;
        --warning-border: #fde68a;
        
        --gray-bg: #f1f5f9;
        --gray-text: #475569;
        --gray-border: #cbd5e1;
      }
      body {
        margin: 0;
        min-height: 100vh;
        background-color: var(--bg);
        color: var(--text-primary);
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, "Microsoft YaHei", "Microsoft JhengHei", sans-serif;
      }
      .shell {
        max-width: 1000px;
        margin: 0 auto;
        padding: 32px 16px;
        animation: fadeIn 0.4s ease-out;
      }
      @keyframes fadeIn {
        from { opacity: 0; transform: translateY(6px); }
        to { opacity: 1; transform: translateY(0); }
      }
      .app-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 32px;
        padding-bottom: 20px;
        border-bottom: 1px solid var(--border);
        flex-wrap: wrap;
        gap: 16px;
      }
      .app-brand {
        display: flex;
        align-items: center;
        gap: 10px;
      }
      .app-brand h1 {
        margin: 0;
        font-size: 1.35rem;
        font-weight: 700;
        color: var(--text-primary);
      }
      .brand-icon {
        color: var(--text-primary);
      }
      .header-actions {
        display: flex;
        align-items: center;
        gap: 12px;
      }
      .region-block {
        margin-bottom: 32px;
      }
      .region-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 16px;
      }
      .region-title {
        display: flex;
        align-items: center;
        gap: 8px;
      }
      .region-title h2 {
        margin: 0;
        font-size: 1.1rem;
        font-weight: 600;
        color: var(--text-primary);
        text-transform: uppercase;
        letter-spacing: 0.05em;
      }
      .machine-list {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
        gap: 16px;
      }
      .machine-card {
        background: var(--card-bg);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 20px;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.02), 0 1px 2px rgba(0, 0, 0, 0.04);
        transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
        display: flex;
        flex-direction: column;
        gap: 16px;
      }
      .machine-card:hover {
        border-color: var(--border-hover);
        box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.05), 0 4px 6px -2px rgba(0, 0, 0, 0.02);
        transform: translateY(-2px);
      }
      .machine-header {
        display: flex;
        align-items: flex-start;
        gap: 12px;
      }
      .machine-icon {
        display: flex;
        align-items: center;
        justify-content: center;
        width: 36px;
        height: 36px;
        border-radius: 8px;
        background-color: var(--gray-bg);
        color: var(--text-secondary);
        flex-shrink: 0;
      }
      .machine-details {
        flex-grow: 1;
        min-width: 0;
      }
      .machine-title-row {
        display: flex;
        align-items: center;
        gap: 8px;
        min-width: 0;
      }
      .machine-name {
        display: inline-block;
        font-size: 0.95rem;
        font-weight: 600;
        color: var(--text-primary);
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .wl-badge {
        flex-shrink: 0;
        border: 1px solid #f59e0b;
        background: #fffbeb;
        color: #b45309;
        border-radius: 4px;
        padding: 1px 6px;
        font-size: 0.68rem;
        font-weight: 700;
        line-height: 1.45;
      }
      .machine-id {
        display: block;
        font-size: 0.8rem;
        color: var(--text-secondary);
        margin-top: 2px;
      }
      .region-badge {
        font-size: 0.75rem;
        background-color: var(--gray-bg);
        color: var(--text-secondary);
        padding: 2px 6px;
        border-radius: 4px;
        font-weight: 500;
      }
      .machine-info-row {
        display: flex;
        flex-direction: column;
        gap: 10px;
        font-size: 0.85rem;
        padding: 12px 0;
        border-top: 1px solid var(--border);
        border-bottom: 1px solid var(--border);
      }
      .info-item {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 8px;
      }
      .info-label {
        color: var(--text-secondary);
        font-weight: 500;
        flex-shrink: 0;
      }
      .info-value {
        color: var(--text-primary);
        font-weight: 500;
        word-break: break-all;
        text-align: right;
      }
      .dns-container {
        display: inline-flex;
        align-items: center;
        justify-content: flex-end;
        gap: 6px;
        max-width: 180px;
        min-width: 0;
      }
      .dns-container .dns,
      .dns-container .public-ip {
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
        display: inline-block;
        max-width: 150px;
      }
      .copy-btn {
        background: none;
        border: none;
        padding: 4px;
        color: var(--text-secondary);
        border-radius: 4px;
        cursor: pointer;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        transition: all 0.15s ease;
      }
      .copy-btn:hover {
        background-color: var(--gray-bg);
        color: var(--text-primary);
      }
      .copy-btn.copied {
        color: var(--success-text);
        background-color: var(--success-bg);
      }
      .card-actions {
        display: flex;
        gap: 8px;
      }
      .card-actions button {
        flex: 1;
      }
      button {
        font: inherit;
        font-size: 0.85rem;
        font-weight: 500;
        padding: 8px 14px;
        border-radius: 6px;
        cursor: pointer;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 6px;
        transition: all 0.2s ease;
        box-sizing: border-box;
      }
      button:active:not(:disabled) {
        transform: translateY(0);
      }
      button:hover:not(:disabled) {
        transform: translateY(-1px);
      }
      button:disabled {
        opacity: 0.5;
        cursor: not-allowed;
      }
      .btn-icon {
        flex-shrink: 0;
      }
      button.primary, button#refresh-all {
        background-color: var(--primary);
        color: #ffffff;
        border: 1px solid var(--primary);
      }
      button.primary:hover:not(:disabled), button#refresh-all:hover:not(:disabled) {
        background-color: var(--primary-hover);
        border-color: var(--primary-hover);
      }
      button.secondary, button[data-action="refresh-one"], button.refresh-btn {
        background-color: var(--secondary-bg);
        color: var(--text-secondary);
        border: 1px solid var(--border);
      }
      button.secondary:hover:not(:disabled), button[data-action="refresh-one"]:hover:not(:disabled), button.refresh-btn:hover:not(:disabled) {
        background-color: var(--secondary-hover);
        color: var(--text-primary);
        border-color: var(--border-hover);
      }
      button.start-btn {
        background-color: #ecfdf5;
        color: #047857;
        border: 1px solid #a7f3d0;
      }
      button.start-btn:hover:not(:disabled) {
        background-color: #d1fae5;
        border-color: #34d399;
      }
      button.warn, button.stop-btn {
        background-color: #fff1f2;
        color: #be123c;
        border: 1px solid #fecdd3;
      }
      button.warn:hover:not(:disabled), button.stop-btn:hover:not(:disabled) {
        background-color: #ffe4e6;
        border-color: #fb7185;
      }
      form.inline {
        display: inline-flex;
      }
      
      /* State Badge styles */
      .state-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 4px 10px;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 600;
      }
      .badge-dot {
        width: 6px;
        height: 6px;
        border-radius: 50%;
        display: inline-block;
      }
      .badge-running {
        background-color: #ecfdf5;
        color: #047857;
        border: 1px solid #a7f3d0;
      }
      .badge-running .badge-dot {
        background-color: #10b981;
      }
      .badge-stopped {
        background-color: #fff1f2;
        color: #be123c;
        border: 1px solid #fecdd3;
      }
      .badge-stopped .badge-dot {
        background-color: #ef4444;
      }
      .badge-pending {
        background-color: #fef3c7;
        color: #b45309;
        border: 1px solid #fde68a;
      }
      .badge-pending .badge-dot {
        background-color: #f59e0b;
      }
      .badge-unknown {
        background-color: #f1f5f9;
        color: #475569;
        border: 1px solid #cbd5e1;
      }
      .badge-unknown .badge-dot {
        background-color: #94a3b8;
      }
      .badge-failed {
        background-color: #fff1f2;
        color: #be123c;
        border: 1px solid #fecdd3;
      }
      .badge-failed .badge-dot {
        background-color: #ef4444;
      }

      /* Spinning keyframe animation */
      @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
      }
      .spinning {
        animation: spin 1.2s linear infinite;
        display: inline-block;
      }

      /* Toast Notification styling */
      .toast-container {
        position: fixed;
        top: 24px;
        left: 50%;
        transform: translateX(-50%);
        z-index: 1000;
        display: flex;
        flex-direction: column;
        gap: 8px;
        pointer-events: none;
      }
      .toast {
        pointer-events: auto;
        background: #ffffff;
        border: 1px solid var(--border);
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.05), 0 8px 10px -6px rgba(0, 0, 0, 0.03);
        border-radius: 8px;
        padding: 10px 16px;
        display: flex;
        align-items: center;
        gap: 8px;
        min-width: 280px;
        opacity: 0;
        transform: translateY(-16px);
        transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
        font-size: 0.85rem;
        font-weight: 500;
      }
      .toast.show {
        opacity: 1;
        transform: translateY(0);
      }
      .toast-success {
        border-left: 3px solid #10b981;
      }
      .toast-error {
        border-left: 3px solid #ef4444;
      }
      .toast-info {
        border-left: 3px solid #3b82f6;
      }
      .toast-icon {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        flex-shrink: 0;
      }
      .toast-message {
        color: var(--text-primary);
      }
    </style>
  </head>
  <body>
    <div id="toast-container" class="toast-container"></div>
    <div class="shell">
      <header class="app-header">
        <div class="app-brand">
          <svg class="brand-icon" xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 10h-1.26A8 8 0 1 0 9 20h9a6 6 0 0 0 6-6 6 6 0 0 0-6-6z"></path></svg>
          <h1>EC2 電源管理器</h1>
        </div>
        <div class="header-actions">
          <button type="button" class="primary" id="refresh-all">
            <svg class="btn-icon icon-spin-all" xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M23 4v6h-6"></path><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path></svg>
            <span>全部重新整理</span>
          </button>
          <form class="inline" method="post" action="/logout">
            <button type="submit" class="secondary">
              <svg class="btn-icon" xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path><polyline points="16 17 21 12 16 7"></polyline><line x1="21" y1="12" x2="9" y2="12"></line></svg>
              <span>登出</span>
            </button>
          </form>
        </div>
      </header>
      ${renderRegionSections(placeholderRegions)}
    </div>
    <script>
      let isRefreshing = false;

      function showToast(message, type = "info") {
        const container = document.getElementById("toast-container");
        if (!container) return;
        
        const toast = document.createElement("div");
        toast.className = \`toast toast-\${type}\`;
        
        let icon = "";
        if (type === "success") {
          icon = \`<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>\`;
        } else if (type === "error") {
          icon = \`<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#be123c" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>\`;
        } else {
          icon = \`<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#2563eb" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>\`;
        }
        
        toast.innerHTML = \`
          <span class="toast-icon">\${icon}</span>
          <span class="toast-message">\${message}</span>
        \`;
        container.appendChild(toast);
        
        requestAnimationFrame(() => {
          toast.classList.add("show");
        });
        
        setTimeout(() => {
          toast.classList.remove("show");
          toast.addEventListener("transitionend", () => {
            toast.remove();
          });
        }, 4000);
      }

      function getStatusBadgeClass(state) {
        const s = (state || "").toLowerCase().trim();
        if (s === "running") return "badge-running";
        if (s === "stopped") return "badge-stopped";
        if (["pending", "stopping", "shutting-down"].includes(s) || s.includes("中")) return "badge-pending";
        if (s === "查詢失敗" || s === "未找到") return "badge-failed";
        return "badge-unknown";
      }

      function isCopyableValue(value) {
        return Boolean(value && value !== "未刷新" && value !== "查詢失敗" && value !== "未找到");
      }

      function updateCopyButton(button, value) {
        if (!button) return;
        if (isCopyableValue(value)) {
          button.dataset.copy = value;
          button.style.display = "inline-flex";
        } else {
          button.dataset.copy = "";
          button.style.display = "none";
        }
      }

      function updateCard(item) {
        const escapedRegion = CSS.escape(item.region);
        const escapedInstanceId = CSS.escape(item.instanceId);
        const card = document.querySelector(
          \`.machine-card[data-region="\${escapedRegion}"][data-instance-id="\${escapedInstanceId}"]\`
        );
        if (!card) return;
        card.querySelector(".machine-name").textContent = item.displayName;

        const wlBadge = card.querySelector(".wl-badge");
        if (wlBadge) {
          wlBadge.style.display = item.isWlInstance ? "inline-flex" : "none";
        }
        
        const stateEl = card.querySelector(".state");
        if (stateEl) {
          stateEl.textContent = item.state;
          const badgeEl = stateEl.closest(".state-badge");
          if (badgeEl) {
            badgeEl.className = "state-badge " + getStatusBadgeClass(item.state);
          }
        }
        
        const dnsEl = card.querySelector(".dns");
        if (dnsEl) {
          dnsEl.textContent = item.publicDnsName;
        }

        const publicIpEl = card.querySelector(".public-ip");
        if (publicIpEl) {
          publicIpEl.textContent = item.publicIpAddress;
        }

        updateCopyButton(card.querySelector(".dns-container .dns + .copy-btn"), item.publicDnsName);
        updateCopyButton(card.querySelector(".dns-container .public-ip + .copy-btn"), item.publicIpAddress);
      }

      function applyRefreshPayload(data) {
        for (const region of data.regions || []) {
          for (const item of region.items || []) {
            updateCard(item);
          }
        }
      }

      function setRefreshingState(active) {
        isRefreshing = active;
        
        document.querySelectorAll("button").forEach(btn => {
          if (!btn.closest("form")) {
            btn.disabled = active;
          }
        });
        
        document.querySelectorAll(".icon-spin-all, .refresh-btn svg, [data-action='refresh-one'] svg").forEach(icon => {
          if (active) {
            icon.classList.add("spinning");
          } else {
            icon.classList.remove("spinning");
          }
        });
      }

      async function refreshAll() {
        if (isRefreshing) return;
        setRefreshingState(true);
        
        try {
          const response = await fetch("/api/refresh", { method: "POST" });
          const data = await response.json().catch(() => ({}));
          if (!response.ok) {
            showToast(data.error || "整理狀態失敗。", "error");
            return;
          }
          applyRefreshPayload(data);
          showToast("狀態已整理完成", "success");
        } catch (err) {
          showToast("網路錯誤，整理狀態失敗。", "error");
        } finally {
          setRefreshingState(false);
        }
      }

      async function runAction(region, instanceId, action) {
        if (action === "stop") {
          if (!confirm("確定要關機嗎？此操作將停止 EC2 實例。")) {
            return;
          }
        }
        
        const actionText = action === "start" ? "開機" : "關機";
        showToast(\`正在傳送 \${actionText} 請求...\`, "info");
        setRefreshingState(true);
        
        try {
          const response = await fetch("/api/action", {
            method: "POST",
            headers: {
              "content-type": "application/json",
            },
            body: JSON.stringify({ region, instanceId, action }),
          });
          const data = await response.json().catch(() => ({}));
          if (!response.ok) {
            showToast(data.error || \`\${actionText}操作失敗。\`, "error");
            return;
          }
          
          showToast(data.message || \`已成功送出 \${actionText} 請求。\`, "success");
          
          // Auto-refresh state after short delay
          setTimeout(refreshAll, 2000);
        } catch (err) {
          showToast("網路錯誤，操作失敗。", "error");
        } finally {
          setRefreshingState(false);
        }
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

      // Clipboard copy handling
      document.addEventListener("click", async (e) => {
        const copyBtn = e.target.closest(".copy-btn");
        if (!copyBtn) return;
        
        const textToCopy = copyBtn.dataset.copy;
        if (!textToCopy) return;
        
        try {
          await navigator.clipboard.writeText(textToCopy);
          
          const copyIcon = copyBtn.querySelector(".copy-icon");
          const checkIcon = copyBtn.querySelector(".check-icon");
          
          if (copyIcon && checkIcon) {
            copyIcon.style.display = "none";
            checkIcon.style.display = "inline-block";
            copyBtn.classList.add("copied");
            
            showToast("成功複製到剪貼簿", "success");
            
            setTimeout(() => {
              copyIcon.style.display = "inline-block";
              checkIcon.style.display = "none";
              copyBtn.classList.remove("copied");
            }, 2000);
          }
        } catch (err) {
          showToast("複製失敗", "error");
        }
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
      "content-security-policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'self'",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "referrer-policy": "no-referrer",
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
  return verifySessionValue(sessionValue, env.SESSION_SECRET);
}

function getLoginFailureStore(env) {
  return env.__testHooks?.loginFailures || loginFailures;
}

function getClientIp(request) {
  return request.headers.get("cf-connecting-ip") || "unknown";
}

function nowMs(env) {
  return env.__testHooks?.now?.() || Date.now();
}

function getLoginFailureRecord(request, env) {
  const store = getLoginFailureStore(env);
  const key = getClientIp(request);
  const now = nowMs(env);
  const record = store.get(key);
  if (!record) {
    return { store, key, now, record: null };
  }

  if (record.blockedUntil && record.blockedUntil > now) {
    return { store, key, now, record };
  }

  if (record.firstFailureAt + LOGIN_WINDOW_MS <= now) {
    store.delete(key);
    return { store, key, now, record: null };
  }

  return { store, key, now, record };
}

function isLoginBlocked(request, env) {
  const { record, now } = getLoginFailureRecord(request, env);
  return Boolean(record?.blockedUntil && record.blockedUntil > now);
}

function recordLoginFailure(request, env) {
  const { store, key, now, record } = getLoginFailureRecord(request, env);
  const nextRecord = record || {
    count: 0,
    firstFailureAt: now,
    blockedUntil: 0,
  };

  nextRecord.count += 1;
  if (nextRecord.count >= LOGIN_FAILURE_LIMIT) {
    nextRecord.blockedUntil = now + LOGIN_BLOCK_MS;
  }
  store.set(key, nextRecord);
}

function clearLoginFailures(request, env) {
  getLoginFailureStore(env).delete(getClientIp(request));
}

function cleanupExpiredFailures(env) {
  const now = nowMs(env);
  if (now - lastCleanupTime < CLEANUP_INTERVAL_MS) {
    return;
  }

  const store = getLoginFailureStore(env);
  const expiredKeys = [];

  for (const [key, record] of store.entries()) {
    if (record.firstFailureAt + LOGIN_WINDOW_MS <= now &&
        (!record.blockedUntil || record.blockedUntil <= now)) {
      expiredKeys.push(key);
    }
  }

  for (const key of expiredKeys) {
    store.delete(key);
  }

  if (!env.__testHooks?.now) {
    lastCleanupTime = now;
  }
}

async function handleLogin(request, env) {
  cleanupExpiredFailures(env);

  if (isLoginBlocked(request, env)) {
    return htmlResponse(renderLoginPage("登入嘗試過多，請稍後再試。"), { status: 429 });
  }

  const formData = await request.formData();
  const password = String(formData.get("password") || "");
  if (password !== env.APP_PASSWORD) {
    recordLoginFailure(request, env);
    return htmlResponse(renderLoginPage("密碼不正確。"), { status: 401 });
  }

  clearLoginFailures(request, env);
  const sessionValue = await createSessionValue(env.SESSION_SECRET);
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

      const contentLength = parseInt(request.headers.get("content-length") || "0", 10);
      if (contentLength > 10240) {
        return jsonResponse({ error: "請求內容過大。" }, { status: 413 });
      }

      const body = await request.json().catch(() => null);
      if (!body || typeof body !== "object") {
        return jsonResponse({ error: "請求內容無效。" }, { status: 400 });
      }

      const { region, instanceId, action } = body;
      if (!findTarget(region, instanceId)) {
        return jsonResponse({ error: "指定的機器不在清單內。" }, { status: 400 });
      }
      if (!["start", "stop"].includes(action)) {
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
            : "已送出關機請求。",
      });
    }

    return new Response("Not Found", { status: 404 });
  },
};
