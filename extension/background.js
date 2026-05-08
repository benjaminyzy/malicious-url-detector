const API = "http://localhost:8000";

async function classifyAndStore(tabId, url) {
  try {
    const resp = await fetch(`${API}/classify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    if (!resp.ok) return;
    const data = await resp.json();
    data._checkedAt = Date.now();

    await chrome.storage.local.set({ [`tab_${tabId}`]: data });
    await updateBadge(tabId, data);
    notifyIfThreat(tabId, data);
  } catch {
    // Backend unreachable — clear any stale badge
    chrome.action.setBadgeText({ text: "", tabId });
  }
}

async function updateBadge(tabId, data) {
  const isMalicious = data.final_label === 1;
  const confidence  = data.confidence;

  let text, color;
  if (!isMalicious) {
    text  = "✓";
    color = "#22c55e"; // green
  } else if (confidence >= 66) {
    text  = "!";
    color = "#ef4444"; // red
  } else {
    text  = "?";
    color = "#f97316"; // orange
  }

  chrome.action.setBadgeText({ text, tabId });
  chrome.action.setBadgeBackgroundColor({ color, tabId });
}

function notifyIfThreat(tabId, data) {
  const isMalicious = data.final_label === 1;
  if (!isMalicious) return;

  const confidence = data.confidence;
  const shortUrl   = data.url.length > 60 ? data.url.slice(0, 57) + "…" : data.url;
  const notifId    = `threat_tab_${tabId}`;

  const isSuspicious = confidence < 66;
  const title   = isSuspicious ? "Suspicious URL Detected" : "Malicious URL Detected!";
  const message = `${shortUrl}\nConfidence: ${confidence}%`;

  chrome.notifications.create(notifId, {
    type:    "basic",
    iconUrl: "icons/shield.png",
    title,
    message,
    priority: 2,
  });
}

// ── Listen for page loads ─────────────────────────────────────────────────────

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete") return;
  const url = tab.url || "";
  if (!url.startsWith("http://") && !url.startsWith("https://")) return;
  classifyAndStore(tabId, url);
});

// ── Restore badge when switching tabs ─────────────────────────────────────────

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  const key = `tab_${tabId}`;
  const stored = await chrome.storage.local.get(key);
  if (stored[key]) {
    await updateBadge(tabId, stored[key]);
  } else {
    chrome.action.setBadgeText({ text: "", tabId });
  }
});
