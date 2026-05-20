const API = "http://localhost:8000";

async function updateBadge(tabId, data) {
  if (!data) {
    await chrome.action.setBadgeText({ tabId, text: "" });
    return;
  }
  const isMalicious = data.final_label === 1;
  const confidence = data.confidence;

  if (!isMalicious) {
    await chrome.action.setBadgeText({ tabId, text: "✓" });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: "#2ecc71" });
    return;
  }

  if (confidence >= 66) {
    await chrome.action.setBadgeText({ tabId, text: "!" });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: "#e74c3c" });
  } else {
    await chrome.action.setBadgeText({ tabId, text: "?" });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: "#f39c12" });
  }
}

// Unicode-safe hash for stable per-URL notification IDs.
function _shortHash(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash) + str.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash).toString(36);
}

async function notifyIfThreat(tabId, data) {
  if (data.final_label !== 1) return;

  // Dedup state in session storage survives service-worker suspension.
  const key = `notified_${tabId}`;
  let lastNotifiedUrl = null;
  try {
    if (chrome.storage.session) {
      const stored = await chrome.storage.session.get(key);
      lastNotifiedUrl = stored[key];
    }
  } catch (e) {
    console.error("session storage read failed", e);
  }
  if (lastNotifiedUrl === data.url) return;

  try {
    if (chrome.storage.session) {
      await chrome.storage.session.set({ [key]: data.url });
    }
  } catch (e) {
    console.error("session storage write failed", e);
  }

  const isHighConfidence = data.confidence >= 66;
  const title = isHighConfidence
    ? "Malicious URL detected"
    : "Suspicious URL detected";
  const idHash = _shortHash(data.url);
  chrome.notifications.create(`url-alert-${tabId}-${idHash}`, {
    type: "basic",
    iconUrl: "icons/shield.png",
    title,
    message: data.url,
    contextMessage: `Confidence: ${data.confidence}%`,
    priority: isHighConfidence ? 2 : 1,
  });
}

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
    await notifyIfThreat(tabId, data);
  } catch (e) {
    console.error("classifyAndStore failed", e);
    await chrome.action.setBadgeText({ tabId, text: "" });
  }
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete") return;
  const url = tab.url || "";
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    chrome.action.setBadgeText({ tabId, text: "" });
    return;
  }
  classifyAndStore(tabId, url);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.local.remove(`tab_${tabId}`);
  try {
    if (chrome.storage.session) {
      chrome.storage.session.remove(`notified_${tabId}`);
    }
  } catch (e) {
    console.error("session storage cleanup failed", e);
  }
});
