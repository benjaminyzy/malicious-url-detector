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

function notifyIfThreat(tabId, data) {
  if (data.final_label !== 1) return;
  const isHighConfidence = data.confidence >= 66;
  const title = isHighConfidence
    ? "Malicious URL detected"
    : "Suspicious URL detected";
  const message = `${data.url}\nConfidence: ${data.confidence}%`;

  chrome.notifications.create(`url-alert-${tabId}-${Date.now()}`, {
    type: "basic",
    iconUrl: "icons/shield.png",
    title,
    message,
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
    notifyIfThreat(tabId, data);
  } catch {
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
});
