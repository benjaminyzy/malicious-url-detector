const API = "http://localhost:8000";

let currentTabId = null;
let currentUrl = "";

function show(id) {
  ["loading", "error", "result", "non-http"].forEach((s) => {
    document.getElementById(s).style.display = s === id ? "block" : "none";
  });
}

function setVote(dotId, verdictId, value) {
  const isMalicious = value === 1;
  const dot = document.getElementById(dotId);
  const verdict = document.getElementById(verdictId);
  dot.className = "vote-dot " + (isMalicious ? "malicious" : "benign");
  verdict.textContent = isMalicious ? "Malicious" : "Benign";
  verdict.className = "vote-verdict " + (isMalicious ? "malicious" : "benign");
}

function findModelKeys(data, suffix) {
  return Object.keys(data)
    .filter((k) => k.endsWith(suffix) && k !== "rule_prediction")
    .sort();
}

function renderResult(data) {
  const isMalicious = data.final_label === 1;
  const confidence = data.confidence;
  const isOverride = data.override_applied === true;

  const badge = document.getElementById("badge");
  if (!isMalicious) {
    badge.textContent = "SAFE";
    badge.className = "badge safe";
  } else if (confidence >= 66) {
    badge.textContent = isOverride ? "MALICIOUS (OVERRIDE)" : "MALICIOUS";
    badge.className = "badge malicious";
  } else {
    badge.textContent = "SUSPICIOUS";
    badge.className = "badge suspicious";
  }

  document.getElementById("confidence").textContent = confidence + "%";

  const predKeys = findModelKeys(data, "_prediction");
  setVote("dot-rf", "verdict-rf", predKeys[0] ? data[predKeys[0]] : 0);
  setVote("dot-xgb", "verdict-xgb", predKeys[1] ? data[predKeys[1]] : 0);
  setVote("dot-rule", "verdict-rule", data.rule_prediction);

  const container = document.getElementById("rules-container");
  const rules = data.triggered_rules || [];
  if (rules.length === 0) {
    container.innerHTML = '<span class="no-rules">No rules triggered</span>';
  } else {
    const ul = document.createElement("ul");
    ul.className = "rules-list";
    rules.forEach((r) => {
      const li = document.createElement("li");
      li.textContent = r;
      ul.appendChild(li);
    });
    container.innerHTML = "";
    container.appendChild(ul);
  }

  const ts = document.getElementById("checked-at");
  if (data._checkedAt) {
    const secs = Math.round((Date.now() - data._checkedAt) / 1000);
    ts.textContent =
      secs < 5 ? "Last checked: just now" : `Last checked: ${secs}s ago`;
    ts.style.display = "block";
  } else {
    ts.style.display = "none";
  }

  show("result");
}

async function checkUrl(url, forceRefresh = false) {
  if (!forceRefresh && currentTabId !== null) {
    const key = `tab_${currentTabId}`;
    const stored = await chrome.storage.local.get(key);
    // Only use cached data if the cached URL matches the current URL.
    // Without this check, intra-tab navigation shows stale results.
    if (stored[key] && stored[key].url === url) {
      renderResult(stored[key]);
      return;
    }
  }

  show("loading");
  try {
    const resp = await fetch(`${API}/classify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    data._checkedAt = Date.now();

    if (currentTabId !== null) {
      await chrome.storage.local.set({ [`tab_${currentTabId}`]: data });
    }
    renderResult(data);
  } catch (e) {
    console.error("checkUrl failed", e);
    show("error");
  }
}

function truncate(url, max = 52) {
  return url.length > max ? url.slice(0, max) + "..." : url;
}

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const tab = tabs[0];
  currentTabId = tab?.id ?? null;
  currentUrl = tab?.url || "";
  document.getElementById("url-display").textContent = truncate(currentUrl);

  if (currentUrl.startsWith("http://") || currentUrl.startsWith("https://")) {
    checkUrl(currentUrl);
  } else {
    show("non-http");
  }
});

document.getElementById("recheck-btn").addEventListener("click", () => {
  if (currentUrl) checkUrl(currentUrl, true);
});

document.getElementById("retry-btn").addEventListener("click", () => {
  if (currentUrl) checkUrl(currentUrl, true);
});

document.getElementById("dashboard-btn").addEventListener("click", () => {
  chrome.tabs.create({ url: "http://localhost:8501" });
});
