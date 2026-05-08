const API = "http://localhost:8000";

let currentUrl = "";

function show(id) {
  ["loading", "error", "result"].forEach((s) => {
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

function renderResult(data) {
  const isMalicious = data.final_label === 1;
  const confidence = data.confidence;

  // Badge: MALICIOUS (high) → red, MALICIOUS (low / 1 vote) → orange SUSPICIOUS, BENIGN → green
  const badge = document.getElementById("badge");
  if (!isMalicious) {
    badge.textContent = "SAFE";
    badge.className = "badge safe";
  } else if (confidence >= 66) {
    badge.textContent = "MALICIOUS";
    badge.className = "badge malicious";
  } else {
    badge.textContent = "SUSPICIOUS";
    badge.className = "badge suspicious";
  }

  document.getElementById("confidence").textContent = confidence + "%";

  // Find RF and XGBoost keys dynamically
  const rfKey  = Object.keys(data).find((k) => k.endsWith("_prediction") && k.includes("random_forest"));
  const xgbKey = Object.keys(data).find((k) => k.endsWith("_prediction") && k.includes("xgboost"));

  setVote("dot-rf",   "verdict-rf",   rfKey  ? data[rfKey]  : 0);
  setVote("dot-xgb",  "verdict-xgb",  xgbKey ? data[xgbKey] : 0);
  setVote("dot-rule", "verdict-rule", data.rule_prediction);

  // Rules
  const container = document.getElementById("rules-container");
  const rules = data.triggered_rules || [];
  if (rules.length === 0) {
    container.innerHTML = '<span class="no-rules">✓ No rules triggered</span>';
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

  show("result");
}

async function checkUrl(url) {
  show("loading");
  try {
    const resp = await fetch(`${API}/classify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    renderResult(data);
  } catch {
    show("error");
  }
}

function truncate(url, max = 50) {
  return url.length > max ? url.slice(0, max) + "…" : url;
}

// ── Init ──────────────────────────────────────────────────────────────────────

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  currentUrl = tabs[0]?.url || "";
  document.getElementById("url-display").textContent = truncate(currentUrl, 52);
  if (currentUrl) {
    checkUrl(currentUrl);
  } else {
    show("error");
  }
});

document.getElementById("recheck-btn").addEventListener("click", () => {
  if (currentUrl) checkUrl(currentUrl);
});

document.getElementById("retry-btn").addEventListener("click", () => {
  if (currentUrl) checkUrl(currentUrl);
});

document.getElementById("dashboard-btn").addEventListener("click", () => {
  chrome.tabs.create({ url: "http://localhost:8501" });
});
