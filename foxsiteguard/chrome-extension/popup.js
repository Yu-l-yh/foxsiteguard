/**
 * FoxSiteGuard — Popup Script
 *
 * Displays analysis results. Supports both safe mode (local only)
 * and deep mode (includes SSL handshake + WHOIS).
 */

const API_URL = "http://127.0.0.1:8000/analyze";
const HEALTH_URL = "http://127.0.0.1:8000/health";
const STATUS_COLORS = {
  CRITICAL: { ring: "#c0392b", bg: "#fce4e4", text: "#c0392b" },
  "HIGH RISK": { ring: "#e67e22", bg: "#fef5e7", text: "#e67e22" },
  "MEDIUM RISK": { ring: "#f1c40f", bg: "#fef9e7", text: "#b7950b" },
  SAFE: { ring: "#27ae60", bg: "#eafaf1", text: "#27ae60" },
};

const $ = (id) => document.getElementById(id);

async function checkServerHealth() {
  try {
    const res = await fetch(HEALTH_URL, { signal: AbortSignal.timeout(2000) });
    const ok = res.ok;
    $("statusDot").className = ok ? "badge-online" : "badge-offline";
    $("statusLabel").textContent = ok ? "connected" : "error";
    return ok;
  } catch {
    $("statusDot").className = "badge-offline";
    $("statusLabel").textContent = "offline";
    return false;
  }
}

function displayResult(data) {
  if (!data?.result) {
    $("scoreRing").textContent = "?";
    $("scoreRing").style.borderColor = "#ccc";
    $("levelLabel").textContent = "Unknown";
    $("reasonsList").innerHTML = "<li>No analysis data available</li>";
    return;
  }

  const { score, level, reasons } = data.result;
  const colors = STATUS_COLORS[level] || STATUS_COLORS.SAFE;

  $("scoreRing").textContent = score;
  $("scoreRing").style.borderColor = colors.ring;
  $("levelLabel").textContent = level;
  $("levelLabel").style.color = colors.text;
  $("statusCard").style.background = colors.bg;

  $("reasonsList").innerHTML = "";
  if (reasons?.length > 0) {
    $("reasonsList").style.display = "block";
    reasons.forEach((r) => {
      const li = document.createElement("li");
      li.textContent = r;
      $("reasonsList").appendChild(li);
    });
  } else {
    $("reasonsList").style.display = "none";
  }

  // Show mode
  $("modeIndicator").textContent = data.mode === "deep"
    ? "Deep analysis: SSL + WHOIS (network)"
    : "Safe mode: local checks only (no network)";
}

async function analyzeUrl(url) {
  const btn = $("btnCheck");
  btn.disabled = true;
  btn.textContent = "Analyzing...";
  $("errorMsg").textContent = "";

  const isSafe = document.getElementById("safeToggle").checked;

  try {
    const res = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, safe_mode: isSafe }),
      signal: AbortSignal.timeout(15000),
    });

    if (!res.ok) {
      $("errorMsg").textContent = `Server error: ${res.status}`;
      return;
    }

    const data = await res.json();
    $("urlInput").value = url;
    $("urlInput").title = url;
    displayResult(data);
  } catch (e) {
    $("errorMsg").textContent = "Cannot reach server.\nIs the backend running?\n\nRun: .venv\\Scripts\\python -m foxsiteguard.main";
    console.error("[FoxSiteGuard] API error:", e);
  } finally {
    btn.disabled = false;
    btn.textContent = "Check URL";
  }
}

function getInputUrl() {
  let raw = $("urlInput").value.trim();
  if (!raw) return "";
  if (!raw.startsWith("http://") && !raw.startsWith("https://")) {
    raw = "https://" + raw;
  }
  return raw;
}

function doCheck() {
  const url = getInputUrl();
  if (!url) { $("errorMsg").textContent = "Please enter a URL."; return; }
  analyzeUrl(url);
}

async function fillCurrentTab() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.url && tab.url.startsWith("http")) {
      $("urlInput").value = tab.url;
      $("urlInput").title = tab.url;
    }
  } catch { /* ignore */ }
}

function updateDeepWarning(visible) {
  $("deepWarning").classList.toggle("visible", visible);
}

// Init
(async function init() {
  await checkServerHealth();

  // Load saved preference
  const { safeMode } = await chrome.storage.local.get("safeMode");
  if (safeMode !== undefined) {
    document.getElementById("safeToggle").checked = safeMode;
  }
  updateDeepWarning(!document.getElementById("safeToggle").checked);

  await fillCurrentTab();

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.id) {
    const stored = await chrome.storage.session.get(`analysis_${tab.id}`);
    if (stored[`analysis_${tab.id}`]) {
      displayResult(stored[`analysis_${tab.id}`]);
    }
  }

  $("urlInput").focus();
  $("urlInput").select();
})();

// Events
$("btnCheck").addEventListener("click", doCheck);
$("btnUseCurrent").addEventListener("click", () => { fillCurrentTab(); $("urlInput").focus(); });
$("urlInput").addEventListener("keydown", (e) => { if (e.key === "Enter") doCheck(); });
$("safeToggle").addEventListener("change", (e) => {
  chrome.storage.local.set({ safeMode: e.target.checked });
  updateDeepWarning(!e.target.checked);
});
