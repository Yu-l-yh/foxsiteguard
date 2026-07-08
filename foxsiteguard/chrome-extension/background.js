/**
 * FoxSiteGuard — Background Service Worker
 *
 * Intercepts page navigation, sends URLs to the local analysis API,
 * and blocks or warns based on risk level.
 */

const API_URL = "http://127.0.0.1:8000/analyze";
const API_TIMEOUT = 5000;

// Local cache to avoid re-checking the same domain within a session
const analysisCache = new Map();

async function analyzeUrl(url) {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), API_TIMEOUT);

    const res = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (!res.ok) return null;
    return await res.json();
  } catch (e) {
    console.warn("[FoxSiteGuard] API error:", e.message);
    return null;
  }
}

function getCachedOrAnalyze(url) {
  try {
    const u = new URL(url);
    const key = u.hostname;

    if (analysisCache.has(key)) {
      const cached = analysisCache.get(key);
      if (Date.now() - cached.timestamp < 300_000) {
        // 5 min cache
        return Promise.resolve(cached.data);
      }
      analysisCache.delete(key);
    }

    return analyzeUrl(url).then((data) => {
      if (data) {
        analysisCache.set(key, { data, timestamp: Date.now() });
      }
      return data;
    });
  } catch {
    return Promise.resolve(null);
  }
}

async function handleTabUpdate(tabId, changeInfo, tab) {
  if (changeInfo.status !== "complete") return;
  if (!tab.url || !tab.url.startsWith("http")) return;

  const data = await getCachedOrAnalyze(tab.url);
  if (!data) return;

  const score = data?.result?.score;
  const level = data?.result?.level;

  // Determine badge and color
  let badgeText = "";
  let badgeColor = [0, 0, 0, 0]; // transparent

  if (level === "CRITICAL") {
    badgeText = "!!";
    badgeColor = [180, 0, 0, 255];
  } else if (level === "HIGH RISK") {
    badgeText = "!";
    badgeColor = [220, 60, 0, 255];
  } else if (level === "MEDIUM RISK") {
    badgeText = "?";
    badgeColor = [220, 180, 0, 255];
  } else {
    badgeText = "";
    badgeColor = [0, 160, 60, 255];
  }

  // Block dangerous pages
  if (score >= 80) {
    chrome.tabs.update(tabId, {
      url: chrome.runtime.getURL("blocked.html"),
    });
    return;
  }

  // Update badge
  chrome.action.setBadgeText({ text: badgeText, tabId });
  chrome.action.setBadgeBackgroundColor({ color: badgeColor, tabId });

  // Store analysis result for popup
  chrome.storage.session.set({ [`analysis_${tabId}`]: data });
}

// Listen for page navigation
chrome.tabs.onUpdated.addListener(handleTabUpdate);

// When tab switches, show stored result
chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  const stored = await chrome.storage.session.get(`analysis_${tabId}`);
  if (stored[`analysis_${tabId}`]) {
    const data = stored[`analysis_${tabId}`];
    const score = data?.result?.score;
    if (score >= 80) {
      chrome.action.setBadgeText({ text: "!", tabId });
      chrome.action.setBadgeBackgroundColor({ color: [180, 0, 0, 255], tabId });
    }
  }
});
