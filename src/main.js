// src/main.js

// ---------- Config ----------
const SBOM_URL = "./reports/sbom.cdx.json";
const GRYPE_URL = "./reports/grype.json";

// ---------- State ----------
let vulnsRaw = [];     // one row per Grype match
let viewMode = "pkg";  // "pkg" | "cve"
let severityFilter = "all";
let searchQuery = "";

// ---------- Severity ranking ----------
const SEV_RANK = { Critical: 4, High: 3, Medium: 2, Low: 1, Unknown: 0 };

// ---------- Helpers ----------
function bySeverityDesc(a, b) {
  return SEV_RANK[b.severity] - SEV_RANK[a.severity] ||
         a.cve.localeCompare(b.cve);
}
const fmt = (x) => (x == null ? "" : String(x));

function nvdUrlFor(cve) {
  return /^CVE-\d{4}-\d+$/i.test(cve) ? `https://nvd.nist.gov/vuln/detail/${cve}` : "";
}
function cveHref(v) {
  return (v.urls && v.urls[0]) || nvdUrlFor(v.cve) || "";
}

function link(html, url) {
  if (!url) return html;
  const safe = String(url).replace(/"/g, "&quot;");
  return `<a href="${safe}" target="_blank" rel="noopener noreferrer">${html}</a>`;
}

// ---------- Deduping ----------
function mergeArraysUnique(a = [], b = []) {
  return [...new Set([...a, ...b].filter(Boolean))];
}

function dedupeByPkg(list) {
  const seen = new Map();
  for (const v of list) {
    const key = `${v.cve}|${v.package}|${v.version}`;
    const old = seen.get(key);
    if (!old || SEV_RANK[v.severity] > SEV_RANK[old.severity]) {
      seen.set(key, {
        ...v,
        urls: mergeArraysUnique(old?.urls, v.urls),
        fixVersions: mergeArraysUnique(old?.fixVersions, v.fixVersions),
      });
    } else if (old) {
      old.urls = mergeArraysUnique(old.urls, v.urls);
      old.fixVersions = mergeArraysUnique(old.fixVersions, v.fixVersions);
    }
  }
  return [...seen.values()];
}

function dedupeByCve(list) {
  const best = new Map();
  for (const v of list) {
    const id = v.cve;
    const old = best.get(id);
    if (!old || SEV_RANK[v.severity] > SEV_RANK[old.severity]) {
      best.set(id, {
        ...v,
        urls: mergeArraysUnique(old?.urls, v.urls),
        fixVersions: mergeArraysUnique(old?.fixVersions, v.fixVersions),
      });
    } else if (old) {
      old.urls = mergeArraysUnique(old.urls, v.urls);
      old.fixVersions = mergeArraysUnique(old.fixVersions, v.fixVersions);
    }
  }
  return [...best.values()];
}

// ---------- Filters ----------
function applyFilters(list) {
  let out = list;
  if (severityFilter !== "all") {
    out = out.filter(v => v.severity === severityFilter);
  }
  if (searchQuery.trim()) {
    const q = searchQuery.trim().toLowerCase();
    out = out.filter(v =>
      v.cve.toLowerCase().includes(q) ||
      v.package.toLowerCase().includes(q) ||
      (v.version || "").toLowerCase().includes(q)
    );
  }
  return out.sort(bySeverityDesc);
}

// ---------- Rendering ----------
function renderVulnTable(list) {
  const tbody = document.getElementById("vuln-tbody");
  if (!tbody) return;

  const rows = list.map(v => {
    const url = cveHref(v);
    const cveCell = link(fmt(v.cve), url);
    const fixedIn = v.fixVersions && v.fixVersions.length ? v.fixVersions[0] : "";
    return `
      <tr>
        <td>${cveCell}</td>
        <td><span class="sev sev-${v.severity.toLowerCase()}">${v.severity}</span></td>
        <td>${fmt(v.package)}</td>
        <td>${fmt(v.version)}</td>
        <td>${fmt(fixedIn)}</td>
      </tr>
    `;
  });

  tbody.innerHTML = rows.join("") || `
    <tr><td colspan="5" style="opacity:.7">No results</td></tr>
  `;

  const countEl = document.getElementById("vuln-count");
  if (countEl) countEl.textContent = String(list.length);
}

// ---------- Data loading ----------
async function fetchJSON(url) {
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
  return res.json();
}

function shapeFromGrype(grype) {
  // Expecting Grype JSON with "matches"
  if (grype && Array.isArray(grype.matches)) {
    return grype.matches.map(m => {
      const vuln = m?.vulnerability || {};
      const art  = m?.artifact || {};
      const fix  = vuln?.fix || {};
      return {
        cve: vuln.id || m?.id || "UNKNOWN",
        severity: vuln.severity || "Unknown",
        package: art.name || art.pkg?.name || "unknown",
        version: art.version || art.pkg?.version || "",
        urls: mergeArraysUnique(vuln.urls, [vuln.dataSource]),
        fixVersions: Array.isArray(fix.versions) ? fix.versions : [],
      };
    });
  }

  console.warn("Unrecognized Grype format; raw object:", grype);
  return [];
}

async function loadReports() {
  const meta = document.getElementById("meta");
  try {
    // SBOM not required for table, but we keep this to validate availability
    await fetchJSON(SBOM_URL).catch(() => null);

    const grype = await fetchJSON(GRYPE_URL);
    vulnsRaw = shapeFromGrype(grype);

    if (meta) {
      meta.textContent = `Data source: ${SBOM_URL} & ${GRYPE_URL} (${vulnsRaw.length} matches)`;
    }
  } catch (e) {
    console.error("Failed loading reports:", e);
    if (meta) meta.textContent = "No reports found. Using demo data.";
    vulnsRaw = [{
      cve: "DEMO-0000",
      severity: "Medium",
      package: "demo",
      version: "1.0.0",
      urls: [ "https://example.com" ],
      fixVersions: ["1.0.1"],
    }];
  }
}

// ---------- Controller ----------
function currentView(listRaw) {
  const base = viewMode === "cve" ? dedupeByCve(listRaw) : dedupeByPkg(listRaw);
  return applyFilters(base);
}

function rerender() {
  renderVulnTable(currentView(vulnsRaw));
}

// ---------- Wire up UI ----------
function setupUI() {
  const groupToggle = document.getElementById("group-by-cve");
  if (groupToggle) groupToggle.addEventListener("change", (e) => {
    viewMode = e.target.checked ? "cve" : "pkg";
    rerender();
  });

  const sevSel = document.getElementById("severityFilter");
  if (sevSel) sevSel.addEventListener("change", (e) => {
    severityFilter = e.target.value;
    rerender();
  });

  const search = document.getElementById("searchInput");
  if (search) search.addEventListener("input", (e) => {
    searchQuery = e.target.value || "";
    rerender();
  });

  const reloadBtn = document.getElementById("reloadBtn");
  if (reloadBtn) reloadBtn.addEventListener("click", async () => {
    await loadReports();
    rerender();
  });
}

// ---------- Init ----------
(async function init() {
  setupUI();
  await loadReports();
  rerender();
})();
