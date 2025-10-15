import { renderSeverityChart, renderTypeChart } from './viz.js';

const state = {
  sbom: null,
  grype: null,
  vulns: [],
  pkgs: []
};

async function loadJSON(path){
  const res = await fetch(path);
  if(!res.ok) throw new Error(`Failed to fetch ${path}`);
  return res.json();
}

async function loadData(){
  const meta = document.getElementById('meta');
  meta.textContent = 'Loading reports…';
  try{
    const [sbom, grype] = await Promise.all([
      loadJSON('/reports/sbom.cdx.json'),
      loadJSON('/reports/grype.json')
    ]);
    state.sbom = sbom;
    state.grype = grype;
    parseData();
    meta.textContent = `Packages: ${state.pkgs.length}
Vulnerabilities: ${state.vulns.length}
Generated: ${(grype.descriptor && grype.descriptor.timestamp) || 'n/a'}`;
    drawCharts();
    renderTables();
  }catch(e){
    meta.textContent = 'No reports found. Using demo data.';
    await loadDemo();
    drawCharts();
    renderTables();
  }
}

async function loadDemo(){
  const demoSBOM = {
    bomFormat:"CycloneDX",
    components:[
      { name:"react", version:"18.2.0", type:"library", purl:"pkg:npm/react@18.2.0" },
      { name:"vite", version:"5.4.0", type:"application", purl:"pkg:npm/vite@5.4.0" },
      { name:"eslint", version:"9.13.0", type:"library", purl:"pkg:npm/eslint@9.13.0" }
    ]
  };
  const demoGrype = {
    matches:[
      { vulnerability:{id:"CVE-2024-1234", severity:"High"}, artifact:{name:"react", version:"18.2.0"} },
      { vulnerability:{id:"CVE-2025-1111", severity:"Medium"}, artifact:{name:"vite", version:"5.4.0"} }
    ],
    descriptor:{ timestamp:new Date().toISOString() }
  };
  state.sbom = demoSBOM;
  state.grype = demoGrype;
  parseData();
}

function parseData(){
  const comps = (state.sbom.components || []);
  state.pkgs = comps.map(c => ({ name:c.name, version:c.version, type:c.type || 'library' }));
  const matches = (state.grype.matches || []);
  state.vulns = matches.map(m => ({
    id: m.vulnerability?.id || 'N/A',
    severity: m.vulnerability?.severity || 'Unknown',
    pkg: m.artifact?.name || 'unknown',
    version: m.artifact?.version || ''
  }));
}

function drawCharts(){
  const severities = ['Critical','High','Medium','Low'];
  const counts = Object.fromEntries(severities.map(s=>[s,0]));
  state.vulns.forEach(v => { if(counts[v.severity] !== undefined) counts[v.severity]++; });
  renderSeverityChart(document.getElementById('severityChart'), counts);

  const byType = {};
  state.pkgs.forEach(p => { byType[p.type] = (byType[p.type]||0)+1; });
  renderTypeChart(document.getElementById('typeChart'), byType);
}

function renderTables(){
  // Vulnerabilities
  const vt = document.getElementById('vulnTable');
  vt.innerHTML = '<tr><th>CVE</th><th>Severity</th><th>Package</th><th>Version</th></tr>' +
    state.vulns.map(v => `<tr>
      <td>${v.id}</td>
      <td><span class="badge ${v.severity}">${v.severity}</span></td>
      <td>${v.pkg}</td>
      <td>${v.version}</td>
    </tr>`).join('');

  // Packages
  const pt = document.getElementById('pkgTable');
  pt.innerHTML = '<tr><th>Package</th><th>Version</th><th>Type</th></tr>' +
    state.pkgs.map(p => `<tr><td>${p.name}</td><td>${p.version}</td><td>${p.type}</td></tr>`).join('');

  // Filters
  const vFilter = document.getElementById('vulnFilter');
  const sFilter = document.getElementById('sevFilter');
  vFilter.oninput = () => applyVulnFilter();
  sFilter.onchange = () => applyVulnFilter();
  const pFilter = document.getElementById('pkgFilter');
  pFilter.oninput = () => applyPkgFilter();
}

function applyVulnFilter(){
  const term = (document.getElementById('vulnFilter').value || '').toLowerCase();
  const sev = document.getElementById('sevFilter').value;
  const vt = document.getElementById('vulnTable');
  vt.querySelectorAll('tr').forEach((tr,i) => {
    if(i===0) return;
    const [cve, sevTd, pkg, ver] = tr.children;
    const matchTerm = [cve.textContent, pkg.textContent, ver.textContent].join(' ').toLowerCase().includes(term);
    const matchSev = !sev || sevTd.textContent.trim()===sev;
    tr.style.display = (matchTerm && matchSev) ? '' : 'none';
  });
}
function applyPkgFilter(){
  const term = (document.getElementById('pkgFilter').value || '').toLowerCase();
  const pt = document.getElementById('pkgTable');
  pt.querySelectorAll('tr').forEach((tr,i) => {
    if(i===0) return;
    tr.style.display = tr.textContent.toLowerCase().includes(term) ? '' : 'none';
  });
}

// Tabs
function setupTabs(){
  const tabs = {
    'tab-dashboard':'dashboard',
    'tab-vulns':'vulns',
    'tab-packages':'packages'
  };
  Object.entries(tabs).forEach(([btnId, panelId]) => {
    document.getElementById(btnId).onclick = () => {
      document.querySelectorAll('nav .tab').forEach(b=>b.classList.remove('active'));
      document.getElementById(btnId).classList.add('active');
      document.querySelectorAll('.panel').forEach(p=>p.classList.remove('visible'));
      document.getElementById(panelId).classList.add('visible');
    };
  });
}

document.getElementById('reload').onclick = loadData;
setupTabs();
loadData();
