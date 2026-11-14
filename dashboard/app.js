/* AzIAM Assessor - dashboard logic */
(function () {
  "use strict";
  const D = window.ASSESSMENT_DATA || emptyData();
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const SEV = ["Critical", "High", "Medium", "Low", "Info"];
  const SEVCOLOR = { Critical: "#ff4d5e", High: "#ff8a3d", Medium: "#ffcc3d", Low: "#4fd0ff", Info: "#8c97b0" };
  const TYPECOLOR = { User: "#7bb8ff", Group: "#c79bff", ServicePrincipal: "#ffb86b", ManagedIdentity: "#38d39f",
    DirectoryRole: "#ff6b9d", Subscription: "#4f9cff", ResourceGroup: "#5f6b85", Resource: "#3a455f", Tenant: "#4f9cff" };

  function emptyData() {
    return { meta: { tool: "AzIAM", riskScore: 0, subscriptions: [] }, stats: {},
      findings: [], identities: [], roleAssignments: [], resources: [], directoryRoles: [],
      graph: { nodes: [], edges: [] }, attackPaths: [] };
  }

  /* ---------- header + risk ---------- */
  function initHeader() {
    const m = D.meta || {};
    $("#hdrMeta").textContent = `tenant ${m.tenantId || "?"} · ${(m.subscriptions || []).length} sub(s) · ${fmtDate(m.generatedAt)}`;
    const r = m.riskScore || 0;
    const color = r >= 70 ? "#ff4d5e" : r >= 40 ? "#ff8a3d" : r >= 15 ? "#ffcc3d" : "#38d39f";
    const ring = $("#riskRing");
    ring.style.setProperty("--riskpct", r);
    ring.style.setProperty("--riskcolor", color);
    $("#riskNum").textContent = r;
    $("#riskNum").style.color = color;
  }
  const fmtDate = (s) => { if (!s) return "n/a"; try { return new Date(s).toLocaleString(); } catch { return s; } };

  /* ---------- tabs ---------- */
  function initTabs() {
    $$("#tabs button").forEach(b => b.addEventListener("click", () => {
      $$("#tabs button").forEach(x => x.classList.remove("active"));
      $$(".tabpane").forEach(x => x.classList.remove("active"));
      b.classList.add("active");
      $("#tab-" + b.dataset.tab).classList.add("active");
      if (b.dataset.tab === "graph") renderGraph();
    }));
  }

  /* ---------- overview ---------- */
  function renderOverview() {
    const s = D.stats || {};
    const cards = [
      { k: "critical", l: "Critical", cls: "crit" }, { k: "high", l: "High", cls: "high" },
      { k: "findings", l: "Findings", cls: "accent" }, { k: "attackPaths", l: "Attack Paths", cls: "accent" },
      { k: "users", l: "Users", cls: "" }, { k: "groups", l: "Groups", cls: "" },
      { k: "servicePrincipals", l: "Service Principals", cls: "" }, { k: "managedIdentities", l: "Managed IDs", cls: "" },
      { k: "roleAssignments", l: "Role Assignments", cls: "" }, { k: "resources", l: "Resources", cls: "" },
      { k: "tier0Nodes", l: "Tier-0 Assets", cls: "crit" }, { k: "subscriptions", l: "Subscriptions", cls: "" },
    ];
    $("#statGrid").innerHTML = cards.map(c =>
      `<div class="card stat ${c.cls}"><div class="num">${s[c.k] ?? 0}</div><div class="lbl">${c.l}</div></div>`).join("");

    // severity bar
    const counts = SEV.map(sv => (D.findings || []).filter(f => f.severity === sv).length);
    const total = counts.reduce((a, b) => a + b, 0) || 1;
    $("#sevBar").innerHTML = SEV.map((sv, i) =>
      `<i style="width:${(counts[i] / total) * 100}%;background:${SEVCOLOR[sv]}"></i>`).join("");
    $("#sevLegend").innerHTML = SEV.map((sv, i) =>
      `<span><span class="dot" style="background:${SEVCOLOR[sv]}"></span>${sv} <b>${counts[i]}</b></span>`).join("");

    $("#topRisks").innerHTML = (D.findings || []).slice(0, 6).map(f =>
      `<div class="row" style="margin:8px 0"><span class="pill ${f.severity}">${f.severity}</span>
       &nbsp;${esc(f.title)}</div>`).join("") || `<div class="empty">No findings 🎉</div>`;

    const m = D.meta || {};
    $("#tenantInfo").innerHTML = `
      <div class="row"><b>Tenant ID:</b> <span class="mono">${esc(m.tenantId)}</span></div>
      <div class="row"><b>Account:</b> ${esc(m.account)}</div>
      <div class="row"><b>Generated:</b> ${fmtDate(m.generatedAt)}</div>
      <div class="row"><b>Subscriptions:</b><br>${(m.subscriptions || []).map(x => `<span class="tag">${esc(x.name)}</span>`).join(" ")}</div>`;
  }

  /* ---------- findings ---------- */
  function renderFindings() {
    const cats = [...new Set((D.findings || []).map(f => f.category))].sort();
    $("#findCat").innerHTML = `<option value="">All categories</option>` + cats.map(c => `<option>${esc(c)}</option>`).join("");
    const draw = () => {
      const q = $("#findSearch").value.toLowerCase();
      const sv = $("#findSev").value, ct = $("#findCat").value;
      const list = (D.findings || []).filter(f =>
        (!sv || f.severity === sv) && (!ct || f.category === ct) &&
        (!q || JSON.stringify(f).toLowerCase().includes(q)));
      $("#findingsList").innerHTML = list.length ? list.map(findingHtml).join("") :
        `<div class="empty">No matching findings</div>`;
    };
    ["findSearch", "findSev", "findCat"].forEach(id => $("#" + id).addEventListener("input", draw));
    draw();
  }
  function findingHtml(f) {
    const refs = (f.references || []).map(r => `<a href="${esc(r)}" target="_blank" rel="noopener">${esc(r)}</a>`).join("<br>");
    return `<details class="finding card ${f.severity}" style="padding:0">
      <summary><span class="pill ${f.severity}">${f.severity}</span>
        <span class="ftitle">${esc(f.title)}</span>
        <span class="tag">${esc(f.category)}</span></summary>
      <div class="body">
        <div class="row">${esc(f.description)}</div>
        <div class="row"><b>Principal:</b> ${esc(f.principal)} <span class="tag">${esc(f.principalType)}</span></div>
        ${f.evidence ? `<div class="row"><b>Evidence:</b> <span class="mono">${esc(f.evidence)}</span></div>` : ""}
        <div class="rec"><b>→ Recommendation:</b> ${esc(f.recommendation)}</div>
        ${refs ? `<div class="row" style="margin-top:8px"><b>References:</b><br>${refs}</div>` : ""}
      </div></details>`;
  }

  /* ---------- attack paths ---------- */
  function renderPaths() {
    const paths = D.attackPaths || [];
    $("#pathsList").innerHTML = paths.length ? paths.map(p => {
      const chain = (p.steps || []).map((step, i) => {
        const txt = step.replace(/^\[(.*?)\]\s*/, "");
        const via = (step.match(/^\[(.*?)\]/) || [])[1];
        return `${i > 0 ? `<span class="arrow">──${via ? ` ${esc(via)} ` : ""}──▶</span>` : ""}<span class="node">${esc(txt)}</span>`;
      }).join(" ");
      return `<div class="path">
        <span class="pill ${p.severity}">${p.severity}</span>
        <b>&nbsp;${esc(p.start)}</b> can reach <b>${esc(p.target)}</b>
        <span class="tag">${p.length} hop(s)</span>
        <div class="chain">${chain}</div></div>`;
    }).join("") : `<div class="empty">No attack paths to Tier-0 assets discovered 🎉</div>`;
  }

  /* ---------- SP right-sizing ---------- */
  const VERDICT_LABEL = {
    Dormant: "Dormant — no activity", ReadOnly: "Read-only, write granted", UnusedRoles: "Unused role assignments",
    ScopeReduction: "Scope too broad", ReviewGraph: "High-risk Graph perms", ReviewNoLogs: "Review (no usage data)",
    Justified: "Looks justified",
  };
  function renderRightSizing() {
    const data = D.spRightSizing || [];
    const analyzed = data.some(r => r.usage && r.usage.analyzed);
    $("#rsBanner").innerHTML = data.length
      ? `${data.length} service principal(s) analyzed · ` + (analyzed
          ? `usage from last ${(data[0].usage || {}).windowDays || "?"} days of Activity Logs`
          : `<b style="color:var(--high)">config-only</b> — re-run with <code>-AnalyzeUsage</code> to compare against actual log usage`)
      : "No service principals with role assignments or Graph permissions found.";
    const verdicts = [...new Set(data.map(r => r.verdict))];
    $("#rsVerdict").innerHTML = `<option value="">All verdicts</option>` + verdicts.map(v => `<option value="${v}">${VERDICT_LABEL[v] || v}</option>`).join("");
    const draw = () => {
      const q = $("#rsSearch").value.toLowerCase(), v = $("#rsVerdict").value, sort = $("#rsSort").value;
      let list = data.filter(r => (!v || r.verdict === v) &&
        (!q || r.displayName.toLowerCase().includes(q) || JSON.stringify(r).toLowerCase().includes(q)));
      list = list.slice().sort((a, b) => sort === "displayName"
        ? a.displayName.localeCompare(b.displayName) : b.overprivilege - a.overprivilege);
      $("#rsList").innerHTML = list.length ? list.map(rsCard).join("") : `<div class="empty">No matching service principals</div>`;
      wireCopy();
    };
    ["rsSearch", "rsVerdict", "rsSort"].forEach(id => $("#" + id).addEventListener("input", draw));
    draw();
  }
  function opColor(n) { return n >= 85 ? "#ff4d5e" : n >= 70 ? "#ff8a3d" : n >= 50 ? "#ffcc3d" : "#38d39f"; }
  function rsCard(r) {
    const u = r.usage || {};
    const rolesHtml = (r.grantedRoles || []).map(g =>
      `<div class="rrow"><span class="mono">${esc(g.role)}</span>
        <span class="tag">${g.scopeLevel}</span>
        <span class="${g.exercised ? "used" : "unused"}">${u.analyzed ? (g.exercised ? "✓ used" : "✗ unused") : (g.writeCapable ? "write" : "read")}</span></div>`).join("") || "<div class='meta'>none</div>";
    const graphHtml = (r.graphPermissions || []).length
      ? (r.graphPermissions || []).map(g => `<span class="gperm ${g.highRisk ? "risk" : ""}" title="${esc(g.api || "")}">${esc(g.permission)}</span>`).join("")
      : "<div class='meta'>none</div>";
    const usageHtml = u.analyzed
      ? `<div class="rrow"><span class="mono">operations used</span><b>${u.distinctOps || 0}</b> (${u.totalOperations || 0} calls)</div>
         <div class="rrow"><span class="mono">read-only</span>${u.readOnly ? "yes" : "no"}</div>
         <div class="rrow"><span class="mono">last activity</span>${u.lastActivity ? fmtDate(u.lastActivity) : "none"}</div>
         <div class="rrow"><span class="mono">scopes touched</span>${(u.scopesUsed || []).length}</div>`
      : `<div class="meta">No usage data collected. Run with <code>-AnalyzeUsage</code>.</div>`;
    const recs = (r.recommendations || []).map(x => `<li>${esc(x)}</li>`).join("");
    const remed = (r.remediation || []).join("\n");
    return `<details class="rs">
      <summary>
        <div class="opmeter" title="over-privilege ${r.overprivilege}/100"><i style="width:${r.overprivilege}%;background:${opColor(r.overprivilege)}"></i></div>
        <span class="name">${esc(r.displayName)}</span>
        <span class="tag ${r.type}">${r.type}</span>
        <span class="verdict ${r.verdict}">${VERDICT_LABEL[r.verdict] || r.verdict}</span>
      </summary>
      <div class="body">
        <div class="mono" style="margin-bottom:6px">appId ${esc(r.appId)}</div>
        <div class="cols">
          <div class="col"><h4>Granted (config)</h4>${rolesHtml}
            <h4 style="margin-top:12px">Graph app permissions</h4>${graphHtml}</div>
          <div class="col"><h4>Used (logs)</h4>${usageHtml}</div>
        </div>
        ${recs ? `<h4 style="color:var(--text)">Recommendation</h4><ul class="recs">${recs}</ul>` : ""}
        ${remed ? `<h4>Remediation (review before running)</h4>
          <div class="remed"><button class="btn copy" data-copy="${esc(remed).replace(/"/g, "&quot;")}">Copy</button><pre>${esc(remed)}</pre></div>` : ""}
      </div></details>`;
  }
  function wireCopy() {
    $$(".copy").forEach(b => b.addEventListener("click", () => {
      const txt = b.getAttribute("data-copy");
      navigator.clipboard?.writeText(txt).then(() => { b.textContent = "Copied ✓"; setTimeout(() => b.textContent = "Copy", 1500); })
        .catch(() => { b.textContent = "Ctrl+C"; });
    }));
  }

  /* ---------- tables ---------- */
  function makeTable(el, cols, rows) {
    let sortCol = null, sortDir = 1;
    const render = (data) => {
      el.innerHTML = `<thead><tr>${cols.map((c, i) =>
        `<th data-i="${i}">${c.h}${sortCol === i ? (sortDir > 0 ? " ▲" : " ▼") : ""}</th>`).join("")}</tr></thead>
        <tbody>${data.map(r => `<tr>${cols.map(c => `<td>${c.render ? c.render(r) : esc(r[c.k])}</td>`).join("")}</tr>`).join("")}</tbody>`;
      $$("th", el).forEach(th => th.addEventListener("click", () => {
        const i = +th.dataset.i; sortDir = sortCol === i ? -sortDir : 1; sortCol = i;
        const k = cols[i].k;
        data.sort((a, b) => String(a[k] ?? "").localeCompare(String(b[k] ?? ""), undefined, { numeric: true }) * sortDir);
        render(data);
      }));
    };
    return { render };
  }

  function renderIdentities() {
    const t = makeTable($("#identTable"), [
      { h: "Name", k: "label" },
      { h: "Type", k: "type", render: r => `<span class="tag ${r.type}">${r.type}</span>` },
      { h: "UPN / App ID", k: "sub", render: r => `<span class="mono">${esc(r.data?.upn || r.data?.appId || "")}</span>` },
      { h: "Enabled", k: "enabled", render: r => r.data?.enabled === false ? "❌" : (r.data?.enabled === true ? "✓" : "–") },
      { h: "Tier-0", k: "tier0", render: r => r.tier0 ? `<span class="pill Critical">T0</span>` : "" },
      { h: "Secrets", k: "secrets", render: r => (r.data?.passwordCreds || 0) + (r.data?.keyCreds || 0) || "" },
    ], []);
    const all = (D.identities || []);
    const draw = () => {
      const q = $("#identSearch").value.toLowerCase(), ty = $("#identType").value;
      t.render(all.filter(r => (!ty || r.type === ty) && (!q || (r.label || "").toLowerCase().includes(q) || JSON.stringify(r.data || {}).toLowerCase().includes(q))));
    };
    $("#identSearch").addEventListener("input", draw); $("#identType").addEventListener("change", draw);
    draw();
  }

  function renderRoles() {
    const scopes = [...new Set((D.roleAssignments || []).map(scopeLevel))].sort();
    $("#roleScope").innerHTML = `<option value="">All scope levels</option>` + scopes.map(s => `<option>${esc(s)}</option>`).join("");
    const t = makeTable($("#roleTable"), [
      { h: "Principal", k: "principalName" },
      { h: "Type", k: "principalType", render: r => `<span class="tag ${r.principalType}">${esc(r.principalType)}</span>` },
      { h: "Role", k: "role", render: r => privileged(r.role) ? `<b style="color:var(--high)">${esc(r.role)}</b>` : esc(r.role) },
      { h: "Scope level", k: "scope", render: r => scopeLevel(r) },
      { h: "Scope", k: "scope", render: r => `<span class="mono">${esc(r.scope)}</span>` },
    ], []);
    const all = (D.roleAssignments || []);
    const draw = () => {
      const q = $("#roleSearch").value.toLowerCase(), sc = $("#roleScope").value;
      t.render(all.filter(r => (!sc || scopeLevel(r) === sc) && (!q || JSON.stringify(r).toLowerCase().includes(q))));
    };
    $("#roleSearch").addEventListener("input", draw); $("#roleScope").addEventListener("change", draw);
    draw();
  }
  const privileged = (role) => /Owner|User Access Administrator|Contributor|Role Based Access Control/i.test(role || "");
  function scopeLevel(r) {
    const s = r.scope || "";
    if (/\/managementGroups\//.test(s)) return "ManagementGroup";
    if (/^\/subscriptions\/[^/]+$/.test(s)) return "Subscription";
    if (/\/resourceGroups\/[^/]+$/.test(s)) return "ResourceGroup";
    if (/\/providers\/.+\/.+/.test(s)) return "Resource";
    if (s === "/") return "Root";
    return "Other";
  }

  function renderDirRoles() {
    const rows = (D.directoryRoles || []).slice().sort((a, b) => b.memberCount - a.memberCount);
    $("#dirTable").innerHTML = `<thead><tr><th>Directory Role</th><th>Members</th><th>Who</th></tr></thead><tbody>${
      rows.map(r => `<tr><td><b>${esc(r.roleName)}</b></td><td>${r.memberCount}</td>
        <td>${(r.members || []).map(m => `<span class="tag">${esc(m)}</span>`).join(" ")}</td></tr>`).join("")
      || `<tr><td colspan="3" class="empty">No directory role data (run without -SkipGraph)</td></tr>`}</tbody>`;
  }

  function renderResources() {
    const types = [...new Set((D.resources || []).map(r => r.type))].sort();
    $("#resType").innerHTML = `<option value="">All types</option>` + types.map(t => `<option>${esc(t)}</option>`).join("");
    const t = makeTable($("#resTable"), [
      { h: "Name", k: "name" }, { h: "Type", k: "type", render: r => `<span class="mono">${esc(r.type)}</span>` },
      { h: "Resource Group", k: "resourceGroup" }, { h: "Location", k: "location" },
    ], []);
    const all = (D.resources || []);
    const draw = () => {
      const q = $("#resSearch").value.toLowerCase(), ty = $("#resType").value;
      t.render(all.filter(r => (!ty || r.type === ty) && (!q || JSON.stringify(r).toLowerCase().includes(q))));
    };
    $("#resSearch").addEventListener("input", draw); $("#resType").addEventListener("change", draw);
    draw();
  }

  /* ---------- graph ---------- */
  let cy = null;
  function renderGraph() {
    if (typeof cytoscape === "undefined") { $("#cy").innerHTML = `<div class="empty">Graph library unavailable (offline). Attack paths tab still works.</div>`; return; }
    const onlyRisk = $("#onlyRisk").checked;
    const g = D.graph || { nodes: [], edges: [] };
    let nodes = g.nodes, edges = g.edges;
    if (onlyRisk) {
      const keep = new Set();
      (g.edges || []).forEach(e => { if (["CanControl", "CanEscalate", "MemberOf", "HasDirectoryRole"].includes(e.type)) { keep.add(e.source); keep.add(e.target); } });
      g.nodes.forEach(n => { if (n.tier0) keep.add(n.id); });
      nodes = g.nodes.filter(n => keep.has(n.id));
      edges = g.edges.filter(e => keep.has(e.source) && keep.has(e.target));
    }
    const elements = [
      ...nodes.map(n => ({ data: { id: n.id, label: n.label, type: n.type, tier0: n.tier0 } })),
      ...edges.filter(e => nodes.find(n => n.id === e.source) && nodes.find(n => n.id === e.target))
        .map(e => ({ data: { id: e.id, source: e.source, target: e.target, label: e.label, type: e.type } })),
    ];
    $("#graphInfo").textContent = `${nodes.length} nodes · ${elements.length - nodes.length} edges`;
    $("#graphLegend").innerHTML = Object.keys(TYPECOLOR).map(t =>
      `<span><span class="dot" style="background:${TYPECOLOR[t]}"></span>${t}</span>`).join("");

    if (cy) cy.destroy();
    cy = cytoscape({
      container: $("#cy"),
      elements,
      style: [
        { selector: "node", style: {
          "background-color": ele => TYPECOLOR[ele.data("type")] || "#5f6b85",
          "label": "data(label)", "color": "#e6e9f0", "font-size": 9, "text-wrap": "ellipsis",
          "text-max-width": 90, "width": 18, "height": 18, "border-width": 0 } },
        { selector: "node[?tier0]", style: { "border-width": 3, "border-color": "#ff4d5e", "width": 26, "height": 26 } },
        { selector: "edge", style: {
          "width": 1, "line-color": "#2a3550", "target-arrow-color": "#2a3550",
          "target-arrow-shape": "triangle", "curve-style": "bezier", "font-size": 7,
          "color": "#8c97b0", "label": "data(label)", "text-rotation": "autorotate" } },
        { selector: "edge[type='CanControl'],edge[type='CanEscalate']", style: { "line-color": "#ff4d5e", "target-arrow-color": "#ff4d5e", "width": 2, "line-style": "dashed" } },
        { selector: "edge[type='HasDirectoryRole']", style: { "line-color": "#ff6b9d", "target-arrow-color": "#ff6b9d" } },
      ],
      layout: layoutOpts($("#graphLayout").value),
    });
    cy.on("tap", "node", (e) => {
      const d = e.target.data();
      alert(`${d.label}\nType: ${d.type}${d.tier0 ? "\n⚠ TIER-0 ASSET" : ""}`);
    });
  }
  function layoutOpts(name) {
    if (name === "concentric") return { name: "concentric", concentric: n => n.data("tier0") ? 10 : 1, levelWidth: () => 2, minNodeSpacing: 20 };
    if (name === "breadthfirst") return { name: "breadthfirst", directed: true, spacingFactor: 1.1 };
    return { name: "cose", animate: false, nodeRepulsion: 6000, idealEdgeLength: 60 };
  }

  /* ---------- counts ---------- */
  function initCounts() {
    $("#cntFindings").textContent = (D.findings || []).length;
    $("#cntPaths").textContent = (D.attackPaths || []).length;
    $("#cntIdent").textContent = (D.identities || []).length;
    $("#cntRoles").textContent = (D.roleAssignments || []).length;
    $("#cntRes").textContent = (D.resources || []).length;
    $("#cntRS").textContent = (D.spRightSizing || []).filter(r => r.verdict !== "Justified").length;
  }

  /* ---------- self-contained HTML report download ---------- */
  function buildReport() {
    const m = D.meta || {}, s = D.stats || {};
    const counts = SEV.map(sv => (D.findings || []).filter(f => f.severity === sv).length);
    const total = counts.reduce((a, b) => a + b, 0) || 1;
    const sevBar = SEV.map((sv, i) => `<i style="display:inline-block;height:14px;width:${(counts[i]/total)*100}%;background:${SEVCOLOR[sv]}"></i>`).join("");
    const statCards = Object.entries({
      "Risk score": `${m.riskScore}/100`, Critical: s.critical, High: s.high, "Attack paths": s.attackPaths,
      "Tier-0 assets": s.tier0Nodes, Users: s.users, "Service principals": s.servicePrincipals,
      "Role assignments": s.roleAssignments, Resources: s.resources, Subscriptions: s.subscriptions,
    }).map(([k, v]) => `<div class="rc"><div class="rn">${v ?? 0}</div><div class="rl">${k}</div></div>`).join("");

    const findings = (D.findings || []).map(f => `
      <div class="rf ${f.severity}">
        <div class="rfh"><span class="rp ${f.severity}">${f.severity}</span> <b>${esc(f.title)}</b> <span class="rt">${esc(f.category)}</span></div>
        <p>${esc(f.description)}</p>
        <p><b>Principal:</b> ${esc(f.principal)} (${esc(f.principalType)})${f.evidence ? ` &middot; <b>Evidence:</b> <code>${esc(f.evidence)}</code>` : ""}</p>
        <p class="rr"><b>→ ${esc(f.recommendation)}</b></p>
        ${(f.references || []).length ? `<p class="rref">${f.references.map(r => esc(r)).join("<br>")}</p>` : ""}
      </div>`).join("") || "<p>No findings.</p>";

    const paths = (D.attackPaths || []).map(p =>
      `<div class="rpath"><span class="rp ${p.severity}">${p.severity}</span> <b>${esc(p.start)}</b> → <b>${esc(p.target)}</b> (${p.length} hop)
        <div class="rchain">${(p.steps || []).map(st => esc(st.replace(/^\[.*?\]\s*/, ""))).join(" &nbsp;▶&nbsp; ")}</div></div>`).join("") || "<p>None.</p>";

    const rsRows = (D.spRightSizing || []).filter(r => r.verdict !== "Justified").map(r => {
      const remed = (r.remediation || []).filter(x => !x.startsWith("#")).join("\n");
      return `<tr><td><b>${esc(r.displayName)}</b><br><code>${esc(r.appId)}</code></td>
        <td>${r.overprivilege}</td><td>${VERDICT_LABEL[r.verdict] || r.verdict}</td>
        <td>${(r.grantedRoles || []).map(g => esc(g.role) + " @ " + g.scopeLevel).join("<br>") || "—"}</td>
        <td>${(r.recommendations || []).map(esc).join("<br>")}${remed ? `<pre style="background:#f0f2f8;padding:6px;border-radius:5px;margin-top:5px;white-space:pre-wrap">${esc(remed)}</pre>` : ""}</td></tr>`;
    }).join("");

    const dirRoles = (D.directoryRoles || []).filter(r => r.memberCount).map(r =>
      `<tr><td><b>${esc(r.roleName)}</b></td><td>${r.memberCount}</td><td>${(r.members || []).map(esc).join(", ")}</td></tr>`).join("");

    const privRoles = (D.roleAssignments || []).filter(r => privileged(r.role)).map(r =>
      `<tr><td>${esc(r.principalName)}</td><td>${esc(r.principalType)}</td><td><b>${esc(r.role)}</b></td><td>${scopeLevel(r)}</td><td><code>${esc(r.scope)}</code></td></tr>`).join("");

    return `<!doctype html><html><head><meta charset="utf-8"><title>AzIAM Report — ${esc(m.tenantId)}</title>
<style>
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:960px;margin:0 auto;padding:30px;color:#1a1f2e;background:#fff}
h1{margin:0 0 4px}h2{border-bottom:2px solid #eee;padding-bottom:6px;margin-top:34px}
.sub{color:#667;font-size:13px}.rc{display:inline-block;width:150px;padding:12px;margin:4px;background:#f6f8fc;border:1px solid #e3e8f3;border-radius:10px;vertical-align:top}
.rn{font-size:24px;font-weight:700}.rl{font-size:11px;color:#667;text-transform:uppercase}
.rf{border-left:4px solid #ccc;padding:8px 14px;margin:10px 0;background:#fafbfe;border-radius:0 8px 8px 0}
.rf.Critical{border-color:#ff4d5e}.rf.High{border-color:#ff8a3d}.rf.Medium{border-color:#ffcc3d}.rf.Low{border-color:#4fd0ff}
.rfh{font-size:15px}.rf p{margin:5px 0;font-size:13px;color:#445}.rr{color:#1a1f2e}
.rref{color:#88f;font-size:11px;word-break:break-all}
.rp{display:inline-block;padding:1px 8px;border-radius:12px;font-size:11px;font-weight:700;color:#fff}
.rp.Critical{background:#ff4d5e}.rp.High{background:#ff8a3d}.rp.Medium{background:#e0b020}.rp.Low{background:#3aa0c0}
.rt{background:#eef;border-radius:6px;padding:1px 7px;font-size:11px;color:#558}
.rpath{background:#fafbfe;border:1px solid #eee;border-radius:8px;padding:10px;margin:8px 0;font-size:13px}
.rchain{margin-top:6px;color:#558;font-size:12px}
table{width:100%;border-collapse:collapse;font-size:12px;margin-top:10px}td,th{border:1px solid #e3e8f3;padding:6px 9px;text-align:left}th{background:#f6f8fc}
code{background:#f0f2f8;padding:1px 4px;border-radius:4px;font-size:11px;word-break:break-all}
@media print{.rf{break-inside:avoid}}
</style></head><body>
<h1>Azure IAM Security Assessment</h1>
<div class="sub">Tenant <b>${esc(m.tenantId)}</b> &middot; ${(m.subscriptions || []).map(x => esc(x.name)).join(", ")} &middot; generated ${fmtDate(m.generatedAt)} &middot; ${esc(m.tool)} v${esc(m.version)}</div>
<h2>Summary</h2><div>${statCards}</div>
<div style="display:flex;margin-top:14px;border-radius:7px;overflow:hidden">${sevBar}</div>
<h2>Findings (${(D.findings || []).length})</h2>${findings}
<h2>Attack Paths (${(D.attackPaths || []).length})</h2>${paths}
<h2>SP Right-Sizing (${(D.spRightSizing || []).filter(r => r.verdict !== "Justified").length})</h2>
<table><tr><th>Service Principal</th><th>Over-priv</th><th>Verdict</th><th>Granted</th><th>Recommendation &amp; remediation</th></tr>${rsRows || "<tr><td colspan=5>Nothing to right-size (or run with -AnalyzeUsage)</td></tr>"}</table>
<h2>Privileged Azure Role Assignments</h2><table><tr><th>Principal</th><th>Type</th><th>Role</th><th>Scope level</th><th>Scope</th></tr>${privRoles || "<tr><td colspan=5>None</td></tr>"}</table>
<h2>Entra Directory Roles</h2><table><tr><th>Role</th><th>#</th><th>Members</th></tr>${dirRoles || "<tr><td colspan=3>No data</td></tr>"}</table>
<p style="margin-top:40px;color:#99a;font-size:11px">Generated by AzIAM Assessor — defensive IAM assessment. Review with your security team.</p>
</body></html>`;
  }
  function initReportButton() {
    $("#btnReport").addEventListener("click", () => {
      const html = buildReport();
      const blob = new Blob([html], { type: "text/html" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `AzIAM-Report-${(D.meta.tenantId || "tenant").slice(0, 8)}-${new Date().toISOString().slice(0, 10)}.html`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    });
  }

  /* ---------- boot ---------- */
  document.addEventListener("DOMContentLoaded", () => {
    initHeader(); initTabs(); initCounts();
    renderOverview(); renderFindings(); renderPaths();
    renderIdentities(); renderRoles(); renderDirRoles(); renderResources();
    renderRightSizing();
    initReportButton();
  });
})();
