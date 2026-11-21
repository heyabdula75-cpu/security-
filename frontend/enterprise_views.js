/**
 * SecureChain Enterprise Visual & UX Modules (Option B):
 * - Interactive SVG Dependency Graph Explorer
 * - VEX & Python/JS AST Reachability Workbench
 * - AI Security Copilot & Deep AI-BOM / Pickle Scanner
 * - Cryptographic Signing, Auto-Fix Patch Diffs, Audit Evidence Bundle, Real API Keys & Webhooks
 */
'use strict';

window.EnterpriseUI = {
  /* ── API Helpers ───────────────────────────── */
  api: {
    syncLiveIntel: () => API.post('/intel/sync', {}),
    askCopilot: (question) => API.post('/assistant/query', { question }),
    scanAiBom: (payload) => API.post('/ai-bom/scan', payload),
    listApiKeys: () => API.get('/auth/api-keys'),
    createApiKey: (name, scopes) => API.post('/auth/api-keys', { name, scopes }),
    revokeApiKey: (id) => API.delete(`/auth/api-keys/${id}`),
    listWebhooks: () => API.get('/webhooks'),
    createWebhook: (name, url) => API.post('/webhooks', { name, url }),
    deleteWebhook: (id) => API.delete(`/webhooks/${id}`),
    signSbom: (id) => API.post(`/sboms/${id}/sign`, { slsa_level: 'SLSA_BUILD_L2' }),
    verifySbom: (id) => API.post(`/sboms/${id}/verify`, {}),
    autofixSbom: (id) => API.get(`/sboms/${id}/autofix`),
    auditBundle: (id) => API.get(`/sboms/${id}/audit-bundle`),
    listComponents: (sbomId) => API.get(`/components?sbom_id=${sbomId}&limit=100`),
    runReachability: (sbomId, files, autoVex) => API.post(`/sboms/${sbomId}/reachability`, { files, auto_generate_vex: autoVex }),
    listVex: (sbomId) => API.get(sbomId ? `/vex?sbom_id=${sbomId}` : '/vex'),
    exportVex: (sbomId, fmt) => API.get(`/sboms/${sbomId}/vex/export?format=${fmt}`),
  },

  /* ── Live Real-Time Threat Intel Sync ──────── */
  async syncLiveIntel() {
    Toast.info('Syncing live CISA KEV & threat intelligence feeds…');
    try {
      const res = await this.api.syncLiveIntel();
      const d = res.data;
      Toast.success(`Live Intel Synced (${d.source}): ${d.total_kev_cves} CISA KEV CVEs loaded!`);
    } catch (e) {
      Toast.error('Intel sync failed: ' + e.message);
    }
  },

  /* ── Interactive Dependency Graph Explorer ── */
  async loadGraph() {
    const sel = $('graph-sbom-select');
    const sboms = State.data.sboms.length ? State.data.sboms : ((await API.listSboms())?.data ?? []);
    State.data.sboms = sboms;
    if (sel) {
      sel.innerHTML = sboms.length
        ? sboms.map(s => `<option value="${s.id}">${s.format} v${s.version ?? '1.0'} (${s.component_count ?? 0} comps, risk ${s.risk_score ?? 0})</option>`).join('')
        : '<option value="">Upload an SBOM first</option>';
    }
    if (sboms.length) await this.renderGraph(sboms[0].id);
  },

  async renderGraph(sbomId) {
    const canvas = $('dep-graph-canvas');
    const inspector = $('dep-graph-inspector');
    if (!canvas || !sbomId) return;
    canvas.innerHTML = '<div class="empty-state"><div class="spinner spinner-lg"></div><div class="empty-title">Building dependency graph…</div></div>';

    try {
      const [compRes, threatRes] = await Promise.allSettled([
        this.api.listComponents(sbomId),
        API.listThreats(),
      ]);
      const comps = compRes.value?.data ?? [];
      const threats = (threatRes.value?.data ?? []).filter(t => t.sbom_id === sbomId);
      const threatByComp = {};
      threats.forEach(t => { if (t.component_name) threatByComp[t.component_name] = t; });

      if (!comps.length) {
        canvas.innerHTML = '<div class="empty-state"><div class="empty-icon">🕸️</div><div class="empty-title">No components in this SBOM</div></div>';
        return;
      }

      const w = 780, h = 420, cx = w / 2, cy = h / 2, radius = Math.min(w, h) * 0.36;
      const nodes = comps.slice(0, 28);
      let edgesSvg = '';
      let nodesSvg = '';

      nodes.forEach((c, idx) => {
        const angle = (2 * Math.PI * idx) / nodes.length - Math.PI / 2;
        const x = Math.round(cx + radius * Math.cos(angle));
        const y = Math.round(cy + radius * Math.sin(angle));
        const hasThreat = Boolean(threatByComp[c.name]);
        const isAi = (c.type || '').includes('model');
        const fill = hasThreat ? '#f43f5e' : isAi ? '#a855f7' : '#06b6d4';

        edgesSvg += `<line x1="${cx}" y1="${cy}" x2="${x}" y2="${y}" stroke="${hasThreat ? '#f43f5e88' : '#334155'}" stroke-width="${hasThreat ? 2.2 : 1.3}" />`;
        const safeJson = encodeURIComponent(JSON.stringify({ ...c, threat: threatByComp[c.name] || null }));
        nodesSvg += `
          <g style="cursor:pointer;" onclick="EnterpriseUI.inspectNode('${safeJson}')">
            <circle cx="${x}" cy="${y}" r="${hasThreat ? 16 : 12}" fill="${fill}" fill-opacity="0.22" stroke="${fill}" stroke-width="2" />
            <text x="${x}" y="${y + 26}" text-anchor="middle" fill="#cbd5e1" font-size="10" font-family="JetBrains Mono, monospace">${c.name.slice(0, 16)}</text>
          </g>`;
      });

      canvas.innerHTML = `
        <svg viewBox="0 0 ${w} ${h}" style="width:100%; height:420px; background:rgba(10,15,26,0.55); border-radius:12px; border:1px solid rgba(255,255,255,0.06);">
          ${edgesSvg}
          <g>
            <circle cx="${cx}" cy="${cy}" r="28" fill="#6366f1" fill-opacity="0.25" stroke="#818cf8" stroke-width="2.5" />
            <text x="${cx}" y="${cy + 4}" text-anchor="middle" fill="#f8fafc" font-size="11" font-weight="700">SBOM ROOT</text>
          </g>
          ${nodesSvg}
        </svg>`;
      if (inspector) {
        inspector.innerHTML = `<p class="text-muted text-sm">Click any node (${nodes.length} rendered) to inspect PURL, license, version, and active threats. <span style="color:#f43f5e;">● Threat</span> · <span style="color:#a855f7;">● AI/ML Model</span> · <span style="color:#06b6d4;">● Library</span></p>`;
      }
    } catch (e) {
      canvas.innerHTML = `<div class="empty-state"><div class="empty-title">Error: ${e.message}</div></div>`;
    }
  },

  inspectNode(encoded) {
    const c = JSON.parse(decodeURIComponent(encoded));
    const el = $('dep-graph-inspector');
    if (!el) return;
    el.innerHTML = `
      <div class="text-sm">
        <strong>${c.name}</strong> <span class="badge badge-info">${c.version || '0.0.0'}</span>
        <span class="badge badge-ok">${c.type || 'library'}</span>
        <div class="font-mono text-xs text-muted mt-1">PURL: ${c.purl || '—'} · License: ${c.license || 'Undeclared'}</div>
        ${c.threat ? `<div class="mt-1 text-rose text-xs">⚠️ <strong>${c.threat.threat_type}:</strong> ${c.threat.summary}</div>` : '<div class="mt-1 text-emerald text-xs">✅ No active supply-chain threats on this node.</div>'}
      </div>`;
  },

  /* ── VEX & AST Reachability Workbench ──────── */
  async loadVexWorkbench() {
    const sel = $('vex-sbom-select');
    const sboms = State.data.sboms.length ? State.data.sboms : ((await API.listSboms())?.data ?? []);
    State.data.sboms = sboms;
    if (sel) {
      sel.innerHTML = sboms.length
        ? sboms.map(s => `<option value="${s.id}">${s.format} v${s.version ?? '1.0'} (${s.vulnerability_count ?? 0} vulns)</option>`).join('')
        : '<option value="">Upload an SBOM first</option>';
    }
    await this.refreshVexList();
  },

  async runReachability() {
    const sbomId = $('vex-sbom-select')?.value;
    const filename = $('reach-filename')?.value || 'app.py';
    const code = $('reach-code')?.value || '';
    const autoVex = $('reach-autovex')?.checked ?? true;
    const out = $('reach-output');
    if (!sbomId) { Toast.error('Select an SBOM first.'); return; }
    try {
      const res = await this.api.runReachability(sbomId, { [filename]: code }, autoVex);
      const d = res.data;
      out.innerHTML = `
        <div class="mb-2 text-sm">
          <strong>Reachability Result:</strong>
          <span class="badge badge-critical">${d.reachable_count} Reachable</span>
          <span class="badge badge-ok">${d.unreachable_count} Unreachable</span>
          <span class="badge badge-info">${d.noise_reduction_percent}% Noise Reduction</span>
        </div>
        ${d.results.length ? `<div class="table-wrap"><table><thead><tr><th>CVE</th><th>Package</th><th>Status</th><th>Evidence</th></tr></thead><tbody>
          ${d.results.map(r => `<tr><td class="font-mono text-xs">${r.cve_id}</td><td class="font-mono">${r.component_name}</td><td><span class="badge badge-${r.reachability==='reachable'?'critical':'ok'}">${r.reachability.toUpperCase()}</span></td><td class="text-xs text-muted">${r.reason}</td></tr>`).join('')}
        </tbody></table></div>` : '<p class="text-muted text-sm">No vulnerabilities in this SBOM to trace.</p>'}`;
      Toast.success(`AST Reachability complete (${d.noise_reduction_percent}% noise reduced)`);
      this.refreshVexList();
    } catch (e) { Toast.error(e.message); }
  },

  async refreshVexList() {
    const sbomId = $('vex-sbom-select')?.value || null;
    const box = $('vex-statements-list');
    if (!box) return;
    try {
      const res = await this.api.listVex(sbomId);
      const items = res.data ?? [];
      if (!items.length) {
        box.innerHTML = '<div class="empty-state"><div class="empty-title">No VEX attestations yet</div><div class="empty-sub">Run AST Reachability with Auto-VEX enabled to generate OpenVEX attestations.</div></div>';
        return;
      }
      box.innerHTML = `<div class="table-wrap"><table><thead><tr><th>CVE</th><th>Component</th><th>VEX Status</th><th>Justification</th></tr></thead><tbody>
        ${items.map(v => `<tr><td class="font-mono text-xs">${v.cve_id}</td><td class="font-mono">${v.component_name || '—'}</td><td><span class="badge badge-${v.status==='not_affected'?'ok':'critical'}">${v.status}</span></td><td class="text-xs text-muted">${v.justification || v.impact_statement || '—'}</td></tr>`).join('')}
      </tbody></table></div>`;
    } catch {}
  },

  async exportVexDoc(format) {
    const sbomId = $('vex-sbom-select')?.value;
    if (!sbomId) { Toast.warn('Select an SBOM first.'); return; }
    try {
      const res = await this.api.exportVex(sbomId, format);
      this._downloadJson(res.data, `vex-${sbomId.slice(0, 8)}-${format}.json`);
      Toast.success(`Exported ${format.toUpperCase()} VEX`);
    } catch (e) { Toast.error(e.message); }
  },

  /* ── AI Security Copilot & Deep AI-BOM ─────── */
  async askCopilot(preset) {
    const input = $('copilot-input');
    const question = preset || input?.value?.trim();
    if (!question) return;
    if (input && !preset) input.value = '';
    const log = $('copilot-messages');
    log.innerHTML += `<div class="mb-2"><span class="badge badge-info">YOU</span> <span class="text-sm">${question}</span></div>`;
    try {
      const res = await this.api.askCopilot(question);
      const d = res.data;
      const htmlAns = (d.answer || '').replace(/\n/g, '<br/>').replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
      log.innerHTML += `<div class="card mb-2" style="padding:0.85rem; background:rgba(6,182,212,0.06);"><span class="badge badge-ok">COPILOT</span><div class="text-sm mt-1">${htmlAns}</div></div>`;
      log.scrollTop = log.scrollHeight;
    } catch (e) { Toast.error(e.message); }
  },

  async scanAiBom() {
    const filename = $('aibom-filename')?.value || 'load_model.py';
    const content = $('aibom-content')?.value || '';
    const out = $('aibom-output');
    if (!content.trim()) { Toast.warn('Paste HuggingFace config.json, Modelfile, or Python ML loader code.'); return; }
    try {
      const res = await this.api.scanAiBom({ filename, content_text: content });
      const d = res.data;
      out.innerHTML = `
        <div class="text-sm mb-1"><strong>AI-BOM Scan (${d.filename}):</strong> <span class="badge badge-${d.risk_level==='low'?'ok':d.risk_level}">${d.risk_level.toUpperCase()}</span> (${d.findings_count} finding(s))</div>
        ${d.findings.map(f => `<div class="text-xs text-rose mt-1">🚨 <strong>${f.rule_id}:</strong> ${f.summary}</div>`).join('') || '<div class="text-xs text-emerald">✅ No unsafe model loading or remote code patterns found.</div>'}`;
    } catch (e) { Toast.error(e.message); }
  },

  /* ── Signing, Auto-Fix & Audit Bundle ──────── */
  async signAndVerify(sbomId) {
    const out = $('sbom-inspect-output');
    try {
      const sigRes = await this.api.signSbom(sbomId);
      const verRes = await this.api.verifySbom(sbomId);
      out.style.display = 'block';
      out.innerHTML = `<div class="text-sm"><strong>🔐 Signed (${sigRes.data.slsa_level}):</strong> <span class="badge badge-ok">${verRes.data.verified ? 'VERIFIED' : 'TAMPERED'}</span> <span class="font-mono text-xs text-muted">SHA256: ${sigRes.data.payload_sha256.slice(0, 20)}…</span></div>`;
      Toast.success('SBOM signed with SLSA provenance & verified!');
    } catch (e) { Toast.error(e.message); }
  },

  async showAutofix(sbomId) {
    const out = $('sbom-inspect-output');
    try {
      const res = await this.api.autofixSbom(sbomId);
      const d = res.data;
      out.style.display = 'block';
      if (!d.patch_count) {
        out.innerHTML = '<div class="text-sm text-emerald">✅ No vulnerable dependencies requiring automated patch diffs.</div>';
        return;
      }
      out.innerHTML = `<div class="text-sm mb-1"><strong>🔧 Auto-Fix (${d.patch_count} patch(es)) — ${d.pull_request.title}</strong></div>` +
        d.patches.map(p => `<pre class="font-mono text-xs" style="background:#0a0f1a;padding:.5rem;border-radius:6px;margin-top:.35rem;"># ${p.target_manifest} (${p.cve_id})\n${p.unified_diff}</pre>`).join('');
    } catch (e) { Toast.error(e.message); }
  },

  async downloadAuditBundle(sbomId) {
    try {
      const res = await this.api.auditBundle(sbomId);
      this._downloadJson(res.data, `securechain-audit-bundle-${sbomId.slice(0, 8)}.json`);
      Toast.success('Downloaded Signed Regulatory Audit Evidence Bundle!');
    } catch (e) { Toast.error(e.message); }
  },

  /* ── Real API Keys & Webhooks (Settings) ───── */
  async loadEnterpriseSettings() {
    const keyBox = $('api-keys-list');
    const hookBox = $('webhooks-list');
    try {
      const [kRes, hRes] = await Promise.allSettled([this.api.listApiKeys(), this.api.listWebhooks()]);
      const keys = kRes.value?.data ?? [];
      const hooks = hRes.value?.data ?? [];
      if (keyBox) {
        keyBox.innerHTML = keys.length
          ? keys.map(k => `<div class="flex items-center gap-1 mb-1 text-xs"><span class="font-mono">${k.key_prefix}…</span> <strong>${k.name}</strong> <span class="badge badge-${k.is_active?'ok':'medium'}">${k.is_active?'Active':'Revoked'}</span> ${k.is_active?`<button class="btn btn-secondary" style="font-size:.65rem;padding:.15rem .4rem;margin-left:auto;" onclick="EnterpriseUI.revokeKey('${k.id}')">Revoke</button>`:''}</div>`).join('')
          : '<p class="text-muted text-xs">No scoped API keys yet.</p>';
      }
      if (hookBox) {
        hookBox.innerHTML = hooks.length
          ? hooks.map(h => `<div class="flex items-center gap-1 mb-1 text-xs"><strong>${h.name}</strong> <span class="font-mono text-muted truncate">${h.url}</span> <button class="btn btn-secondary" style="font-size:.65rem;padding:.15rem .4rem;margin-left:auto;" onclick="EnterpriseUI.deleteWebhook('${h.id}')">Delete</button></div>`).join('')
          : '<p class="text-muted text-xs">No webhooks configured.</p>';
      }
    } catch {}
  },

  async createRealApiKey() {
    const name = $('new-key-name')?.value?.trim() || 'CI/CD Pipeline Key';
    try {
      const res = await this.api.createApiKey(name, ['sbom:read', 'scan:write', 'compliance:read']);
      $('api-key-display').value = res.data.api_key;
      Toast.success('Scoped API key created! Copy it now — shown once.');
      this.loadEnterpriseSettings();
    } catch (e) { Toast.error(e.message); }
  },

  async revokeKey(id) {
    try { await this.api.revokeApiKey(id); Toast.info('API key revoked'); this.loadEnterpriseSettings(); }
    catch (e) { Toast.error(e.message); }
  },

  async addWebhook() {
    const name = $('webhook-name')?.value?.trim() || 'Slack Alert';
    const url = $('webhook-url')?.value?.trim();
    if (!url) { Toast.warn('Enter a webhook URL'); return; }
    try {
      await this.api.createWebhook(name, url);
      Toast.success('HMAC-signed webhook registered!');
      $('webhook-url').value = '';
      this.loadEnterpriseSettings();
    } catch (e) { Toast.error(e.message); }
  },

  async deleteWebhook(id) {
    try { await this.api.deleteWebhook(id); Toast.info('Webhook deleted'); this.loadEnterpriseSettings(); }
    catch (e) { Toast.error(e.message); }
  },

  _downloadJson(data, filename) {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  },
};
