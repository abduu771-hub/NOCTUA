/* ============================================================
   SIEM-AI — Utilities
   Pure helper functions. No DOM manipulation here.
   ============================================================ */

const SIEM_UTILS = {

  /* --- Time ------------------------------------------------ */
  timeAgo(isoString) {
    if (!isoString) return '—';
    const then = new Date(isoString);
    if (isNaN(then)) return '—';
    const diffMs  = Date.now() - then.getTime();
    const diffSec = Math.floor(diffMs  / 1000);
    if (diffSec  < 60)   return `${diffSec}s ago`;
    const diffMin = Math.floor(diffSec  / 60);
    if (diffMin  < 60)   return `${diffMin} min ago`;
    const diffH   = Math.floor(diffMin  / 60);
    if (diffH    < 24)   return `${diffH}h ago`;
    const diffD   = Math.floor(diffH    / 24);
    if (diffD    < 30)   return `${diffD}d ago`;
    return this.formatDate(isoString);
  },

  formatDate(isoString) {
    if (!isoString) return '—';
    const d = new Date(isoString);
    if (isNaN(d)) return '—';
    return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' })
      + ' · '
      + d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
  },

  formatDateShort(isoString) {
    if (!isoString) return '—';
    const d = new Date(isoString);
    if (isNaN(d)) return '—';
    return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
  },

  /* --- Severity -------------------------------------------- */
  severityClass(severity) {
    const s = (severity || '').toLowerCase();
    if (s === 'critical') return 'bc';
    if (s === 'high')     return 'bh';
    if (s === 'medium')   return 'bm';
    if (s === 'low')      return 'bl';
    return 'bn';
  },

  severityBadge(severity) {
    const cls = this.severityClass(severity);
    const label = severity
      ? severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase()
      : 'Unknown';
    return `<span class="badge ${cls}">${this.esc(label)}</span>`;
  },

  severityDotClass(severity) {
    const s = (severity || '').toLowerCase();
    if (s === 'critical') return 'crit';
    if (s === 'high')     return 'high';
    if (s === 'medium')   return 'med';
    if (s === 'low')      return 'low';
    return '';
  },

  /* --- Status ---------------------------------------------- */
  statusPill(status) {
    const s = (status || '').toLowerCase();
    const dot = `<span class="status-dot"></span>`;
    if (s === 'open')   return `<span class="status-pill status-open">${dot}Open</span>`;
    if (s === 'closed') return `<span class="status-pill status-closed">Closed</span>`;
    if (s === 'active') return `<span class="status-pill status-active">${dot}Active</span>`;
    if (s === 'stale')  return `<span class="status-pill status-stale">Stale</span>`;
    return `<span class="status-pill status-unknown">${this.esc(status || 'Unknown')}</span>`;
  },

  /* --- Hosts ----------------------------------------------- */
  hostDisplay(host) {
    if (!host) return '—';
    if (typeof host === 'string') return host;
    if (Array.isArray(host)) return host[0] || '—';
    if (typeof host === 'object') {
      if (Array.isArray(host.name)) return host.name[0] || '—';
      return host.name || '—';
    }
    return '—';
  },

  hostsArray(host) {
    if (!host) return [];
    if (typeof host === 'string') return [host];
    if (Array.isArray(host)) return host.filter(Boolean);
    if (typeof host === 'object') {
      if (Array.isArray(host.name)) return host.name.filter(Boolean);
      return host.name ? [host.name] : [];
    }
    return [];
  },

  /* --- Text ------------------------------------------------ */
  truncate(str, n = 80) {
    if (!str) return '';
    const s = String(str);
    return s.length > n ? s.slice(0, n) + '…' : s;
  },

  capitalize(str) {
    if (!str) return '';
    return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
  },

  humanize(str) {
    if (!str) return '';
    return String(str)
      .replace(/[_-]/g, ' ')
      .replace(/\b\w/g, c => c.toUpperCase());
  },

  esc(str) {
    if (str == null) return '';
    return String(str)
      .replace(/&/g,  '&amp;')
      .replace(/</g,  '&lt;')
      .replace(/>/g,  '&gt;')
      .replace(/"/g,  '&quot;');
  },

  /* --- URL Params ------------------------------------------ */
  getParam(name) {
    return new URLSearchParams(window.location.search).get(name);
  },

  /* --- Root path ------------------------------------------- */
  getRoot() {
    return window.location.pathname.includes('/pages/') ? '../' : '';
  },

  /* --- URL builders ---------------------------------------- */
  investigationUrl(id) {
    const r = this.getRoot();
    return `${r}pages/investigation.html?id=${encodeURIComponent(id)}`;
  },

  alertUrl(id) {
    const r = this.getRoot();
    return `${r}pages/alert.html?id=${encodeURIComponent(id)}`;
  },

  sourceUrl(host) {
    const r = this.getRoot();
    return `${r}pages/source.html?host=${encodeURIComponent(host)}`;
  },

  /* --- Object → clean key-value pairs ---------------------- */
  flattenObj(obj, prefix = '', result = {}) {
    if (!obj || typeof obj !== 'object') return result;
    for (const [k, v] of Object.entries(obj)) {
      const key = prefix ? `${prefix}.${k}` : k;
      if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
        this.flattenObj(v, key, result);
      } else {
        result[key] = v;
      }
    }
    return result;
  },

  /* --- Odometer animation ---------------------------------- */
  animateCount(el, endVal, delay = 0, hasSuffix = '') {
    const startVal = 0;
    const duration = 1800;
    function easeOut(t) { return 1 - Math.pow(1 - t, 4); }
    setTimeout(() => {
      let start = null;
      function step(ts) {
        if (!start) start = ts;
        const p   = Math.min((ts - start) / duration, 1);
        const cur = Math.round(startVal + (endVal - startVal) * easeOut(p));
        el.textContent = cur + hasSuffix;
        if (p < 1) requestAnimationFrame(step);
      }
      requestAnimationFrame(step);
    }, delay);
  },

  /* --- Deterministic AI insights from real data ------------ */
  generateInsights(incidents = [], alerts = []) {
    const sevOrder = ['critical', 'high', 'medium', 'low'];

    // Sort incidents
    const openIncs = incidents
      .filter(i => (i.incident?.status || '').toLowerCase() === 'open')
      .sort((a, b) =>
        sevOrder.indexOf((a.incident?.severity || '').toLowerCase()) -
        sevOrder.indexOf((b.incident?.severity || '').toLowerCase())
      );

    const topInc    = openIncs[0];
    const latestInc = incidents[0]; // already sorted by updated_at desc

    /* Card 1 — Latest Assessment */
    let c1;
    if (topInc) {
      const inc  = topInc.incident || {};
      const ctx  = topInc.attack_context || {};
      const sev  = this.capitalize(inc.severity || 'unknown');
      const hosts = this.hostsArray(topInc.host).length;
      const users = (ctx.users_seen || []).length;
      const title = inc.title || inc.name || this.humanize(inc.incident_type) || 'Active incident';
      c1 = {
        eye: 'Latest Assessment',
        val: title,
        body: `${sev} severity incident detected across ${hosts} host${hosts !== 1 ? 's' : ''}${users > 0 ? `, involving ${users} account${users !== 1 ? 's' : ''}` : ''}. ${inc.description || ''}`.trim(),
        tag: `${sev} severity`
      };
    } else {
      c1 = {
        eye: 'Latest Assessment',
        val: 'No active threats',
        body: 'All monitored systems are currently operating within normal parameters. No open investigations.',
        tag: 'System nominal'
      };
    }

    /* Card 2 — Attack Story */
    let c2;
    if (topInc) {
      const ctx  = topInc.attack_context || {};
      const users = ctx.users_seen  || [];
      const ips   = ctx.source_ips  || [];
      const hosts = this.hostsArray(topInc.host);
      const techs = ctx.techniques  || [];
      const parts = [];
      if (users.length) parts.push(`${users.length} account${users.length > 1 ? 's' : ''} targeted`);
      if (ips.length)   parts.push(`${ips.length} source IP${ips.length > 1 ? 's' : ''} identified`);
      if (hosts.length) parts.push(`${hosts.length} host${hosts.length > 1 ? 's' : ''} affected`);
      c2 = {
        eye: 'Attack Story',
        val: this.humanize(topInc.incident?.incident_type || 'Active campaign'),
        body: parts.length ? parts.join(', ') + '. Attack chain reconstructed from correlated detections.' : 'Attack chain reconstructed from correlated detection events across monitored infrastructure.',
        tag: techs.length ? `${techs.length} technique${techs.length > 1 ? 's' : ''} identified` : 'Pattern confirmed'
      };
    } else {
      c2 = {
        eye: 'Attack Story',
        val: 'No attack chain detected',
        body: 'No correlated attack patterns are currently active across monitored hosts.',
        tag: 'Quiet'
      };
    }

    /* Card 3 — Recommendation */
    const RECS = {
      lateral_movement:    { val: 'Isolate affected hosts',         body: 'Lateral movement detected. Isolate the primary host to contain the blast radius. Rotate service account credentials and enforce MFA on privileged identities before restoring connectivity.' },
      brute_force:         { val: 'Lock targeted accounts',         body: 'Brute force activity detected. Temporarily lock targeted accounts, review authentication logs, and implement rate limiting on authentication endpoints.' },
      privilege_escalation:{ val: 'Audit privilege grants',         body: 'Privilege escalation confirmed. Audit recent permission changes, revoke unnecessary elevated access, and review admin group membership immediately.' },
      data_exfiltration:   { val: 'Block outbound channels',        body: 'Data exfiltration indicators detected. Review and restrict outbound connections on affected hosts. Identify and preserve staged data for forensic analysis.' },
      ransomware:          { val: 'Isolate — preserve for forensics',body: 'Ransomware indicators confirmed. Isolate affected hosts immediately. Preserve memory state — do not power off. Engage incident response.' },
      credential_access:   { val: 'Rotate compromised credentials', body: 'Credential compromise detected. Reset all affected account passwords, invalidate active sessions, and audit credential store integrity.' },
      account_compromise:  { val: 'Reset and verify identity',      body: 'Account compromise confirmed. Reset credentials, revoke all active sessions, and verify recent authentication events from this identity.' },
    };
    let c3;
    if (topInc) {
      const type  = (topInc.incident?.incident_type || '').toLowerCase().replace(/\s+/g,'_');
      const rec   = RECS[type] || { val: 'Investigate and contain', body: 'Review the alert timeline, cross-reference with available telemetry, and apply least-privilege containment to affected resources.' };
      const host  = this.hostDisplay(topInc.host);
      c3 = {
        eye: 'Recommendation',
        val: rec.val,
        body: rec.body + (host && host !== '—' ? ` Primary host: ${host}.` : ''),
        tag: 'Action required'
      };
    } else {
      c3 = { eye: 'Recommendation', val: 'Continue routine monitoring', body: 'No immediate action required. Maintain standard monitoring posture.', tag: 'No action required' };
    }

    /* Card 4 — Latest Investigation */
    let c4;
    if (latestInc) {
      const inc    = latestInc.incident || {};
      const id     = inc.id || latestInc._id?.slice(0, 8).toUpperCase() || 'N/A';
      const status = inc.status || 'unknown';
      const ago    = this.timeAgo(latestInc.updated_at);
      const rules  = (latestInc.related?.rule_ids || []).length;
      c4 = {
        eye: 'Latest Investigation',
        val: inc.title || inc.name || `Case ${id}`,
        body: `Status: ${this.capitalize(status)}. Last updated ${ago}.${rules > 0 ? ` ${rules} detection rule${rules > 1 ? 's' : ''} correlated.` : ''}`,
        tag: status.toLowerCase() === 'open' ? 'Under investigation' : 'Resolved'
      };
    } else {
      c4 = { eye: 'Latest Investigation', val: 'No investigations', body: 'No recent investigations to report.', tag: 'No activity' };
    }

    return [c1, c2, c3, c4];
  }
};
