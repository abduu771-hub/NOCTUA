/* ============================================================
   SIEM-AI — Components
   Generates and injects shared UI: nav, footer, loading,
   empty states, error states. All HTML is produced here
   so it stays in one place and never duplicates across pages.
   ============================================================ */

const SIEM_COMPONENTS = {

  /* --------------------------------------------------------
     Navigation
  -------------------------------------------------------- */
  NAV_LINKS: [
    { id: 'dashboard',       label: 'Mission Control', path: 'index.html',             level: 'root'  },
    { id: 'Incidents',  label: 'Incidents',  path: 'pages/incidents.html', level: 'root'  },
    { id: 'alerts',          label: 'Alerts',          path: 'pages/alerts.html',         level: 'root'  },
    { id: 'analytics',       label: 'Analytics',       path: 'pages/analytics.html',      level: 'root'  },
    { id: 'settings',        label: 'Settings',        path: 'pages/settings.html',       level: 'root'  },
  ],

  injectNav(activePage) {
    const root  = SIEM_UTILS.getRoot();
    const logo  = root + 'assets/images/LOGO_SIEM.png';
    const home  = root + 'index.html';

    const links = this.NAV_LINKS.map(link => {
      const href   = root + link.path;
      const active = link.id === activePage ? ' on' : '';
      return `<a class="nav-a${active}" href="${href}" data-page="${link.id}">${link.label}</a>`;
    }).join('\n    ');

    const html = `
<nav class="nav" role="navigation" aria-label="Main navigation">
  <div class="nav-left">
    <a href="${home}" class="ft-logo-wrap" aria-label="SIEM-AI home">
      <img src="${logo}" alt="SIEM-AI" class="logo-mark">
    </a>
  </div>
  <div class="nav-links" role="list">
    ${links}
  </div>
  <div style="display:flex;align-items:center;gap:16px">
    <div class="avatar" role="button" aria-label="User menu" tabindex="0">SA</div>
  </div>
</nav>`;

    document.body.insertAdjacentHTML('afterbegin', html);
  },

  /* --------------------------------------------------------
     Footer
  -------------------------------------------------------- */
  injectFooter() {
    const root = SIEM_UTILS.getRoot();
    const logo = root + 'assets/images/LOGO_SIEM.png';
    const home = root + 'index.html';

    const html = `
<footer>
  <div class="ft">
    <a href="${home}" class="ft-logo-wrap" aria-label="SIEM-AI home">
      <img src="${logo}" alt="SIEM-AI" style="width:28px;height:28px;object-fit:contain">
    </a>
    <div class="ft-status" id="ft-health">
      <div class="dot"></div>
      Connecting…
    </div>
  </div>
</footer>`;

    document.body.insertAdjacentHTML('beforeend', html);
    this._checkHealth();
  },

  async _checkHealth() {
    const el = document.getElementById('ft-health');
    if (!el) return;
    try {
      const h = await SIEM_API.getHealth();
      if (h.status === 'ok') {
        el.innerHTML = '<div class="dot"></div>All systems operational';
      } else {
        el.innerHTML = '<div class="dot amber"></div>Service degraded';
      }
    } catch {
      el.innerHTML = '<div class="dot red"></div>API unreachable';
    }
  },

  /* --------------------------------------------------------
     Loading skeleton
  -------------------------------------------------------- */
  showLoading(container, rows = 4) {
    const skels = Array.from({ length: rows }, (_, i) => `
      <div class="skeleton-row" style="animation-delay:${i * 60}ms">
        <div class="skeleton" style="width:62px;height:22px;border-radius:5px"></div>
        <div style="flex:1">
          <div class="skeleton" style="width:55%;height:14px;margin-bottom:6px"></div>
          <div class="skeleton" style="width:35%;height:12px;opacity:.6"></div>
        </div>
        <div class="skeleton" style="width:90px;height:14px"></div>
        <div class="skeleton" style="width:68px;height:14px"></div>
      </div>`).join('');
    container.innerHTML = skels;
  },

  /* --------------------------------------------------------
     Empty state
  -------------------------------------------------------- */
  showEmpty(container, title = 'Nothing here', body = '') {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-title">${SIEM_UTILS.esc(title)}</div>
        ${body ? `<div class="empty-state-body">${SIEM_UTILS.esc(body)}</div>` : ''}
      </div>`;
  },

  /* --------------------------------------------------------
     Error state
  -------------------------------------------------------- */
  showError(container, message = 'Unable to load data.') {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-title">Unable to load</div>
        <div class="empty-state-body">${SIEM_UTILS.esc(message)}<br>
          <span style="font-size:11px;opacity:.6">Check that the SIEM-AI API is running on port 8000.</span>
        </div>
      </div>`;
  },

  /* --------------------------------------------------------
     Pagination — "Load more" helper
  -------------------------------------------------------- */
  makeLoadMore(text, onClick) {
    const btn = document.createElement('div');
    btn.className = 'va-wrap';
    btn.innerHTML = `<button class="va-btn" id="load-more-btn">${SIEM_UTILS.esc(text)} →</button>`;
    btn.querySelector('button').addEventListener('click', onClick);
    return btn;
  }
};
