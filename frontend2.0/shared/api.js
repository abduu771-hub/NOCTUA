/* ============================================================
   SIEM-AI — API Client
   Single source of truth for all backend requests.
   Base URL is configurable for different environments.
   ============================================================ */

var API_BASE = 'http://localhost:8000';

var SIEM_API = {
async _get(path) {
    const res = await fetch(`${API_BASE}${path}`);
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`HTTP ${res.status}${text ? ': ' + text : ''}`);
    }
    return res.json();
  },

  /* --- Health -------------------------------------------- */
  getHealth() {
    return this._get('/api/health');
  },

  /* --- Overview ------------------------------------------ */
  getOverview() {
    return this._get('/api/overview');
  },

  /* --- Incidents ----------------------------------------- */
  getIncidents(params = {}) {
    const q = new URLSearchParams();
    if (params.size)          q.set('size',          String(params.size));
    if (params.status)        q.set('status',        params.status);
    if (params.incident_type) q.set('incident_type', params.incident_type);
    if (params.user)          q.set('user',          params.user);
    if (params.host)          q.set('host',          params.host);
    const qs = q.toString();
    return this._get(`/api/incidents${qs ? '?' + qs : ''}`);
  },

  getIncident(id) {
    return this._get(`/api/incidents/${encodeURIComponent(id)}`);
  },

  getIncidentTimeline(id) {
    return this._get(`/api/incidents/${encodeURIComponent(id)}/timeline`);
  },

  /* --- Alerts -------------------------------------------- */
  getAlerts(params = {}) {
    const q = new URLSearchParams();
    if (params.size)      q.set('size',      String(params.size));
    if (params.severity)  q.set('severity',  params.severity);
    if (params.rule_id)   q.set('rule_id',   params.rule_id);
    if (params.user)      q.set('user',      params.user);
    if (params.source_ip) q.set('source_ip', params.source_ip);
    if (params.host)      q.set('host',      params.host);
    const qs = q.toString();
    return this._get(`/api/alerts${qs ? '?' + qs : ''}`);
  },

  getAlert(id) {
    return this._get(`/api/alerts/${encodeURIComponent(id)}`);
  },

  /* --- Events -------------------------------------------- */
  getEvents(params = {}) {
    const q = new URLSearchParams();
    if (params.size)         q.set('size',         String(params.size));
    if (params.event_action) q.set('event_action', params.event_action);
    if (params.host)         q.set('host',         params.host);
    if (params.user)         q.set('user',         params.user);
    if (params.source_ip)    q.set('source_ip',    params.source_ip);
    const qs = q.toString();
    return this._get(`/api/events${qs ? '?' + qs : ''}`);
  },

  /* --- Sources ------------------------------------------- */
  getSources() {
    return this._get('/api/sources');
  }
  ,
  updateAlertStatus: function (alertId, newStatus) {
    return fetch(API_BASE + '/api/alerts/' + encodeURIComponent(alertId) + '/status', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus }),
    }).then(function (res) {
      if (!res.ok) return res.json().then(function (d) { throw new Error(d.detail || res.statusText); });
      return res.json();
    });
  },
  
};
