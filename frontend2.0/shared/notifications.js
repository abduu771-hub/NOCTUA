/**
 * notifications.js
 *
 * Global, self-contained live notification system for SIEM-AI.
 * Connects to GET /api/notifications/stream (SSE) and owns:
 *   - the bell icon + unread counter
 *   - toast popups for new events
 *   - the notification history panel
 *   - click-to-navigate to incident.html?id=<incident_id>
 *
 * No page implements its own notification logic. Every page just
 * includes this file and calls SIEMNotifications.init() once.
 *
 * Persistence: localStorage, since each HTML page is a full reload,
 * not an SPA route. History/unread count survive navigation between
 * index.html, alerts.html, alert.html, incidents.html, incident.html.
 */

(function () {
  "use strict";

  const STORAGE_KEY_NOTIFICATIONS = "siem_notifications_history";
  const STORAGE_KEY_LAST_SEEN = "siem_notifications_last_seen";
  const MAX_HISTORY = 100;
  const TOAST_AUTO_DISMISS_MS = 5000;
  const SSE_URL = (typeof API_BASE !== "undefined" ? API_BASE : "http://localhost:8000") + "/api/notifications/stream";
  const ASSET_PREFIX = window.location.pathname.includes("/pages/") ? "../" : "";
  // ── Notification type -> display metadata ────────────────────────────
  // Severity color follows the existing SIEM-AI scale:
  //   CRITICAL #991B1B | HIGH #C2410C | MEDIUM #D97706 | LOW #16A34A
  const TYPE_META = {
    incident_created: { label: "New Incident", dot: "severity" },
    incident_closed: { label: "Incident Closed", dot: "#16A34A" },
    incident_reopened: { label: "Incident Reopened", dot: "#D97706" },
    incident_updated: { label: "Incident Escalated", dot: "severity" },
    cross_layer_correlation: { label: "Cross-Layer Correlation", dot: "#991B1B" },
    alert_created: { label: "New Alert", dot: "severity" },
    alert_closed: { label: "Alert Closed", dot: "#16A34A" },
    alert_reopened: { label: "Alert Reopened", dot: "#D97706" },
  };

  const SEVERITY_COLOR = {
    CRITICAL: "#991B1B",
    HIGH: "#C2410C",
    MEDIUM: "#D97706",
    LOW: "#16A34A",
  };
  const OWL_IMAGES = {
    CRITICAL: "assets/images/OWL_Notification_critical.png",
    HIGH:     "assets/images/OWL_Notification_high.png",
    MEDIUM:   "assets/images/OWL_Notification_medium.png",
    LOW:      "assets/images/OWL_Notification_low.png",
    CLOSED:   "assets/images/OWL_Notification_closed.png",
  };
  const TOAST_OWL = {
    top: 8,
    left: 12,
    width: 100,
    height: 56,
    glowWidth: 30,
    glowHeight: 10,
    glowOffsetTop: 34,
    glowOffsetLeft: 5,
    glowBlur: 8,
    glowOpacity: 0.6,
  };

  function resolveOwlSrc(event) {
    const meta = TYPE_META[event.kind];
    let sevKey = "CLOSED";
    if (meta && meta.dot === "severity") {
      sevKey = (event.severity || "").toUpperCase();
      if (!OWL_IMAGES[sevKey]) sevKey = "MEDIUM";
    } else if (event.kind === "incident_closed" || event.kind === "alert_closed") {
      sevKey = "CLOSED";
    } else if (event.kind === "incident_reopened" || event.kind === "alert_reopened") {
      sevKey = "HIGH";
    } else if (event.kind === "cross_layer_correlation") {
      sevKey = "CRITICAL";
    }
    return ASSET_PREFIX + OWL_IMAGES[sevKey];;
  }

  function resolveGlowColor(event) {
    const meta = TYPE_META[event.kind];
    if (meta && meta.dot === "severity") {
      return SEVERITY_COLOR[(event.severity || "").toUpperCase()] || SEVERITY_COLOR.MEDIUM;
    }
    return resolveDotColor(event);
  }

  function resolveDotColor(event) {
    const meta = TYPE_META[event.kind];
    if (!meta) return "#6B7280";
    if (meta.dot === "severity") {
      return SEVERITY_COLOR[(event.severity || "").toUpperCase()] || "#6B7280";
    }
    return meta.dot;
  }

  function buildMessage(event) {
    const meta = TYPE_META[event.kind] || { label: "Notification" };
    const name = event.incident_name || event.rule_id || event.incident_type || "";
    return { title: meta.label, detail: name };
  }

  function timeAgo(isoString) {
    if (!isoString) return "";
    const then = new Date(isoString).getTime();
    const now = Date.now();
    const diffSec = Math.max(0, Math.floor((now - then) / 1000));
    if (diffSec < 5) return "just now";
    if (diffSec < 60) return `${diffSec} sec ago`;
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return `${diffMin} min ago`;
    const diffHr = Math.floor(diffMin / 60);
    return `${diffHr} hr ago`;
  }

  // ── State ──────────────────────────────────────────────────────────────

  let notifications = [];
  let unreadCount = 0;
  let lastSeenTimestamp = null;
  let activeToasts = [];
  let eventSource = null;
  let panelOpen = false;

  function loadState() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY_NOTIFICATIONS);
      notifications = raw ? JSON.parse(raw) : [];
    } catch (e) {
      notifications = [];
    }
    lastSeenTimestamp = localStorage.getItem(STORAGE_KEY_LAST_SEEN) || null;
    unreadCount = notifications.filter(
      (n) => !lastSeenTimestamp || n.occurred_at > lastSeenTimestamp
    ).length;
  }

  function persistNotifications() {
    try {
      localStorage.setItem(
        STORAGE_KEY_NOTIFICATIONS,
        JSON.stringify(notifications.slice(0, MAX_HISTORY))
      );
    } catch (e) {
      /* storage full or unavailable — fail silently, in-memory state still works */
    }
  }

  function markAllSeen() {
    lastSeenTimestamp = new Date().toISOString();
    localStorage.setItem(STORAGE_KEY_LAST_SEEN, lastSeenTimestamp);
    unreadCount = 0;
    renderBell();
  }

  // ── Dedup ──────────────────────────────────────────────────────────────

  function notificationKey(event) {
    return [
      event.kind,
      event.incident_id || event.alert_id || "",
      event.occurred_at || "",
    ].join("::");
  }

  function isDuplicate(event) {
    const key = notificationKey(event);
    return notifications.some((n) => notificationKey(n) === key);
  }

  // ── DOM: bell + panel + toast container (injected once) ────────────────

  function injectStyles() {
    if (document.getElementById("siem-notif-styles")) return;
    const style = document.createElement("style");
    style.id = "siem-notif-styles";
    style.textContent = `
      .siem-notif-bell {
        position: relative;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 36px;
        height: 36px;
        cursor: pointer;
        border: 0.5px solid rgba(0,0,0,0.1);
        border-radius: 6px;
        background: #fff;
        transition: background 200ms ease, border-color 200ms ease;
      }
      .siem-notif-bell:hover { background: #F2F2EF; }
      .siem-notif-bell svg { width: 18px; height: 18px; stroke: #0B0B0B; }
      .siem-notif-badge {
        position: absolute;
        top: -4px;
        right: -4px;
        min-width: 16px;
        height: 16px;
        padding: 0 4px;
        border-radius: 8px;
        background: #991B1B;
        color: #fff;
        font-family: "DM Sans", sans-serif;
        font-size: 10px;
        font-weight: 600;
        line-height: 16px;
        text-align: center;
      }
      .siem-notif-panel {
        position: absolute;
        top: 44px;
        right: 0;
        width: 360px;
        max-height: 480px;
        overflow-y: auto;
        background: #fff;
        border: 0.5px solid rgba(0,0,0,0.1);
        border-radius: 8px;
        box-shadow: 0 4px 16px rgba(0,0,0,0.08);
        z-index: 1000;
        display: none;
      }
      .siem-notif-panel.open { display: block; }
      .siem-notif-panel-header {
        padding: 12px 16px;
        font-family: Georgia, serif;
        font-size: 13px;
        text-transform: uppercase;
        letter-spacing: 0.04em;
        border-bottom: 0.5px solid rgba(0,0,0,0.08);
        color: #0B0B0B;
      }
      .siem-notif-item {
        display: flex;
        gap: 10px;
        padding: 12px 16px;
        border-bottom: 0.5px solid rgba(0,0,0,0.06);
        cursor: pointer;
        transition: background 200ms ease;
      }
      .siem-notif-item:hover { background: #F2F2EF; }
      .siem-notif-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        margin-top: 5px;
        flex-shrink: 0;
      }
      .siem-notif-body { flex: 1; min-width: 0; }
      .siem-notif-title {
        font-family: "DM Sans", sans-serif;
        font-size: 13px;
        font-weight: 600;
        color: #0B0B0B;
      }
      .siem-notif-detail {
        font-family: "DM Sans", sans-serif;
        font-size: 12px;
        color: #4B4B4B;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .siem-notif-time {
        font-family: "DM Sans", sans-serif;
        font-size: 11px;
        color: #9A9A9A;
        margin-top: 2px;
      }
      .siem-notif-empty {
        padding: 24px 16px;
        text-align: center;
        font-family: "DM Sans", sans-serif;
        font-size: 12px;
        color: #9A9A9A;
      }
      .siem-toast-container {
        position: fixed;
        top: 16px;
        right: 16px;
        z-index: 2000;
        display: flex;
        flex-direction: column;
        gap: 8px;
      }
   .siem-toast {
        position: relative;
        width: 400px;
        background: #fff;
        border: 0.5px solid rgba(0,0,0,0.08);
        border-left: 4px solid var(--toast-glow-color, #991B1B);
        border-radius: 10px;
        box-shadow: 0 4px 18px rgba(0,0,0,0.10);
        padding: 14px 16px 14px 14px;
        cursor: pointer;
        transform: translateX(110%) scale(0.96);
        transition: transform 320ms cubic-bezier(.22,1.2,.36,1), opacity 280ms ease;
        opacity: 0;
        overflow: hidden;
      }
      .siem-toast.show { transform: translateX(0) scale(1); opacity: 1; }
      .siem-toast-owl-img {
        position: absolute;
        object-fit: contain;
        z-index: 1;
      }
      .siem-toast-body { position: relative; z-index: 1; min-width: 0; padding-top: 1px; }
      .siem-toast-title {
        font-family: var(--ff-mono);
        font-size: 13px;
        font-weight: 800;
        color: #0B0B0B;
      }
      .siem-toast-detail {
        font-family: var(--ff-mono);
        font-size: 12px;
        font-weight: 500;
        color: #4B4B4B;
        margin-top: 2px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .siem-toast-time {
        font-family: var(--ff-mono);
        font-size: 11px;
        font-weight: 500;
        color: #9A9A9A;
        margin-top: 4px;
      }
    `;
    document.head.appendChild(style);
  }

  function injectDom() {
    if (document.getElementById("siem-notif-root")) return;

    const root = document.createElement("div");
    root.id = "siem-notif-root";
    root.style.position = "relative";
    root.innerHTML = `
      <div class="siem-notif-bell" id="siem-notif-bell" title="Notifications">
        <svg viewBox="0 0 24 24" fill="none" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
          <path d="M6 8a6 6 0 0 1 12 0c0 4 1.5 5.5 1.5 6.5H4.5C4.5 13.5 6 12 6 8Z"/>
          <path d="M9.5 17a2.5 2.5 0 0 0 5 0"/>
        </svg>
        <span class="siem-notif-badge" id="siem-notif-badge" style="display:none;">0</span>
      </div>
      <div class="siem-notif-panel" id="siem-notif-panel">
        <div class="siem-notif-panel-header">Notifications</div>
        <div id="siem-notif-list"></div>
      </div>
    `;

    // Mount point: looks for a designated slot, falls back to body (fixed, top-right)
    const mountTarget = document.getElementById("siem-notif-mount");
    if (mountTarget) {
      mountTarget.appendChild(root);
    } else {
      root.style.position = "fixed";
      root.style.top = "16px";
      root.style.right = "60px";
      root.style.zIndex = "1500";
      document.body.appendChild(root);
    }

    const toastContainer = document.createElement("div");
    toastContainer.className = "siem-toast-container";
    toastContainer.id = "siem-toast-container";
    document.body.appendChild(toastContainer);

    document.getElementById("siem-notif-bell").addEventListener("click", (e) => {
      e.stopPropagation();
      togglePanel();
    });

    document.addEventListener("click", (e) => {
      const panel = document.getElementById("siem-notif-panel");
      const bell = document.getElementById("siem-notif-bell");
      if (panelOpen && !panel.contains(e.target) && !bell.contains(e.target)) {
        closePanel();
      }
    });
  }

  function togglePanel() {
    panelOpen ? closePanel() : openPanel();
  }

  function openPanel() {
    panelOpen = true;
    document.getElementById("siem-notif-panel").classList.add("open");
    markAllSeen();
  }

  function closePanel() {
    panelOpen = false;
    document.getElementById("siem-notif-panel").classList.remove("open");
  }

  // ── Rendering ────────────────────────────────────────────────────────

  function renderBell() {
    const badge = document.getElementById("siem-notif-badge");
    if (!badge) return;
    if (unreadCount > 0) {
      badge.style.display = "block";
      badge.textContent = unreadCount > 99 ? "99+" : String(unreadCount);
    } else {
      badge.style.display = "none";
    }
  }

  function renderPanel() {
    const list = document.getElementById("siem-notif-list");
    if (!list) return;

    if (notifications.length === 0) {
      list.innerHTML = `<div class="siem-notif-empty">No notifications yet</div>`;
      return;
    }

    list.innerHTML = notifications
      .map((n) => {
        const msg = buildMessage(n);
        const color = resolveDotColor(n);
        return `
          <div class="siem-notif-item" data-incident-id="${n.incident_id || ""}" data-alert-id="${n.alert_id || ""}">
            <div class="siem-notif-dot" style="background:${color};"></div>
            <div class="siem-notif-body">
              <div class="siem-notif-title">${escapeHtml(msg.title)}</div>
              <div class="siem-notif-detail">${escapeHtml(msg.detail)}</div>
              <div class="siem-notif-time">${timeAgo(n.occurred_at)}</div>
            </div>
          </div>
        `;
      })
      .join("");

    list.querySelectorAll(".siem-notif-item").forEach((el) => {
      el.addEventListener("click", () => {
        const incidentId = el.getAttribute("data-incident-id");
        const alertId = el.getAttribute("data-alert-id");
        if (incidentId) {
          window.location.href = `pages/incident.html?id=${encodeURIComponent(incidentId)}`;
        } else if (alertId) {
          window.location.href = `pages/alert.html?id=${encodeURIComponent(alertId)}`;
        }
      });
    });
  }

  function escapeHtml(str) {
    if (str == null) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  // ── Toasts ─────────────────────────────────────────────────────────────

  function showToast(event) {
    const container = document.getElementById("siem-toast-container");
    if (!container) return;

    const msg = buildMessage(event);
    const glowColor = resolveGlowColor(event);
    const owlSrc = resolveOwlSrc(event);

    const toast = document.createElement("div");
    toast.className = "siem-toast";
    toast.style.setProperty("--toast-glow-color", glowColor);
  toast.innerHTML = `
      <img class="siem-toast-owl-img" src="${owlSrc}" alt="" style="
        top:${TOAST_OWL.top}px;
        left:${TOAST_OWL.left}px;
        width:${TOAST_OWL.width}px;
        height:${TOAST_OWL.height}px;
      " />
      <div class="siem-toast-body" style="padding-left:${TOAST_OWL.left + TOAST_OWL.width + 10}px;">
        <div class="siem-toast-title">${escapeHtml(msg.title)}</div>
        <div class="siem-toast-detail">${escapeHtml(msg.detail)}</div>
        <div class="siem-toast-time">${timeAgo(event.occurred_at)}</div>
      </div>
    `;

    toast.addEventListener("click", () => {
  if (event.incident_id) {
    window.location.href = `pages/incident.html?id=${encodeURIComponent(event.incident_id)}`;
  } else if (event.alert_id) {
    window.location.href = `pages/alert.html?id=${encodeURIComponent(event.alert_id)}`;
  }
});

    container.appendChild(toast);
    activeToasts.push(toast);

    requestAnimationFrame(() => toast.classList.add("show"));

    setTimeout(() => {
      toast.classList.remove("show");
      setTimeout(() => {
        toast.remove();
        activeToasts = activeToasts.filter((t) => t !== toast);
      }, 200);
    }, TOAST_AUTO_DISMISS_MS);
  }

  // ── Incoming event handling ─────────────────────────────────────────

  function handleIncomingEvent(event) {
    if (!event || !event.kind) return;
    if (isDuplicate(event)) return;

    notifications.unshift(event);
    notifications = notifications.slice(0, MAX_HISTORY);
    persistNotifications();

    if (!panelOpen) {
      unreadCount += 1;
    }

    renderBell();
    renderPanel();
    showToast(event);
  }
// ── TEMP TEST INJECTOR — remove before production ──────────────────────
  function injectFakeToast() {
    handleIncomingEvent({
      kind: "incident_created",
      severity: "CRITICAL",
      incident_id: "test-fake-id",
      incident_name: "Fake Test Incident — Owl Placement Check",
      occurred_at: new Date().toISOString(),
    });
  }
  window.SIEMNotifications_testToast = injectFakeToast;
  // ── SSE connection ─────────────────────────────────────────────────────

  function connect() {
    if (eventSource) return;

    eventSource = new EventSource(SSE_URL);

    eventSource.onmessage = (e) => {
      try {
        const event = JSON.parse(e.data);
        handleIncomingEvent(event);
      } catch (err) {
        /* malformed event — ignore, stream continues */
      }
    };

    eventSource.onerror = () => {
      // EventSource auto-reconnects on its own; nothing to do here.
      // We deliberately do not tear down state on error/reconnect —
      // the per-connection cache on the SERVER side resets, but our
      // client-side history in localStorage is untouched.
    };
  }

  // ── Public init ──────────────────────────────────────────────────────

  function init() {
    injectStyles();
    injectDom();
    loadState();
    renderBell();
    renderPanel();
    connect();
    setTimeout(injectFakeToast, 0);
  }

  window.SIEMNotifications = { init };
})();