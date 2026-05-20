# SIEM-AI API Documentation

This document provides a comprehensive reference for the SIEM-AI backend API (`api` folder). The API is built using FastAPI and serves as a read-only data layer for the frontend dashboard. 

## Base Configuration
- **Base Prefix**: All endpoints (except the root, which is unmapped) are prefixed with `/api`.
- **Authentication**: None required.
- **CORS**: Enabled for all origins (`*`), allowing requests from any frontend application.
- **Data Source**: Elasticsearch indices (`siem-raw-*`, `siem-alerts-*`, `siem-incidents-*`).

---

## Endpoint Grouping

### 1. System Metrics & Health

#### `GET /api/health`
Checks the health and status of the API service.
- **File**: `api/main.py`
- **Query Parameters**: None
- **Headers**: None
- **TypeScript Interface**:
  ```typescript
  interface HealthResponse {
      status: string;
      service: string;
  }
  ```
- **Example Request**:
  ```http
  GET /api/health
  ```
- **Example Response**:
  ```json
  {
      "status": "ok",
      "service": "siem-ai-api"
  }
  ```

#### `GET /api/overview`
Retrieves high-level counts and statistics for the dashboard overview.
- **File**: `api/routes/overview.py`
- **Query Parameters**: None
- **Headers**: None
- **Notes**: Critical for the `Overview.tsx` page to render top-level KPIs.
- **TypeScript Interface**:
  ```typescript
  interface OverviewResponse {
      total_events: number;
      total_alerts: number;
      total_incidents: number;
      open_incidents: number;
      critical_alerts: number;
      latest_alert_time: string | null;
      latest_incident_time: string | null;
  }
  ```
- **Example Request**:
  ```http
  GET /api/overview
  ```
- **Example Response**:
  ```json
  {
      "total_events": 15430,
      "total_alerts": 120,
      "total_incidents": 5,
      "open_incidents": 2,
      "critical_alerts": 15,
      "latest_alert_time": "2026-05-05T15:30:00Z",
      "latest_incident_time": "2026-05-05T14:00:00Z"
  }
  ```

---

### 2. Sources (Log Shippers)

#### `GET /api/sources`
Retrieves an aggregation of unique hosts sending logs, their event counts, and their active status.
- **File**: `api/routes/sources.py`
- **Query Parameters**: None
- **Headers**: None
- **TypeScript Interface**:
  ```typescript
  interface Source {
      host: string;
      event_count: number;
      last_event_timestamp: string;
      status: "active" | "stale" | "unknown";
  }
  
  // Note: the API can return { error: string, sources: [] } if Elasticsearch fails.
  ```
- **Example Request**:
  ```http
  GET /api/sources
  ```
- **Example Response**:
  ```json
  [
      {
          "host": "web-server-01",
          "event_count": 5230,
          "last_event_timestamp": "2026-05-05T16:00:00.000Z",
          "status": "active"
      }
  ]
  ```

---

### 3. Alerts

#### `GET /api/alerts`
Fetches a list of security alerts, sorted by `@timestamp` descending.
- **File**: `api/routes/alerts.py`
- **Query Parameters**:
  - `size` (int, optional, default: 50, max: 500) - Number of results to return.
  - `severity` (string, optional) - Filter by severity (e.g., "high", "critical").
  - `rule_id` (string, optional) - Filter by specific rule ID.
  - `user` (string, optional) - Filter by user.name.
  - `source_ip` (string, optional) - Filter by source IP.
  - `host` (string, optional) - Filter by host.name.
- **Headers**: None
- **Notes**: Returns an array of alerts. Crucial for the Alerts dashboard.
- **TypeScript Interface**:
  ```typescript
  interface Alert {
      _id: string;
      _index: string;
      "@timestamp": string;
      rule: Record<string, any>;
      event: Record<string, any>;
      source: Record<string, any>;
      user: { name?: string };
      host: Record<string, any>;
      evidence: Record<string, any>;
      correlation: Record<string, any>;
      mitre: Record<string, any>;
      engine: Record<string, any>;
  }
  ```
- **Example Request**:
  ```http
  GET /api/alerts?size=10&severity=critical
  ```

#### `GET /api/alerts/{alert_id}`
Fetches details of a specific alert by its document ID.
- **File**: `api/routes/alerts.py`
- **Parameters**: `alert_id` (path parameter, string)
- **Response**: A single alert object (contains `_id`, `_index`, and all nested `_source` fields). Returns a `404` if not found.

---

### 4. Incidents

#### `GET /api/incidents`
Fetches a list of grouped security incidents, sorted by `updated_at` descending.
- **File**: `api/routes/incidents.py`
- **Query Parameters**:
  - `size` (int, optional, default: 50, max: 500)
  - `status` (string, optional) - Filter by status (e.g., "open", "closed").
  - `incident_type` (string, optional) - Filter by incident.incident_type.
  - `user` (string, optional) - Filter by attack_context.users_seen.
  - `host` (string, optional) - Filter by host.name.
- **Headers**: None
- **TypeScript Interface**:
  ```typescript
  interface Incident {
      _id: string;
      _index: string;
      incident: Record<string, any>;
      source: Record<string, any>;
      host: Record<string, any>;
      attack_context: Record<string, any>;
      related: Record<string, any>;
      created_at: string;
      updated_at: string;
  }
  ```
- **Example Request**:
  ```http
  GET /api/incidents?status=open
  ```

#### `GET /api/incidents/{incident_id}`
Fetches details of a specific incident by ID. Can accept either the Elasticsearch document `_id` or the logical `incident.id`.
- **File**: `api/routes/incidents.py`
- **Parameters**: `incident_id` (path parameter, string)
- **Response**: A single incident object. Returns `404` if not found.

#### `GET /api/incidents/{incident_id}/timeline`
Constructs a timeline of alerts related to a specific incident by querying related rules, users seen, and hosts involved.
- **File**: `api/routes/incidents.py`
- **Parameters**: `incident_id` (path parameter, string)
- **Response**: Array of timeline event objects sorted by ascending timestamp.
- **TypeScript Interface**:
  ```typescript
  interface TimelineEvent {
      rule: { id?: string; description?: string };
      severity: string;
      user: { name?: string };
      source: { ip?: string };
      host: { name?: string };
      evidence: any;
      correlation: any;
      "@timestamp": string;
  }
  ```

---

### 5. Raw Events

#### `GET /api/events`
Fetches raw normalized logs/events from the SIEM engine.
- **File**: `api/routes/events.py`
- **Query Parameters**:
  - `size` (int, optional, default: 50, max: 500)
  - `event_action` (string, optional)
  - `host` (string, optional)
  - `user` (string, optional)
  - `source_ip` (string, optional)
- **Headers**: None
- **TypeScript Interface**:
  ```typescript
  interface RawEvent {
      _id: string;
      _index: string;
      "@timestamp": string;
      event: { action?: string };
      source: { ip?: string };
      user: { name?: string; effective?: { name?: string } };
      host: { name?: string };
      process: { name?: string; command_line?: string };
      message: string;
      tags: string[];
  }
  ```
- **Example Request**:
  ```http
  GET /api/events?size=10
  ```
