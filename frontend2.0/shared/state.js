/* ============================================================
   SIEM-AI — State
   Simple in-memory cache. Prevents redundant API calls
   when navigating between sections on the same page.
   ============================================================ */

const SIEM_STATE = {
  _cache: {},

  set(key, data, ttlMs = 30_000) {
    this._cache[key] = { data, expires: Date.now() + ttlMs };
  },

  get(key) {
    const entry = this._cache[key];
    if (!entry) return null;
    if (Date.now() > entry.expires) {
      delete this._cache[key];
      return null;
    }
    return entry.data;
  },

  clear(key) {
    if (key) delete this._cache[key];
    else this._cache = {};
  },

  /* Fetch-or-cache helper */
  async fetch(key, fetcher, ttlMs = 30_000) {
    const cached = this.get(key);
    if (cached !== null) return cached;
    const data = await fetcher();
    this.set(key, data, ttlMs);
    return data;
  }
};
