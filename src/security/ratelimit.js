// In-memory sliding-window rate limiter (two-bucket approximation: O(1) memory per client)
// plus a lockout tracker for repeated authentication failures.

export class RateLimiter {
  constructor({ windowMs, max, name = 'limit' }) {
    this.windowMs = windowMs; this.max = max; this.name = name;
    this.buckets = new Map();
    this.gc = setInterval(() => this.sweep(), Math.max(windowMs, 60000));
    this.gc.unref?.();
  }
  _bucket(key, now) {
    let b = this.buckets.get(key);
    const start = now - (now % this.windowMs);
    if (!b) { b = { start, count: 0, prev: 0 }; this.buckets.set(key, b); }
    if (start !== b.start) {
      b.prev = start - b.start === this.windowMs ? b.count : 0;
      b.count = 0; b.start = start;
    }
    return b;
  }
  _estimate(b, now) {
    const elapsed = (now - b.start) / this.windowMs;
    return b.prev * (1 - elapsed) + b.count;
  }
  // Check and consume one unit. Returns { allowed, limit, remaining, retryAfter (s), reset (s) }
  hit(key, cost = 1) {
    const now = Date.now();
    const b = this._bucket(key, now);
    const used = this._estimate(b, now);
    const reset = Math.ceil((b.start + this.windowMs - now) / 1000);
    if (used + cost > this.max) {
      return { allowed: false, limit: this.max, remaining: 0, retryAfter: this._retryAfter(b, now, cost), reset };
    }
    b.count += cost;
    return { allowed: true, limit: this.max, remaining: Math.max(0, Math.floor(this.max - used - cost)), retryAfter: 0, reset };
  }
  // Seconds until estimate + cost fits again. The estimate is prev·(1 − elapsed/W) + count, and when the
  // window rolls over the current count becomes "prev" and keeps decaying — so waiting for the reset alone
  // is not enough if this window is already full.
  _retryAfter(b, now, cost) {
    const W = this.windowMs, e = now - b.start, room = this.max - cost;
    let wait;
    if (room < 0) wait = W * 2;
    else if (b.count <= room && b.prev > 0) wait = W * (1 - (room - b.count) / b.prev) - e;
    else wait = (W - e) + (b.count > room ? W * (1 - room / b.count) : 0);
    return Math.max(1, Math.ceil(wait / 1000));
  }
  peek(key) {
    const now = Date.now();
    const b = this.buckets.get(key);
    return b ? this._estimate(this._bucket(key, now), now) : 0;
  }
  sweep() {
    const now = Date.now();
    for (const [k, b] of this.buckets) if (now - b.start > 2 * this.windowMs) this.buckets.delete(k);
  }
}

// N failures within windowMs → locked out for lockMs
export class Lockout {
  constructor({ maxFailures = 5, windowMs = 15 * 60000, lockMs = 15 * 60000 } = {}) {
    Object.assign(this, { maxFailures, windowMs, lockMs });
    this.fails = new Map(); // key -> { times: [], lockedUntil }
    this.gc = setInterval(() => {
      const now = Date.now();
      for (const [k, v] of this.fails) if ((v.lockedUntil || 0) < now && !v.times.some(t => now - t < this.windowMs)) this.fails.delete(k);
    }, 60000);
    this.gc.unref?.();
  }
  lockedFor(key) {
    const v = this.fails.get(key);
    const left = v?.lockedUntil ? v.lockedUntil - Date.now() : 0;
    return left > 0 ? Math.ceil(left / 1000) : 0;
  }
  fail(key) {
    const now = Date.now();
    const v = this.fails.get(key) || { times: [], lockedUntil: 0 };
    v.times = v.times.filter(t => now - t < this.windowMs);
    v.times.push(now);
    let locked = false;
    if (v.times.length >= this.maxFailures) { v.lockedUntil = now + this.lockMs; v.times = []; locked = true; }
    this.fails.set(key, v);
    return { locked, remaining: Math.max(0, this.maxFailures - v.times.length) };
  }
  success(key) { const v = this.fails.get(key); if (v && !v.lockedUntil) this.fails.delete(key); }
}

// Per-host request throttle (used by the scanner's own HTTP checks so a target is never flooded)
export class HostThrottle {
  constructor(rps = 10) { this.setRate(rps); this.next = new Map(); }
  setRate(rps) { this.rps = Math.max(0.1, Number(rps) || 10); this.interval = 1000 / this.rps; }
  async wait(host) {
    const now = Date.now();
    const slot = Math.max(now, this.next.get(host) || 0);
    this.next.set(host, slot + this.interval);
    if (this.next.size > 5000) for (const [h, t] of this.next) if (t < now) this.next.delete(h);
    if (slot > now) await new Promise(r => setTimeout(r, slot - now));
  }
}
