import type { AuthEvent, AuthEventType, AuthMethod, AuthTracker } from './types';

/**
 * Auth tracking.
 *
 * Three rules, and they are the whole design:
 *
 * 1. **Tracking never throws.** A sign-in must not fail because telemetry did.
 *    Every entry point swallows its own errors.
 *
 * 2. **Tracking never blocks.** `track` is synchronous and fire-and-forget. A
 *    sign-in that waits on a network round trip to record that it happened is
 *    a sign-in that is slower for no user-visible benefit.
 *
 * 3. **Tracking never records a credential.** No tokens, no passwords, no
 *    refresh tokens. `AuthEvent` has no field that could hold one, so this is
 *    enforced by the shape rather than by remembering not to pass it.
 */

const NOOP: AuthTracker = { track: () => {} };

/**
 * Session id, stable per tab so the events of one attempt correlate.
 *
 * Falls back to a per-call id when sessionStorage is unavailable — private
 * mode, or a non-browser context. Worse for correlation, still better than
 * throwing from inside authentication.
 */
function makeSessionId(): string {
  try {
    const existing = sessionStorage.getItem('lectobe.auth.sessionId');
    if (existing) return existing;
    const id = crypto.randomUUID();
    sessionStorage.setItem('lectobe.auth.sessionId', id);
    return id;
  } catch {
    return 'anon-' + Math.random().toString(36).slice(2);
  }
}

export interface CreateTrackerOptions {
  /** Which surface this tracker belongs to. */
  app: string;
  /** Where to POST events. Absent means events are dropped. */
  endpoint?: string;
  /** Drop events rather than send them. Useful in tests. */
  disabled?: boolean;
  /** Batch size before an immediate flush. */
  batchSize?: number;
  /** How often to flush a partial batch, in ms. */
  flushIntervalMs?: number;
}

export function createTracker(options: CreateTrackerOptions): AuthTracker {
  const { app, endpoint, disabled, batchSize = 20, flushIntervalMs = 10_000 } = options;
  if (disabled || !endpoint) return NOOP;

  const sessionId = makeSessionId();
  const queue: AuthEvent[] = [];

  /**
   * Flush with `sendBeacon` where available.
   *
   * A `fetch` on the way out of a page is routinely cancelled by the browser,
   * and a sign-out is exactly the moment you most want the record to survive.
   * `sendBeacon` is queued by the browser and outlives the page.
   */
  const flush = (): void => {
    if (queue.length === 0) return;
    const batch = queue.splice(0, queue.length);
    try {
      const body = JSON.stringify({ events: batch });
      if (typeof navigator !== 'undefined' && typeof navigator.sendBeacon === 'function') {
        navigator.sendBeacon(endpoint, new Blob([body], { type: 'application/json' }));
        return;
      }
      void fetch(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body,
        keepalive: true,
      }).catch(() => {
        /* rule 1 */
      });
    } catch {
      /* rule 1: a failed flush is a lost event, not a failed sign-in */
    }
  };

  if (typeof window !== 'undefined') {
    window.addEventListener('pagehide', flush);
    window.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'hidden') flush();
    });
    // A slow trickle rather than one request per event.
    window.setInterval(flush, flushIntervalMs);
  }

  return {
    track(event: AuthEvent): void {
      try {
        queue.push({ ...event, sessionId, app });
        if (queue.length >= batchSize) flush();
      } catch {
        /* rule 1 */
      }
    },
  };
}

/**
 * Build an event without repeating the boilerplate at every call site.
 *
 * `sessionId` and `app` are filled in by the tracker, so a call site cannot
 * forget them or get them wrong.
 */
export function authEvent(
  type: AuthEventType,
  method: AuthMethod,
  extra: { userId?: string; reason?: string } = {},
): Omit<AuthEvent, 'sessionId' | 'app'> {
  return { type, method, at: Date.now(), ...extra };
}
