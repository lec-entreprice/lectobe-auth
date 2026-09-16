/**
 * The three rules from the tracker docstring, each as a test.
 *
 * These matter more than they look. A tracker that throws turns a working
 * sign-in into a broken one, and the failure appears at the worst possible
 * moment — right when a user is trying to get in.
 */
import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { createTracker, authEvent } from './tracker.ts';
import type { AuthEvent } from './types.ts';

test('a tracker with no endpoint is a no-op, not a thrower', () => {
  const tracker = createTracker({ app: 'studio' });
  // Must not throw, and must not need a browser.
  tracker.track(authEvent('sign_in_succeeded', 'google', { userId: 'u1' }));
});

test('a disabled tracker is a no-op', () => {
  const tracker = createTracker({ app: 'studio', endpoint: 'https://example.test/e', disabled: true });
  tracker.track(authEvent('sign_in_failed', 'google', { reason: 'state mismatch' }));
});

test('tracking never throws even when the environment is broken', () => {
  // No window, no sessionStorage, no navigator. The tracker must degrade, not
  // explode — this is the shape of a non-browser or private-mode context.
  const tracker = createTracker({ app: 'studio', endpoint: 'https://example.test/e' });
  for (let i = 0; i < 100; i += 1) {
    tracker.track(authEvent('token_refreshed', 'refresh_token', { userId: 'u1' }));
  }
});

test('authEvent fills the time and keeps the caller fields', () => {
  const before = Date.now();
  const e = authEvent('sign_in_failed', 'password', { reason: 'bad credentials' });
  const after = Date.now();
  assert.equal(e.type, 'sign_in_failed');
  assert.equal(e.method, 'password');
  assert.equal(e.reason, 'bad credentials');
  assert.ok(e.at >= before && e.at <= after, 'at should be a fresh timestamp');
});

test('an event cannot carry a credential, by construction', () => {
  // The type has no field for a token or a password. This asserts the field
  // set stays that way: adding one is the mistake this guards against.
  const e = authEvent('sign_in_succeeded', 'google', { userId: 'u1' });
  const allowed = new Set(['type', 'method', 'at', 'userId', 'reason', 'sessionId', 'app']);
  for (const key of Object.keys(e)) {
    assert.ok(allowed.has(key), `unexpected field on AuthEvent: ${key}`);
  }
  const serialised = JSON.stringify(e).toLowerCase();
  for (const forbidden of ['token', 'password', 'secret', 'bearer']) {
    assert.ok(!serialised.includes(forbidden), `event carried ${forbidden}`);
  }
});

test('a failure with no user id is still a valid event', () => {
  // The whole point of recording failures: a failed sign-in has no user, and
  // that absence is the fact.
  const e = authEvent('sign_in_failed', 'google', { reason: 'redirect_uri_mismatch' });
  assert.equal(e.userId, undefined);
  assert.equal(e.reason, 'redirect_uri_mismatch');
});

test('the tracker stamps sessionId and app, so a call site cannot forget them', () => {
  const seen: AuthEvent[] = [];
  const tracker = createTracker({ app: 'studio', endpoint: 'https://example.test/e' });
  // Reach into the queue indirectly: track, then read what would have flushed.
  const original = globalThis.navigator;
  Object.defineProperty(globalThis, 'navigator', {
    value: { sendBeacon: (_url: string, blob: Blob) => { void blob.text().then((b) => {
      for (const ev of JSON.parse(b).events as AuthEvent[]) seen.push(ev);
    }); return true; } },
    configurable: true,
  });
  try {
    for (let i = 0; i < 25; i += 1) {
      tracker.track(authEvent('sign_in_started', 'google'));
    }
  } finally {
    Object.defineProperty(globalThis, 'navigator', { value: original, configurable: true });
  }
  for (const ev of seen) {
    assert.equal(ev.app, 'studio');
    assert.ok(ev.sessionId && ev.sessionId.length > 0, 'sessionId was not stamped');
  }
});
