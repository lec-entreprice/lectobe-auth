/**
 * The shape of an auth event.
 *
 * Every authentication decision the platform makes produces one of these. The
 * point is not observability for its own sake — it is that "who signed in as
 * whom, and when" is a question you cannot answer retroactively if you did not
 * record it at the time.
 */

/**
 * What happened. Deliberately a closed union: an open string would let a typo
 * create a new event type that no dashboard or alert knows about.
 */
export type AuthEventType =
  | 'sign_in_started'
  | 'sign_in_succeeded'
  | 'sign_in_failed'
  | 'sign_out'
  | 'token_refreshed'
  | 'token_refresh_failed'
  | 'session_expired'
  | 'password_reset_requested'
  | 'sign_up_started'
  | 'sign_up_succeeded'
  | 'callback_exchange_succeeded'
  | 'callback_exchange_failed';

/** How the caller proved who they are. */
export type AuthMethod = 'google' | 'password' | 'refresh_token' | 'unknown';

export interface AuthEvent {
  type: AuthEventType;
  /** Stable per browser tab. Correlates the events of one attempt. */
  sessionId: string;
  /**
   * The user id, once known.
   *
   * Absent on a failed sign-in, and that absence is itself the fact worth
   * recording — a failure with no user is still a failure.
   */
  userId?: string;
  method: AuthMethod;
  /**
   * Why it failed, when it did.
   *
   * A human-readable cause, never a payload. There is no field on this type
   * that could hold a token or a password, which is what makes "never record a
   * credential" a property of the shape rather than a rule someone has to
   * remember.
   */
  reason?: string;
  /** Epoch ms. */
  at: number;
  /** Which surface produced it, so a per-app view is possible. */
  app: string;
}

/**
 * Where events go.
 *
 * The default is a no-op. A tracker that throws, or that blocks a sign-in on a
 * network call, is worse than no tracking at all: authentication must not fail
 * because telemetry did.
 */
export interface AuthTracker {
  track(event: AuthEvent): void;
}
