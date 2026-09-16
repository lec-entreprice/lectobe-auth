import type { AuthProvider } from './provider';
import { AuthCapabilityError, AuthConfigurationError } from './provider';
import type {
  AuthChangeEvent,
  AuthResult,
  AuthSession,
  AuthSignOutResult,
  AuthSubscription,
  AuthUser,
  CredentialSignInData,
  OAuthSignInData,
  ResetPasswordData,
  SignInWithGoogleOptions,
  SignUpOptions,
  TokenStorage,
  UserRole,
} from './types';

/* -------------------------------------------------------------------------- */
/* Configuration                                                              */
/* -------------------------------------------------------------------------- */

import type { AuthTracker } from './tracking/types';
import { authEvent } from './tracking/tracker';

/** A tracker that does nothing, so a provider without one is still safe to call. */
const NO_TRACKER: AuthTracker = { track: () => {} };

export interface CognitoConfig {
  /**
   * Where auth events go. Absent means they are dropped -- authentication
   * must never fail because telemetry did.
   */
  tracker?: AuthTracker;
  /** e.g. `us-east-1` */
  region: string;
  /** e.g. `us-east-1_Pyka8fOtL` */
  userPoolId: string;
  /** App client id, e.g. `5427olhbnv2dvj4s07b8hfmnv8` */
  clientId: string;
  /** Hosted UI domain, with or without scheme, e.g. `lectobe-maker.auth.us-east-1.amazoncognito.com` */
  domain: string;
  /** Absolute callback URL registered on the app client. */
  redirectUri: string;
  /** Absolute post-logout URL registered on the app client. */
  logoutUri?: string;
  /** OAuth scopes. Defaults to `openid email profile`. */
  scopes?: string[];
  /** Role applied when the `cognito:groups` claim yields nothing. Defaults to `client`. */
  defaultRole?: UserRole;
  /** Where PKCE state and tokens live. Defaults to `sessionStorage` (see `createDefaultStorage`). */
  storage?: TokenStorage;
  /** Key namespace. Defaults to `lectobe.auth.`. */
  storagePrefix?: string;
  /** App-supplied redirect sanitiser, so each portal keeps its own allow-list. */
  resolveRedirect?: (candidate: string | undefined) => string;
  /** Injectable fetch, for tests and non-browser runtimes. */
  fetchImpl?: typeof fetch;
  /** Diagnostics hook. Defaults to `console.warn`. */
  onError?: (message: string, error: unknown) => void;
  /** Refresh this many seconds before expiry. Defaults to 60. */
  refreshLeewaySeconds?: number;
}

const DEFAULT_SCOPES = ['openid', 'email', 'profile'];
const DEFAULT_PREFIX = 'lectobe.auth.';
const DEFAULT_LEEWAY_SECONDS = 60;
const DEFAULT_ROLE: UserRole = 'client';

/* -------------------------------------------------------------------------- */
/* Storage                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Default credential storage.
 *
 * Tokens live in `sessionStorage`, not `localStorage`.
 *
 * A token in `localStorage` survives browser restarts and is readable by every
 * script on the origin for as long as it sits there, so any XSS anywhere on the
 * domain yields a long-lived, replayable credential. `sessionStorage` is scoped
 * to a single tab and dies with it, which is a much smaller blast radius and is
 * what a browser SPA actually needs.
 *
 * Deliberate behaviour change: sign-in no longer survives a browser restart or
 * a duplicated tab. A Cognito refresh token in `sessionStorage` still spans page
 * reloads and client-side navigation within the tab, including the full OAuth
 * redirect round-trip, because the callback returns in the same tab.
 *
 * Falls back to an in-memory map when `sessionStorage` is unavailable (SSR,
 * private-mode restrictions, test runtimes) so the provider never throws on
 * storage access.
 */
export function createDefaultStorage(): TokenStorage {
  const memory = new Map<string, string>();

  const memoryStorage: TokenStorage = {
    getItem: (key) => memory.get(key) ?? null,
    setItem: (key, value) => {
      memory.set(key, value);
    },
    removeItem: (key) => {
      memory.delete(key);
    },
  };

  try {
    if (typeof window !== 'undefined' && window.sessionStorage) {
      const probe = '__lectobe_auth_probe__';
      window.sessionStorage.setItem(probe, '1');
      window.sessionStorage.removeItem(probe);
      return window.sessionStorage;
    }
  } catch {
    // Storage can be present but throw (Safari private mode, blocked cookies).
  }

  return memoryStorage;
}

/* -------------------------------------------------------------------------- */
/* PKCE helpers                                                               */
/* -------------------------------------------------------------------------- */

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * RFC 7636 `code_verifier`: 32 random bytes, base64url encoded. That yields 43
 * characters, inside the spec's 43-128 range.
 */
function createCodeVerifier(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

/** RFC 7636 S256 challenge. */
async function createCodeChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return base64UrlEncode(new Uint8Array(digest));
}

/** Opaque anti-CSRF value, echoed back on the redirect. */
function createState(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

/* -------------------------------------------------------------------------- */
/* Token decoding                                                             */
/* -------------------------------------------------------------------------- */

interface JwtClaims {
  sub?: string;
  iss?: string;
  aud?: string;
  exp?: number;
  iat?: number;
  token_use?: string;
  email?: string;
  'cognito:username'?: string;
  'cognito:groups'?: unknown;
  [key: string]: unknown;
}

/** Decodes a JWT payload without verifying the signature. */
export function decodeJwtClaims(token: string): JwtClaims | null {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=');
    const binary = atob(padded);
    const json = decodeURIComponent(
      binary
        .split('')
        .map((char) => `%${`00${char.charCodeAt(0).toString(16)}`.slice(-2)}`)
        .join(''),
    );
    const parsed: unknown = JSON.parse(json);
    if (!parsed || typeof parsed !== 'object') return null;
    return parsed as JwtClaims;
  } catch {
    return null;
  }
}

/**
 * Maps the `cognito:groups` claim onto a `UserRole`.
 *
 * Cognito has no `user_metadata`, so groups are the only server-controlled role
 * signal. The first group is lowercased (Cognito group names are conventionally
 * upper-case, while the application role union is lower-case) and everything
 * else falls back to `fallback`.
 */
export function roleFromGroups(groups: unknown, fallback: UserRole = DEFAULT_ROLE): UserRole {
  if (!Array.isArray(groups)) return fallback;
  const first = groups.find((group): group is string => typeof group === 'string' && group.length > 0);
  return first ? first.toLowerCase() : fallback;
}

/* -------------------------------------------------------------------------- */
/* Provider                                                                   */
/* -------------------------------------------------------------------------- */

interface StoredSession {
  access_token: string;
  refresh_token: string;
  expires_at: number;
  token_type: string;
  user: AuthUser;
}

interface TokenEndpointResponse {
  access_token?: string;
  id_token?: string;
  refresh_token?: string;
  expires_in?: number;
  token_type?: string;
  error?: string;
  error_description?: string;
}

/**
 * Authorization Code + PKCE provider for the Cognito Hosted UI.
 *
 * Deliberately built on plain `fetch` rather than `amazon-cognito-identity-js`:
 * the library is heavy, and it cannot drive the Hosted UI — which is what serves
 * Google federation here, so it would be the wrong tool for the only sign-in
 * method this platform uses.
 */
export class CognitoAuthProvider implements AuthProvider {
  public readonly name = 'cognito' as const;

  public readonly isConfigured: boolean;

  private readonly config: CognitoConfig;

  private readonly storage: TokenStorage;

  private readonly prefix: string;

  private readonly fetchImpl: typeof fetch | null;

  private readonly listeners = new Set<(event: AuthChangeEvent, session: AuthSession | null) => void>();

  private readonly tracker: AuthTracker;

  /**
   * The most recent user id this provider saw.
   *
   * A sign-out event is worth recording even though the session is about to
   * be cleared, and by the time the event is built the token is gone. This
   * is the id captured before that, so the event names a person rather
   * than being anonymous.
   */
  private lastKnownUserId?: string;

  constructor(config: CognitoConfig) {
    this.tracker = config.tracker ?? NO_TRACKER;
    this.config = config;
    this.storage = config.storage ?? createDefaultStorage();
    this.prefix = config.storagePrefix ?? DEFAULT_PREFIX;
    this.fetchImpl = config.fetchImpl ?? (typeof fetch === 'function' ? fetch.bind(globalThis) : null);
    this.isConfigured = Boolean(
      config.clientId && config.domain && config.redirectUri && config.region && config.userPoolId,
    );
  }

  /* ----------------------------- URL builders ----------------------------- */

  private get domainHost(): string {
    return this.config.domain.replace(/^https?:\/\//, '').replace(/\/$/, '');
  }

  private get authorizeEndpoint(): string {
    return `https://${this.domainHost}/oauth2/authorize`;
  }

  private get tokenEndpoint(): string {
    return `https://${this.domainHost}/oauth2/token`;
  }

  private get logoutEndpoint(): string {
    return `https://${this.domainHost}/logout`;
  }

  private get expectedIssuer(): string {
    return `https://cognito-idp.${this.config.region}.amazonaws.com/${this.config.userPoolId}`;
  }

  private resolveRedirect(candidate: string | undefined): string {
    if (this.config.resolveRedirect) return this.config.resolveRedirect(candidate);
    return candidate || this.config.redirectUri;
  }

  /**
   * Builds a Hosted UI URL, minting and persisting fresh PKCE material.
   *
   * The verifier never leaves the browser; only its S256 digest is sent.
   */
  private async buildAuthorizeUrl(params: {
    path?: string;
    identityProvider?: 'Google';
    loginHint?: string;
    redirectTo?: string;
  }): Promise<string> {
    if (!this.isConfigured) {
      throw new AuthConfigurationError(
        'cognito',
        'Cognito authentication is not configured for this environment.',
      );
    }
    if (typeof crypto === 'undefined' || !crypto.subtle) {
      throw new AuthCapabilityError(
        'cognito',
        'pkce',
        'Secure browser crypto (WebCrypto) is unavailable, so PKCE sign-in cannot start.',
      );
    }

    const verifier = createCodeVerifier();
    const challenge = await createCodeChallenge(verifier);
    const state = createState();
    const redirectUri = this.resolveRedirect(params.redirectTo);

    this.storage.setItem(`${this.prefix}pkce_verifier`, verifier);
    this.storage.setItem(`${this.prefix}pkce_state`, state);
    // The token endpoint requires the *same* redirect_uri that was sent to
    // /oauth2/authorize. Remember exactly what went out rather than assuming it
    // equals the configured default, otherwise a sanitised redirect fails the
    // exchange with `invalid_grant`.
    this.storage.setItem(`${this.prefix}pkce_redirect`, redirectUri);

    const url = new URL(params.path ? `https://${this.domainHost}${params.path}` : this.authorizeEndpoint);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', this.config.clientId);
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('scope', (this.config.scopes ?? DEFAULT_SCOPES).join(' '));
    url.searchParams.set('state', state);
    url.searchParams.set('code_challenge', challenge);
    url.searchParams.set('code_challenge_method', 'S256');
    if (params.identityProvider) {
      url.searchParams.set('identity_provider', params.identityProvider);
    }
    if (params.loginHint) {
      url.searchParams.set('login_hint', params.loginHint);
    }
    return url.toString();
  }

  /** Public so a caller can perform a full (federated) sign-out on demand. */
  public getLogoutUrl(): string {
    const url = new URL(this.logoutEndpoint);
    url.searchParams.set('client_id', this.config.clientId);
    if (this.config.logoutUri) {
      url.searchParams.set('logout_uri', this.config.logoutUri);
    }
    return url.toString();
  }

  /* ------------------------------- Tokens -------------------------------- */

  private clearPkceState(): void {
    this.storage.removeItem(`${this.prefix}pkce_verifier`);
    this.storage.removeItem(`${this.prefix}pkce_state`);
    this.storage.removeItem(`${this.prefix}pkce_redirect`);
  }

  /**
   * Converts an ID token into the `AuthUser` shape the application already
   * understands, normalising `cognito:groups` into `app_metadata.role` so the
   * existing role logic keeps working unchanged.
   */
  private userFromTokens(accessToken: string, idToken: string | undefined): AuthUser {
    const claims: JwtClaims = decodeJwtClaims(idToken ?? '') ?? decodeJwtClaims(accessToken) ?? {};
    const accessClaims: JwtClaims = decodeJwtClaims(accessToken) ?? {};

    if (claims.iss && claims.iss !== this.expectedIssuer) {
      throw new AuthCapabilityError(
        'cognito',
        'issuer',
        'The identity token was issued by an unexpected Cognito user pool.',
      );
    }

    const groups = claims['cognito:groups'] ?? accessClaims['cognito:groups'];
    const role = roleFromGroups(groups, this.config.defaultRole ?? DEFAULT_ROLE);

    // Cognito records the upstream identity provider on `identities` for
    // federated sign-in (e.g. Google) and omits it for native pool users.
    const identities = claims.identities;
    const providers = Array.isArray(identities)
      ? identities
          .map((entry) =>
            entry && typeof entry === 'object' && typeof (entry as { providerName?: unknown }).providerName === 'string'
              ? (entry as { providerName: string }).providerName
              : null,
          )
          .filter((entry): entry is string => entry !== null)
      : [];

    return {
      id: String(claims.sub ?? ''),
      aud: String(claims.aud ?? this.config.clientId),
      created_at: new Date(((claims.iat as number | undefined) ?? Math.floor(Date.now() / 1000)) * 1000).toISOString(),
      email: typeof claims.email === 'string' ? claims.email : undefined,
      role,
      app_metadata: {
        role,
        provider: providers[0],
        providers: providers.length > 0 ? providers : undefined,
        'cognito:groups': Array.isArray(groups) ? groups : undefined,
      },
      user_metadata: {},
    };
  }

  private toSession(payload: TokenEndpointResponse): AuthSession {
    const accessToken = payload.access_token;
    if (!accessToken) {
      throw new AuthCapabilityError(
        'cognito',
        'token_response',
        'The Cognito token endpoint returned no access token.',
      );
    }
    const expiresIn = typeof payload.expires_in === 'number' ? payload.expires_in : 3600;
    const refreshToken = typeof payload.refresh_token === 'string' ? payload.refresh_token : '';
    const user = this.userFromTokens(accessToken, payload.id_token);

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: expiresIn,
      expires_at: Math.floor(Date.now() / 1000) + expiresIn,
      token_type: typeof payload.token_type === 'string' ? payload.token_type : 'Bearer',
      user,
    };
  }

  private persist(session: AuthSession): void {
    // Remembered here rather than at each call site: `persist` is the one
    // place a resolved session lands, so a sign-out can still name the
    // person after the token has been cleared.
    if (session?.user?.id) this.lastKnownUserId = session.user.id;
    const stored: StoredSession = {
      access_token: session.access_token,
      refresh_token: session.refresh_token,
      expires_at: session.expires_at ?? Math.floor(Date.now() / 1000) + session.expires_in,
      token_type: session.token_type,
      user: session.user,
    };
    try {
      this.storage.setItem(`${this.prefix}session`, JSON.stringify(stored));
    } catch (error) {
      this.report('Unable to persist the Cognito session.', error);
    }
  }

  private readPersisted(): StoredSession | null {
    try {
      const raw = this.storage.getItem(`${this.prefix}session`);
      if (!raw) return null;
      const parsed: unknown = JSON.parse(raw);
      if (!parsed || typeof parsed !== 'object') return null;
      const candidate = parsed as Partial<StoredSession>;
      if (!candidate.access_token || !candidate.user) return null;
      return {
        access_token: candidate.access_token,
        refresh_token: typeof candidate.refresh_token === 'string' ? candidate.refresh_token : '',
        expires_at: typeof candidate.expires_at === 'number' ? candidate.expires_at : 0,
        token_type: typeof candidate.token_type === 'string' ? candidate.token_type : 'Bearer',
        user: candidate.user,
      };
    } catch {
      return null;
    }
  }

  private toAuthSession(stored: StoredSession): AuthSession {
    const nowSeconds = Math.floor(Date.now() / 1000);
    return {
      access_token: stored.access_token,
      refresh_token: stored.refresh_token,
      expires_at: stored.expires_at,
      expires_in: Math.max(0, stored.expires_at - nowSeconds),
      token_type: stored.token_type,
      user: stored.user,
    };
  }

  private report(message: string, error: unknown): void {
    if (this.config.onError) {
      this.config.onError(message, error);
      return;
    }
    console.warn(`[lectobe-auth] ${message}`, error);
  }

  private emit(event: AuthChangeEvent, session: AuthSession | null): void {
    for (const listener of Array.from(this.listeners)) {
      try {
        listener(event, session);
      } catch (error) {
        this.report('An onAuthStateChange listener threw.', error);
      }
    }
  }

  private async postToken(body: Record<string, string>): Promise<TokenEndpointResponse> {
    if (!this.fetchImpl) {
      throw new AuthCapabilityError('cognito', 'fetch', 'No fetch implementation is available for the Cognito token exchange.');
    }
    const response = await this.fetchImpl(this.tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(body).toString(),
    });

    let payload: TokenEndpointResponse = {};
    try {
      payload = (await response.json()) as TokenEndpointResponse;
    } catch {
      payload = {};
    }

    if (!response.ok || payload.error) {
      const detail = payload.error_description || payload.error || `HTTP ${response.status}`;
      throw new Error(`Cognito token request failed: ${detail}`);
    }
    return payload;
  }

  private async refreshSession(stored: StoredSession): Promise<AuthSession | null> {
    if (!stored.refresh_token) return null;
    try {
      const payload = await this.postToken({
        grant_type: 'refresh_token',
        client_id: this.config.clientId,
        refresh_token: stored.refresh_token,
      });
      // Cognito omits refresh_token on refresh; carry the existing one forward.
      const session = this.toSession({ refresh_token: stored.refresh_token, ...payload });
      this.persist(session);
      this.emit('TOKEN_REFRESHED', session);
      return session;
    } catch (error) {
      this.report('Unable to refresh the Cognito session; signing out locally.', error);
      await this.signOut();
      return null;
    }
  }

  /* ------------------------------- Methods -------------------------------- */

  public async signInWithGoogle(options: SignInWithGoogleOptions = {}): Promise<AuthResult<OAuthSignInData>> {
    this.tracker.track(authEvent('sign_in_started', 'google'));
    const url = await this.buildAuthorizeUrl({
      identityProvider: 'Google',
      redirectTo: options.redirectTo,
    });
    this.redirect(url);
    return { data: { provider: 'cognito', url }, error: null };
  }

  /**
   * Cognito cannot exchange a password in the browser: the credential form is
   * owned by the Hosted UI. Redirecting with no `identity_provider` makes the
   * Hosted UI render its own email/password form, and the `email` argument is
   * forwarded as `login_hint` so the field arrives pre-filled.
   *
   * The resolved session is therefore always `null`; the callback route performs
   * the real exchange. The return envelope is identical to `signInWithGoogle`,
   * so `AuthContext` handles both the same way.
   */
  public async signInWithPassword(email: string, _password: string): Promise<AuthResult<CredentialSignInData>> {
    const url = await this.buildAuthorizeUrl({ loginHint: email });
    this.redirect(url);
    return { data: { user: null, session: null }, error: null };
  }

  /** Hosted UI sign-up page, pre-filled with the supplied address. */
  public async signUp(
    email: string,
    _password: string,
    options?: SignUpOptions,
  ): Promise<AuthResult<CredentialSignInData>> {
    const url = await this.buildAuthorizeUrl({
      path: '/signup',
      loginHint: email,
      redirectTo: options?.emailRedirectTo,
    });
    this.redirect(url);
    return { data: { user: null, session: null }, error: null };
  }

  /** Hosted UI forgot-password page. */
  public async resetPasswordForEmail(
    email: string,
    redirectTo?: string,
  ): Promise<AuthResult<ResetPasswordData>> {
    const url = await this.buildAuthorizeUrl({
      path: '/forgotPassword',
      loginHint: email,
      redirectTo,
    });
    this.redirect(url);
    return { data: {}, error: null };
  }

  /**
   * Not supported, and says so.
   *
   * Cognito offers passwordless email OTP only through a custom auth challenge
   * (a `CUSTOM_AUTH` Lambda trigger). Until that trigger is deployed on the user
   * pool, this cannot work, so it throws instead of resolving as a no-op. A
   * button that reports "unsupported" is strictly better than one that appears
   * to send a link and never does.
   */
  public async signInWithMagicLink(_email: string, _redirectTo?: string): Promise<AuthResult<ResetPasswordData>> {
    throw new AuthCapabilityError(
      'cognito',
      'magic_link',
      'Magic-link sign-in is not supported by this provider. Cognito requires a custom auth challenge for passwordless email OTP, which is not configured for this user pool. Use Google or email and password.',
    );
  }

  /**
   * Clears local credentials only, deliberately leaving any server-side session
   * alone. Signing out locally and revoking globally are different operations,
   * and conflating them logs a user out of every device by accident.
   *
   * The Cognito SSO session cookie is intentionally left in place; use
   * `getLogoutUrl()` when a federated sign-out is actually wanted.
   */
  public async signOut(): Promise<AuthSignOutResult> {
    this.tracker.track(authEvent('sign_out', 'unknown', { userId: this.lastKnownUserId }));
    try {
      this.storage.removeItem(`${this.prefix}session`);
      this.clearPkceState();
    } catch (error) {
      this.report('Unable to clear the stored Cognito session.', error);
    }
    this.emit('SIGNED_OUT', null);
    return { error: null };
  }

  public async getSession(): Promise<AuthSession | null> {
    if (!this.isConfigured) return null;
    const stored = this.readPersisted();
    if (!stored) return null;

    const nowSeconds = Math.floor(Date.now() / 1000);
    const leeway = this.config.refreshLeewaySeconds ?? DEFAULT_LEEWAY_SECONDS;
    if (stored.expires_at > 0 && nowSeconds >= stored.expires_at - leeway) {
      return this.refreshSession(stored);
    }
    return this.toAuthSession(stored);
  }

  public async getUser(): Promise<AuthUser | null> {
    const session = await this.getSession();
    return session?.user ?? null;
  }

  public getUserRole(user: AuthUser | null | undefined): UserRole {
    if (!user) return this.config.defaultRole ?? DEFAULT_ROLE;
    const serverRole = user.app_metadata?.role;
    if (serverRole === 'admin') return 'admin';
    if (serverRole === 'reviewer') return 'reviewer';
    if (serverRole === 'annotator') return 'annotator';
    return this.config.defaultRole ?? DEFAULT_ROLE;
  }

  public onAuthStateChange(
    callback: (event: AuthChangeEvent, session: AuthSession | null) => void,
  ): AuthSubscription {
    this.listeners.add(callback);
    return {
      unsubscribe: () => {
        this.listeners.delete(callback);
      },
    };
  }

  public async getAccessToken(): Promise<string | null> {
    const session = await this.getSession();
    return session?.access_token ?? null;
  }

  /**
   * Exchanges `?code=` for tokens, verifying `state` first.
   *
   * The state check is what stops an attacker from feeding this route a code
   * minted for their own session. When `returnedState` is not supplied it is read
   * from the current URL, which is where the Hosted UI put it.
   */
  public async exchangeCodeForSession(code: string, returnedState?: string | null): Promise<AuthSession> {
    // Two outcomes, both recorded. A failed exchange with no event is the
    // hardest kind of auth bug to see: the user says "it did not work" and
    // there is nothing to look at.
    if (!this.isConfigured) {
      throw new AuthConfigurationError('cognito', 'Cognito authentication is not configured for this environment.');
    }
    if (!code) {
      throw new AuthCapabilityError('cognito', 'code', 'No authorization code was supplied to complete sign-in.');
    }

    const verifier = this.storage.getItem(`${this.prefix}pkce_verifier`);
    if (!verifier) {
      throw new AuthCapabilityError(
        'cognito',
        'pkce',
        'The PKCE code verifier is missing from this browser session, so the authorization code cannot be exchanged. Start sign-in again in this tab.',
      );
    }

    const expectedState = this.storage.getItem(`${this.prefix}pkce_state`);
    const actualState = returnedState ?? (typeof window !== 'undefined' ? new URLSearchParams(window.location.search).get('state') : null);
    if (expectedState && actualState !== expectedState) {
      this.clearPkceState();
      throw new AuthCapabilityError(
        'cognito',
        'state',
        'The sign-in response did not match the request that started it, so it was rejected. Start sign-in again.',
      );
    }

    const payload = await this.postToken({
      grant_type: 'authorization_code',
      client_id: this.config.clientId,
      code,
      // Must match the redirect_uri sent to /oauth2/authorize.
      redirect_uri: this.storage.getItem(`${this.prefix}pkce_redirect`) || this.config.redirectUri,
      code_verifier: verifier,
    });

    this.clearPkceState();
    const session = this.toSession(payload);
    this.persist(session);
    this.emit('SIGNED_IN', session);
    return session;
  }

  /** Restores a session from raw tokens (hash-token callback style). */
  public async setSession(tokens: { access_token: string; refresh_token: string }): Promise<AuthSession> {
    if (!tokens.access_token) {
      throw new AuthCapabilityError('cognito', 'set_session', 'Cannot restore a session without an access token.');
    }
    const claims: JwtClaims = decodeJwtClaims(tokens.access_token) ?? {};
    const expiresAt = typeof claims.exp === 'number' ? claims.exp : Math.floor(Date.now() / 1000) + 3600;
    const session: AuthSession = {
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
      expires_in: Math.max(0, expiresAt - Math.floor(Date.now() / 1000)),
      expires_at: expiresAt,
      token_type: 'Bearer',
      user: this.userFromTokens(tokens.access_token, undefined),
    };
    this.persist(session);
    this.emit('SIGNED_IN', session);
    return session;
  }

  private redirect(url: string): void {
    if (typeof window !== 'undefined' && typeof window.location?.assign === 'function') {
      window.location.assign(url);
    }
  }
}

/**
 * Creates the Cognito Authorization Code + PKCE provider.
 *
 * Returns the concrete class rather than the bare `AuthProvider` so callers can
 * reach `getLogoutUrl()`. That is Cognito-specific: federated sign-out needs the
 * Hosted UI's `/logout` endpoint to clear the SSO cookie, and the generic
 * `signOut()` above intentionally does not do that.
 */
export function createCognitoProvider(config: CognitoConfig): CognitoAuthProvider {
  return new CognitoAuthProvider(config);
}
