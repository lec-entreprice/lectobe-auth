import type { AuthProvider } from './provider';
import type {
  AuthChangeEvent,
  AuthProviderName,
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
  UserRole,
} from './types';

/**
 * The full service surface: the provider contract plus the pure scope/RBAC
 * helpers the existing `authService` exported.
 *
 * `AuthContext.tsx` consumes the first block; `apiClient.ts` and the workspace
 * hooks consume `getAccessToken`.
 */
export interface AuthService extends AuthProvider {
  hasScope(userScopes: string[] | undefined, requiredScope: string): boolean;
  hasAllScopes(userScopes: string[] | undefined, requiredScopes: string[]): boolean;
  hasAnyScope(userScopes: string[] | undefined, requiredScopes: string[]): boolean;
  parseJwtScopes(token: string): string[];
  validateTokenScopes(token: string, requiredScopes: string[]): boolean;
}

export interface CreateAuthConfig {
  /**
   * The provider to wrap.
   *
   * Injected rather than constructed here from a name. The app's auth client
   * builds it, because only the app knows its redirect URIs, its logout URI and
   * how it reports errors. A second provider constructed inside this factory
   * would be a different instance with different configuration, and the two
   * would drift apart without anything failing.
   *
   * This replaces an earlier `provider?: AuthProviderName` plus `cognito?`
   * pair, which read as "pass a name and I will build it" but was called with a
   * provider object — so the object was discarded and a second, differently
   * configured provider was silently constructed in its place.
   */
  provider: AuthProvider;
  /** Role applied when the provider yields nothing. Defaults to `client`. */
  defaultRole?: UserRole;
  /**
   * Per-application role policy.
   *
   * The two portals disagree about the default (the client portal uses
   * `client`, the workforce portal uses `annotator`), so each app supplies its
   * own resolver. When omitted the provider's resolver is used.
   */
  getUserRole?: (user: AuthUser | null | undefined) => UserRole;
  onError?: (message: string, error: unknown) => void;
}

/**
 * Resolves the `VITE_AUTH_PROVIDER` value to a provider name.
 *
 * There is deliberately NO default.
 *
 * Until now, anything that was not exactly `cognito` resolved to `supabase` —
 * so a typo, a missing variable, or a case mismatch silently selected a backend
 * instead of reporting the mistake. That is precisely the failure mode this
 * migration was about: a deployment that looked configured and was not. The old
 * comment called it "fails safe onto the provider that is currently live"; it
 * failed *silent*, which is a different thing, and it hid a broken configuration
 * behind an app that appeared to work.
 *
 * A missing or unrecognised value is a deployment error, and is reported as one.
 */
export function resolveAuthProviderName(raw: unknown): AuthProviderName {
  const value = typeof raw === 'string' ? raw.trim().toLowerCase() : '';

  if (value === 'cognito') return 'cognito';

  if (value === 'supabase') {
    throw new Error(
      'VITE_AUTH_PROVIDER="supabase". The Supabase auth backend has been removed: ' +
        'the platform authenticates exclusively through AWS Cognito. ' +
        'Set VITE_AUTH_PROVIDER="cognito".',
    );
  }

  throw new Error(
    `VITE_AUTH_PROVIDER is ${value === '' ? 'unset' : `"${String(raw)}"`}. Expected "cognito". ` +
      'There is no default — a missing or misspelled value must not silently choose an auth backend.',
  );
}

/* -------------------------------------------------------------------------- */
/* Scope & RBAC helpers (pure, provider-agnostic)                             */
/* -------------------------------------------------------------------------- */

/** True when `userScopes` grants `requiredScope`, honouring `*` and `domain:*`. */
export function hasScope(userScopes: string[] | undefined, requiredScope: string): boolean {
  if (!userScopes || !Array.isArray(userScopes)) return false;
  if (userScopes.includes('*')) return true;
  if (userScopes.includes(requiredScope)) return true;
  if (requiredScope.includes(':')) {
    const domain = requiredScope.split(':')[0];
    if (userScopes.includes(`${domain}:*`)) return true;
  }
  return false;
}

/** True when `userScopes` contains every required scope. */
export function hasAllScopes(userScopes: string[] | undefined, requiredScopes: string[]): boolean {
  return requiredScopes.every((scope) => hasScope(userScopes, scope));
}

/** True when `userScopes` contains at least one required scope. */
export function hasAnyScope(userScopes: string[] | undefined, requiredScopes: string[]): boolean {
  return requiredScopes.some((scope) => hasScope(userScopes, scope));
}

/**
 * Decodes a JWT payload without external dependencies to extract scopes.
 *
 * Cognito emits a space-delimited `scope` string on the access token. The
 * array-shaped `scopes` claim is also accepted, because custom authorizers in
 * this platform inject it; without that branch those tokens would report zero
 * scopes and every scope check would fail closed.
 */
export function parseJwtScopes(token: string): string[] {
  if (!token || typeof token !== 'string') return [];
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return [];
    const base64Url = parts[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=');
    const jsonPayload = decodeURIComponent(
      atob(padded)
        .split('')
        .map((char) => `%${`00${char.charCodeAt(0).toString(16)}`.slice(-2)}`)
        .join(''),
    );
    const payload = JSON.parse(jsonPayload) as { scopes?: unknown; scope?: unknown };
    if (Array.isArray(payload.scopes)) {
      return payload.scopes.filter((scope): scope is string => typeof scope === 'string');
    }
    if (typeof payload.scope === 'string') {
      return payload.scope.split(/\s+/).filter((scope) => scope.length > 0);
    }
    return [];
  } catch (err) {
    console.warn('[authService] Failed to parse JWT payload for scopes:', err);
    return [];
  }
}

/** True when the token carries every required scope. */
export function validateTokenScopes(token: string, requiredScopes: string[]): boolean {
  return hasAllScopes(parseJwtScopes(token), requiredScopes);
}

/* -------------------------------------------------------------------------- */
/* Factory                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Builds the application-facing auth service.
 *
 * The returned object is a plain set of closures rather than a class, so its
 * methods can be destructured (`export const signOut = authService.signOut`)
 * without losing their receiver, which is how the existing barrel exported them.
 */
export function createAuthService(config: CreateAuthConfig): AuthService {
  // The caller's provider, used as given.
  //
  // The previous version read `config.providerName` — a field the type does not
  // declare, so it was always `undefined` — and then defaulted to `supabase`
  // regardless of what the caller passed. A configuration that looks honoured
  // and is not is worse than one that is missing: nothing errors, and the
  // symptom is "I set the provider and nothing changed".
  //
  // There is no fallback now. A missing provider is a programming error in the
  // caller, and inventing one is how the silent default got in.
  const provider = config.provider;
  if (!provider) {
    throw new Error(
      'createAuthService requires an explicit `provider`. ' +
        'Build it in the app’s auth client and pass it in.',
    );
  }

  const resolveRole = (user: AuthUser | null | undefined): UserRole =>
    config.getUserRole ? config.getUserRole(user) : provider.getUserRole(user);

  return {
    name: provider.name,
    isConfigured: provider.isConfigured,

    signInWithGoogle: (options?: SignInWithGoogleOptions): Promise<AuthResult<OAuthSignInData>> =>
      provider.signInWithGoogle(options),

    signInWithPassword: (email: string, password: string): Promise<AuthResult<CredentialSignInData>> =>
      provider.signInWithPassword(email, password),

    signUp: (email: string, password: string, options?: SignUpOptions): Promise<AuthResult<CredentialSignInData>> =>
      provider.signUp(email, password, options),

    resetPasswordForEmail: (email: string, redirectTo?: string): Promise<AuthResult<ResetPasswordData>> =>
      provider.resetPasswordForEmail(email, redirectTo),

    signInWithMagicLink: (email: string, redirectTo?: string): Promise<AuthResult<ResetPasswordData>> =>
      provider.signInWithMagicLink(email, redirectTo),

    signOut: (): Promise<AuthSignOutResult> => provider.signOut(),

    getSession: (): Promise<AuthSession | null> => provider.getSession(),

    getUser: (): Promise<AuthUser | null> => provider.getUser(),

    getUserRole: (user: AuthUser | null | undefined): UserRole => resolveRole(user),

    onAuthStateChange: (
      callback: (event: AuthChangeEvent, session: AuthSession | null) => void,
    ): AuthSubscription => provider.onAuthStateChange(callback),

    getAccessToken: (): Promise<string | null> => provider.getAccessToken(),

    exchangeCodeForSession: (code: string, returnedState?: string | null): Promise<AuthSession> =>
      provider.exchangeCodeForSession(code, returnedState),

    setSession: (tokens: { access_token: string; refresh_token: string }): Promise<AuthSession> =>
      provider.setSession(tokens),

    hasScope,
    hasAllScopes,
    hasAnyScope,
    parseJwtScopes,
    validateTokenScopes,
  };
}

/* -------------------------------------------------------------------------- */
/* Reading user metadata                                                      */
/* -------------------------------------------------------------------------- */

/**
 * Reads a user-metadata value, but only when it is actually a string.
 *
 * `AuthUser.user_metadata` is `Record<string, unknown>`, which is correct — the
 * provider controls what lands there and it is not a fixed schema. But every
 * call site wants a string to display, and there were eleven of them doing:
 *
 *     user?.user_metadata?.full_name || 'Client'
 *
 * The left operand is `unknown`, so the expression's type is not `string`. Two
 * sites "fixed" it with `as string`, which asserts a shape nothing verified: a
 * provider that returned a number or an object for `full_name` would render
 * `[object Object]` and type-check perfectly.
 *
 * This checks. A non-string, an empty string and a missing key all yield
 * `undefined`, so the caller's own fallback applies.
 */
export function userMetadataString(
  user: AuthUser | null | undefined,
  key: string,
): string | undefined {
  const value = user?.user_metadata?.[key];
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}
