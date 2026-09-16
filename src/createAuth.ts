import type { AuthProvider } from './provider';
import type { CognitoConfig } from './cognito';
import { createCognitoProvider } from './cognito';
import type { SupabaseConfig } from './supabase';
import { createSupabaseProvider } from './supabase';
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
 * hooks consume `getAccessToken` (via `getSupabaseAccessToken()`).
 */
export interface AuthService extends AuthProvider {
  hasScope(userScopes: string[] | undefined, requiredScope: string): boolean;
  hasAllScopes(userScopes: string[] | undefined, requiredScopes: string[]): boolean;
  hasAnyScope(userScopes: string[] | undefined, requiredScopes: string[]): boolean;
  parseJwtScopes(token: string): string[];
  validateTokenScopes(token: string, requiredScopes: string[]): boolean;
}

export interface CreateAuthConfig {
  /** Which backend to use. Defaults to `supabase` so the switch is reversible. */
  provider?: AuthProviderName;
  /** Required when `provider` is `cognito`. */
  cognito?: CognitoConfig;
  /** Required when `provider` is `supabase`. */
  supabase?: SupabaseConfig;
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
 * Normalises the `VITE_AUTH_PROVIDER` value.
 *
 * Anything other than an explicit `cognito` resolves to `supabase`, so a typo
 * or an unset variable fails safe onto the provider that is currently live.
 */
export function resolveAuthProviderName(raw: unknown): AuthProviderName {
  return typeof raw === 'string' && raw.trim().toLowerCase() === 'cognito' ? 'cognito' : 'supabase';
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
 * Reads the array-shaped `scopes` claim used by Supabase. Cognito instead emits
 * a space-delimited `scope` string on the access token, so that form is
 * accepted too; without it every Cognito token would report zero scopes.
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
export function createAuthService(config: CreateAuthConfig = {}): AuthService {
  const providerName = config.providerName ?? 'supabase';

  const provider: AuthProvider = config.provider ?? (providerName === 'cognito'
    ? createCognitoProvider(config.cognito ?? { region: '', userPoolId: '', clientId: '', domain: '', redirectUri: '' })
    : createSupabaseProvider(config.supabase ?? { url: '', anonKey: '', callbackUrl: '', recoveryCallbackUrl: '' }));

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
