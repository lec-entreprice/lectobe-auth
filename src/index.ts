/**
 * `@lectobe/auth` — shared, provider-agnostic authentication for the Lectobe
 * frontends.
 *
 * Two providers ship behind one interface:
 *
 *   - `cognito`  — AWS Cognito Hosted UI, Authorization Code + PKCE, with Google
 *                  federation. Plain `fetch`, no extra dependencies.
 *   - `supabase` — the existing behaviour, preserved method-for-method.
 *
 * Which one is active is chosen by the consuming app (see `resolveAuthProviderName`,
 * driven by `VITE_AUTH_PROVIDER`) and defaults to `supabase` so the migration is
 * reversible.
 *
 * See README.md for the flow, the environment variables and the storage model.
 */

export type {
  AuthAppMetadata,
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
  TokenStorage,
  UserRole,
} from './types';

export type { AuthProvider } from './provider';
export { AuthCapabilityError, AuthConfigurationError } from './provider';

export type { CognitoConfig } from './cognito';
export {
  CognitoAuthProvider,
  createCognitoProvider,
  createDefaultStorage,
  decodeJwtClaims,
  roleFromGroups,
} from './cognito';

export type { SupabaseConfig } from './supabase';
export {
  createSupabaseClient,
  createSupabaseProvider,
  hasValidSupabaseUrl,
  isBrowserSafeKey,
  isSupabaseConfigValid,
} from './supabase';

export type { AuthService, CreateAuthConfig } from './createAuth';
export {
  createAuthService,
  hasAllScopes,
  hasAnyScope,
  hasScope,
  parseJwtScopes,
  resolveAuthProviderName,
  validateTokenScopes,
} from './createAuth';

/* ---------------------------------------------------------------------------
 * Auth tracking
 *
 * Every authentication decision can produce an event. The tracker is optional
 * and defaults to a no-op: a provider without one still works, and a tracker
 * that fails never fails a sign-in.
 * ------------------------------------------------------------------------- */

export type { AuthEvent, AuthEventType, AuthMethod, AuthTracker } from './tracking/types';
export { createTracker, authEvent } from './tracking/tracker';
export type { CreateTrackerOptions } from './tracking/tracker';
