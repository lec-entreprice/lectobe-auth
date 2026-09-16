/**
 * `@lectobe/auth` — shared, provider-agnostic authentication for the Lectobe
 * frontends.
 *
 * One provider ships behind the interface:
 *
 *   - `cognito` — AWS Cognito Hosted UI, Authorization Code + PKCE, with Google
 *                 federation. Plain `fetch`, no extra dependencies.
 *
 * The Supabase provider was removed along with the backend. It is not deprecated
 * or dormant — the code is gone, the peer dependency is gone, and
 * `resolveAuthProviderName` rejects `supabase` by name rather than falling back
 * to it. A second provider would be a deliberate addition to this package, not a
 * value that appears in an environment variable.
 *
 * Which one is active is chosen by the consuming app via `resolveAuthProviderName`,
 * driven by `VITE_AUTH_PROVIDER`. There is no default: a missing or misspelled
 * value is reported instead of silently selecting a backend.
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

export type { AuthEvent, AuthEventInput, AuthEventType, AuthMethod, AuthTracker } from './tracking/types';
export { createTracker, authEvent } from './tracking/tracker';
export type { CreateTrackerOptions } from './tracking/tracker';
