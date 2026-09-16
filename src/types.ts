/**
 * Provider-neutral authentication types.
 *
 * ## These types are now the only source of truth
 *
 * `AuthUser` and `AuthSession` were originally shaped as structural *subtypes*
 * of `User` and `Session` from `@supabase/supabase-js`, so each frontend's
 * `AuthContext.tsx` — which imported those types directly — kept compiling
 * through the migration without being touched.
 *
 * Supabase is gone, so that bridge is gone with it. `AuthContext.tsx` now
 * imports `AuthUser` and `AuthSession` from here, and this package no longer
 * takes a dependency on any Supabase type. The field shapes below are unchanged:
 * they describe the session the Cognito provider actually produces.
 */

/**
 * The role union. The trailing `| string` is intentional and preserved from the
 * original `authService.ts`: call sites compare against known literals, but the
 * server may return a role this package does not enumerate yet.
 */
export type UserRole = 'admin' | 'client' | 'reviewer' | 'annotator' | 'user' | string;

/**
 * Which backend is currently serving authentication.
 *
 * A single-member union rather than a bare `'cognito'`: it keeps the type
 * meaningful at call sites and makes a future provider a deliberate change to
 * this line, rather than a value that quietly appears somewhere.
 */
export type AuthProviderName = 'cognito';

/**
 * Authentication state transitions emitted by `onAuthStateChange`.
 *
 * The names are kept from the Supabase-era API so existing call sites and
 * `switch` statements did not have to change. The Cognito provider emits them.
 */
export type AuthChangeEvent =
  | 'INITIAL_SESSION'
  | 'SIGNED_IN'
  | 'SIGNED_OUT'
  | 'TOKEN_REFRESHED'
  | 'USER_UPDATED';

/**
 * Server-controlled claims, read as `app_metadata.role`.
 *
 * The field name is kept from the Supabase era because the role logic in every
 * portal reads it. The Cognito provider normalises its `cognito:groups` claim
 * into this same field, so callers never learn which provider produced it.
 */
export interface AuthAppMetadata {
  role?: string;
  provider?: string;
  providers?: string[];
  [key: string]: unknown;
}

/** The authenticated principal. */
export interface AuthUser {
  id: string;
  aud: string;
  created_at: string;
  email?: string;
  role?: string;
  app_metadata: AuthAppMetadata;
  user_metadata: Record<string, unknown>;
}

/** A live session. */
export interface AuthSession {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  expires_at?: number;
  token_type: string;
  user: AuthUser;
}

/** Returned by `onAuthStateChange`. Matches the existing `subscription` shape. */
export interface AuthSubscription {
  unsubscribe(): void;
}

/**
 * Successful result envelope. `error` is always `null` because the existing
 * contract throws on failure rather than returning an error object.
 */
export interface AuthResult<TData> {
  data: TData;
  error: null;
}

/** `signOut` resolves with no payload, exactly as the original did. */
export interface AuthSignOutResult {
  error: null;
}

/** Payload of `signInWithGoogle`. */
export interface OAuthSignInData {
  provider: AuthProviderName;
  /** The Hosted UI / provider URL the browser is being sent to. */
  url: string;
}

/** Payload of `signInWithPassword` and `signUp`. */
export interface CredentialSignInData {
  user: AuthUser | null;
  session: AuthSession | null;
}

/** Payload of `resetPasswordForEmail` / `signInWithMagicLink` (no session yet). */
export type ResetPasswordData = Record<string, never>;

/** Options accepted by `signInWithGoogle`. Preserved from the original service. */
export interface SignInWithGoogleOptions {
  redirectTo?: string;
}

/** Options accepted by `signUp`. Preserved from the original service. */
export interface SignUpOptions {
  data?: Record<string, unknown>;
  emailRedirectTo?: string;
}

/**
 * Minimal synchronous storage contract. Implemented over `sessionStorage` in
 * the browser (see `cognito.ts` for why `sessionStorage` and not `localStorage`)
 * with an in-memory fallback for SSR and test environments.
 */
export interface TokenStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}
