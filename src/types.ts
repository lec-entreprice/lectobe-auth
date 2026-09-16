/**
 * Provider-neutral authentication types.
 *
 * ## Supabase structural compatibility (important)
 *
 * `AuthUser` and `AuthSession` are deliberately shaped as structural *subtypes*
 * of the `User` and `Session` types exported by `@supabase/supabase-js`.
 *
 * Each frontend's `AuthContext.tsx` is typed as `useState<Session | null>` and
 * `useState<User | null>` against Supabase's types, and that file must keep the
 * exact shape it exposes today. Because the values returned here are assignable
 * to Supabase's types, the context keeps compiling without being touched, and
 * no `any` has to leak through this public interface to make that work.
 *
 * Concretely this means every field Supabase declares as required is declared
 * here too, with a compatible type:
 *   - `User`    requires id, aud, created_at, app_metadata, user_metadata
 *   - `Session` requires access_token, refresh_token, expires_in, token_type, user
 *
 * Do not narrow these fields (for example to `Record<string, string>`); doing so
 * breaks the assignment in `AuthContext.tsx`.
 */

/**
 * The role union. The trailing `| string` is intentional and preserved from the
 * original `authService.ts`: call sites compare against known literals, but the
 * server may return a role this package does not enumerate yet.
 */
export type UserRole = 'admin' | 'client' | 'reviewer' | 'annotator' | 'user' | string;

/** Which backend is currently serving authentication. */
export type AuthProviderName = 'cognito' | 'supabase';

/**
 * Authentication state transitions emitted by `onAuthStateChange`.
 *
 * This mirrors the subset of Supabase's `AuthChangeEvent` the frontends rely on,
 * so the callback signature stays drop-in compatible.
 */
export type AuthChangeEvent =
  | 'INITIAL_SESSION'
  | 'SIGNED_IN'
  | 'SIGNED_OUT'
  | 'TOKEN_REFRESHED'
  | 'USER_UPDATED';

/**
 * Server-controlled claims. Supabase exposed this as `app_metadata` and the
 * existing role logic reads `app_metadata.role` from it, so the Cognito provider
 * normalises its `cognito:groups` claim into this same field.
 */
export interface AuthAppMetadata {
  role?: string;
  provider?: string;
  providers?: string[];
  [key: string]: unknown;
}

/** The authenticated principal. Structurally assignable to Supabase's `User`. */
export interface AuthUser {
  id: string;
  aud: string;
  created_at: string;
  email?: string;
  role?: string;
  app_metadata: AuthAppMetadata;
  user_metadata: Record<string, unknown>;
}

/** A live session. Structurally assignable to Supabase's `Session`. */
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
