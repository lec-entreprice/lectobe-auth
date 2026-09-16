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
 * The backend contract every provider must satisfy.
 *
 * This is the interface the existing `authService` already exposed, plus the
 * three redirect-completion methods the OAuth callback routes need
 * (`exchangeCodeForSession`, `setSession`, `getAccessToken`). It is intentionally
 * method-for-method compatible with `app-lectobe/src/services/authService.ts` so
 * consumers change an import and nothing else.
 */
export interface AuthProvider {
  /** Which backend this instance talks to. */
  readonly name: AuthProviderName;

  /** False when the deployment is missing the configuration this provider needs. */
  readonly isConfigured: boolean;

  /**
   * Starts Google sign-in. Redirects the browser to the provider and resolves
   * with the URL it navigated to.
   */
  signInWithGoogle(options?: SignInWithGoogleOptions): Promise<AuthResult<OAuthSignInData>>;

  /**
   * Starts email/password sign-in.
   *
   * Supabase performs the exchange in-page and resolves with a session. Cognito
   * cannot (the Hosted UI owns the credential form), so it redirects and
   * resolves with a null session.
   */
  signInWithPassword(email: string, password: string): Promise<AuthResult<CredentialSignInData>>;

  /** Registers a new user. */
  signUp(email: string, password: string, options?: SignUpOptions): Promise<AuthResult<CredentialSignInData>>;

  /** Sends a password-recovery email. */
  resetPasswordForEmail(email: string, redirectTo?: string): Promise<AuthResult<ResetPasswordData>>;

  /**
   * Starts passwordless email sign-in.
   *
   * Throws `AuthCapabilityError` when the provider cannot honour it. This must
   * never resolve silently: a login button that appears to work and does
   * nothing is worse than one that reports it is unsupported.
   */
  signInWithMagicLink(email: string, redirectTo?: string): Promise<AuthResult<ResetPasswordData>>;

  /** Signs the current user out and clears local credentials. */
  signOut(): Promise<AuthSignOutResult>;

  /** Reads the current session, refreshing it when it is at or near expiry. */
  getSession(): Promise<AuthSession | null>;

  /** Reads the current user, or `null` when there is no session. */
  getUser(): Promise<AuthUser | null>;

  /** Maps a user to an application role. */
  getUserRole(user: AuthUser | null | undefined): UserRole;

  /** Subscribes to sign-in, sign-out and token-refresh transitions. */
  onAuthStateChange(
    callback: (event: AuthChangeEvent, session: AuthSession | null) => void,
  ): AuthSubscription;

  /**
   * Returns the bearer token for API calls, refreshing when near expiry.
   * This is what `apiClient.ts` consumes via `getSupabaseAccessToken()`.
   */
  getAccessToken(): Promise<string | null>;

  /**
   * Completes an Authorization Code + PKCE redirect.
   *
   * Implementations must verify the `state` value that was sent on the outbound
   * redirect before exchanging the code. Skipping that check is a CSRF hole.
   */
  exchangeCodeForSession(code: string, returnedState?: string | null): Promise<AuthSession>;

  /** Restores a session from raw tokens (used by hash-token callbacks). */
  setSession(tokens: { access_token: string; refresh_token: string }): Promise<AuthSession>;
}

/**
 * Raised when a provider is structurally unable to perform an operation, as
 * opposed to a transient or credential failure. Callers surface `message`
 * directly to the user.
 */
export class AuthCapabilityError extends Error {
  public readonly capability: string;

  public readonly provider: AuthProviderName;

  constructor(provider: AuthProviderName, capability: string, message: string) {
    super(message);
    this.name = 'AuthCapabilityError';
    this.capability = capability;
    this.provider = provider;
  }
}

/** Raised when a deployment is missing the configuration a provider needs. */
export class AuthConfigurationError extends Error {
  /** Which provider the missing configuration belongs to. */
  readonly provider: AuthProviderName;

  constructor(provider: AuthProviderName, message: string) {
    super(message);
    this.name = 'AuthConfigurationError';
    this.provider = provider;
  }
}
