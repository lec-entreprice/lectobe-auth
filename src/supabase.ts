import { createClient } from '@supabase/supabase-js';
import type { AuthChangeEvent as SupabaseAuthChangeEvent, Session as SupabaseSession, SupabaseClient, User as SupabaseUser } from '@supabase/supabase-js';
import type { AuthProvider } from './provider';
import { AuthConfigurationError } from './provider';
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
  UserRole,
} from './types';

export interface SupabaseConfig {
  /** `VITE_SUPABASE_URL` */
  url: string;
  /** `VITE_SUPABASE_ANON_KEY` — must be a browser-safe (anon/publishable) key. */
  anonKey: string;
  /** Absolute `/auth/callback` URL for this portal. */
  callbackUrl: string;
  /** Absolute `/auth/callback?mode=recovery` URL for this portal. */
  recoveryCallbackUrl: string;
  /** App-supplied redirect allow-list. Defaults to returning the fallback. */
  sanitizeRedirect?: (candidate: string | undefined, fallback: string) => string;
  /** Role applied when `app_metadata.role` is absent. Defaults to `client`. */
  defaultRole?: UserRole;
  /**
   * Options passed through to the Supabase client's `auth` config.
   *
   * Read four times below and previously undeclared, so every one of those reads
   * was against a property the type said did not exist — the build passed only
   * because the frontend buildspec runs `tsc || true`.
   *
   * The portals pin `detectSessionInUrl: false` here so the callback route owns
   * the code exchange and a second automatic exchange cannot race it. That is
   * application policy, which is why it is supplied rather than hardcoded.
   */
  authOptions?: {
    flowType?: 'implicit' | 'pkce';
    persistSession?: boolean;
    autoRefreshToken?: boolean;
    detectSessionInUrl?: boolean;
  };
  /** Pre-built client to reuse, so a frontend creates exactly one. */
  client?: SupabaseClient | null;
  onError?: (message: string, error: unknown) => void;
  onWarn?: (message: string, error?: unknown) => void;
}

/* -------------------------------------------------------------------------- */
/* Configuration guards (preserved verbatim from the frontends)               */
/* -------------------------------------------------------------------------- */

function isLocalSupabaseUrl(value: URL): boolean {
  return ['localhost', '127.0.0.1', '[::1]', '::1'].includes(value.hostname);
}

/** Rejects malformed, credentialed and non-HTTPS (outside localhost) URLs. */
export function hasValidSupabaseUrl(value: string): boolean {
  try {
    const parsed = new URL(value);
    const allowedProtocol = parsed.protocol === 'https:' || (parsed.protocol === 'http:' && isLocalSupabaseUrl(parsed));
    return allowedProtocol && Boolean(parsed.hostname) && !parsed.username && !parsed.password && !parsed.search && !parsed.hash;
  } catch {
    return false;
  }
}

/**
 * Rejects privileged keys. A `service_role` / `sb_secret_` key in a browser
 * bundle is a full-database compromise, so it is refused rather than warned
 * about.
 */
export function isBrowserSafeKey(value: string): boolean {
  if (!value || /service_role|sb_secret_/i.test(value)) return false;
  if (value.startsWith('sb_publishable_')) return true;
  const parts = value.split('.');
  if (parts.length !== 3) return false;
  try {
    const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const paddedPayload = payload.padEnd(Math.ceil(payload.length / 4) * 4, '=');
    const role = (JSON.parse(atob(paddedPayload)) as { role?: unknown }).role;
    return role === 'anon';
  } catch {
    return false;
  }
}

/** True when both the URL and the key are safe to ship to a browser. */
export function isSupabaseConfigValid(config: Pick<SupabaseConfig, 'url' | 'anonKey'>): boolean {
  return hasValidSupabaseUrl(config.url) && isBrowserSafeKey(config.anonKey);
}

/**
 * Builds the Supabase client, or `null` when the deployment is unconfigured.
 *
 * A missing deployment configuration is an unavailable integration, not a
 * reason to construct a fake client or point at a placeholder host. Callers use
 * `isSupabaseConfigured` as their unavailable-state guard.
 */
export function createSupabaseClient(config: SupabaseConfig): SupabaseClient | null {
  if (config.client !== undefined) return config.client;
  if (!isSupabaseConfigValid(config)) return null;

  try {
    return createClient(config.url, config.anonKey, {
      auth: {
        // Keep the browser OAuth flow on the authorization-code + PKCE path.
        // The callback route explicitly exchanges the returned code for a
        // session. Avoid a second URL-detection exchange racing that route.
        flowType: config.authOptions?.flowType ?? 'pkce',
        persistSession: config.authOptions?.persistSession ?? true,
        autoRefreshToken: config.authOptions?.autoRefreshToken ?? true,
        detectSessionInUrl: config.authOptions?.detectSessionInUrl ?? false,
      },
    });
  } catch (error) {
    config.onError?.('Failed to initialize Supabase client:', error);
    return null;
  }
}

/* -------------------------------------------------------------------------- */
/* Provider                                                                   */
/* -------------------------------------------------------------------------- */

/**
 * Wraps the existing Supabase behaviour behind `AuthProvider`.
 *
 * This is the preserved implementation: every method below performs the same
 * call, in the same order, with the same guards and the same error propagation
 * as `app-lectobe/src/services/authService.ts` did, so the default provider
 * remains byte-for-byte equivalent in behaviour.
 */
class SupabaseAuthProvider implements AuthProvider {
  public readonly name = 'supabase' as const;

  public readonly isConfigured: boolean;

  private readonly config: SupabaseConfig;

  private readonly client: SupabaseClient | null;

  constructor(config: SupabaseConfig) {
    this.config = config;
    this.client = createSupabaseClient(config);
    this.isConfigured = this.client !== null;
  }

  private requireClient(): SupabaseClient {
    if (!this.client) {
      throw new AuthConfigurationError('supabase', 'Supabase authentication is not configured for this environment.');
    }
    return this.client;
  }

  private get defaultRole(): UserRole {
    return this.config.defaultRole ?? 'client';
  }

  private sanitize(candidate: string | undefined, fallback: string): string {
    if (this.config.sanitizeRedirect) return this.config.sanitizeRedirect(candidate, fallback);
    return fallback;
  }

  private report(message: string, error: unknown): void {
    if (this.config.onError) {
      this.config.onError(message, error);
      return;
    }
    console.error(message, error);
  }

  private warn(message: string, error?: unknown): void {
    if (this.config.onWarn) {
      this.config.onWarn(message, error);
      return;
    }
    console.warn(message, error);
  }

  private toSession(session: SupabaseSession): AuthSession {
    return session;
  }

  public async signInWithGoogle(options: SignInWithGoogleOptions = {}): Promise<AuthResult<OAuthSignInData>> {
    const { redirectTo } = options;
    const redirectUrl = this.sanitize(redirectTo, this.config.callbackUrl);
    const client = this.requireClient();

    const { data, error } = await client.auth.signInWithOAuth({
      provider: 'google',
      options: { redirectTo: redirectUrl },
    });

    if (error) {
      this.report('[authService] Google OAuth Sign-in error:', error.message);
      throw error;
    }

    return { data: { provider: 'supabase', url: data?.url ?? redirectUrl }, error: null };
  }

  public async signInWithPassword(email: string, password: string): Promise<AuthResult<CredentialSignInData>> {
    const client = this.requireClient();
    const { data, error } = await client.auth.signInWithPassword({ email, password });

    if (error) {
      this.report('[authService] Email/Password Sign-in error:', error.message);
      throw error;
    }

    return {
      data: {
        user: data.user,
        session: data.session ? this.toSession(data.session) : null,
      },
      error: null,
    };
  }

  public async signUp(
    email: string,
    password: string,
    options?: SignUpOptions,
  ): Promise<AuthResult<CredentialSignInData>> {
    const client = this.requireClient();
    const { emailRedirectTo, data: userData } = options || {};

    const { data, error } = await client.auth.signUp({
      email,
      password,
      options: {
        data: userData,
        emailRedirectTo: this.sanitize(emailRedirectTo, this.config.callbackUrl),
      },
    });

    if (error) {
      this.report('[authService] Sign-up error:', error.message);
      throw error;
    }

    return {
      data: {
        user: data.user,
        session: data.session ? this.toSession(data.session) : null,
      },
      error: null,
    };
  }

  public async resetPasswordForEmail(
    email: string,
    redirectTo?: string,
  ): Promise<AuthResult<ResetPasswordData>> {
    const client = this.requireClient();
    const { error } = await client.auth.resetPasswordForEmail(email, {
      redirectTo: this.sanitize(redirectTo, this.config.recoveryCallbackUrl),
    });

    if (error) {
      this.report('[authService] Password reset error:', error.message);
      throw error;
    }

    return { data: {}, error: null };
  }

  public async signInWithMagicLink(
    email: string,
    redirectTo?: string,
  ): Promise<AuthResult<ResetPasswordData>> {
    const client = this.requireClient();
    const { error } = await client.auth.signInWithOtp({
      email,
      options: {
        emailRedirectTo: this.sanitize(redirectTo, this.config.callbackUrl),
      },
    });

    if (error) {
      this.report('[authService] Magic Link Sign-in error:', error.message);
      throw error;
    }

    return { data: {}, error: null };
  }

  public async signOut(): Promise<AuthSignOutResult> {
    if (!this.client) {
      this.warn('[authService] Supabase client not initialized.');
      return { error: null };
    }

    const { error } = await this.client.auth.signOut({ scope: 'local' });
    if (error) {
      this.report('[authService] Sign-out error:', error.message);
      throw error;
    }
    return { error: null };
  }

  public async getSession(): Promise<AuthSession | null> {
    if (!this.client) return null;
    const { data: { session }, error } = await this.client.auth.getSession();
    if (error) {
      this.report('[authService] Error fetching session:', error.message);
      return null;
    }
    return session ? this.toSession(session) : null;
  }

  public async getUser(): Promise<AuthUser | null> {
    if (!this.client) return null;
    const { data: { user }, error } = await this.client.auth.getUser();
    if (error) {
      this.report('[authService] Error fetching user:', error.message);
      return null;
    }
    return (user as SupabaseUser | null) as AuthUser | null;
  }

  /**
   * Reads a role only from Supabase `app_metadata`, which is server-controlled.
   * Only an explicit `admin` / `reviewer` / `annotator` is honoured; everything
   * else falls back to the configured default rather than inventing a role in
   * the browser.
   */
  public getUserRole(user: AuthUser | null | undefined): UserRole {
    if (!user) return this.defaultRole;
    const serverRole = user.app_metadata?.role;
    if (serverRole === 'admin') return 'admin';
    if (serverRole === 'reviewer') return 'reviewer';
    if (serverRole === 'annotator') return 'annotator';
    return this.defaultRole;
  }

  public onAuthStateChange(
    callback: (event: AuthChangeEvent, session: AuthSession | null) => void,
  ): AuthSubscription {
    if (!this.client) {
      return { unsubscribe: () => {} };
    }

    const { data: { subscription } } = this.client.auth.onAuthStateChange(
      (event: SupabaseAuthChangeEvent, session: SupabaseSession | null) => {
        callback(event as AuthChangeEvent, session ? this.toSession(session) : null);
      },
    );

    return subscription;
  }

  public async getAccessToken(): Promise<string | null> {
    const session = await this.getSession();
    return session?.access_token ?? null;
  }

  public async exchangeCodeForSession(code: string, _returnedState?: string | null): Promise<AuthSession> {
    const client = this.requireClient();
    const exchange = await client.auth.exchangeCodeForSession(code);
    if (exchange.error) throw exchange.error;
    if (!exchange.data.session) {
      throw new Error('The authorization code was accepted but no session was returned.');
    }
    return this.toSession(exchange.data.session);
  }

  public async setSession(tokens: { access_token: string; refresh_token: string }): Promise<AuthSession> {
    const client = this.requireClient();
    const restored = await client.auth.setSession({
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
    });
    if (restored.error) throw restored.error;
    if (!restored.data.session) {
      throw new Error('The supplied tokens were accepted but no session was returned.');
    }
    return this.toSession(restored.data.session);
  }
}

/** Creates the preserved Supabase provider. */
export function createSupabaseProvider(config: SupabaseConfig): AuthProvider {
  return new SupabaseAuthProvider(config);
}
