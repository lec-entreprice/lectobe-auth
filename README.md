# @lectobe/auth

Provider-agnostic authentication for Lectobe frontends. Supabase Auth is being
removed; this package is what replaces it.

## Why it exists

Four frontends each grew their own Supabase auth — `app-lectobe` and
`work.lectobe.com` ended up with near-identical 288-line `authService.ts` files.
This replaces all of them with one implementation behind one interface.

## Install

It is a git dependency, not a published package — there is no private registry,
and a relative `file:` path does not survive a CI checkout of a single repo.

```json
"@lectobe/auth": "github:lec-entreprice/lectobe-auth#v1.0.0"
```

Pin a tag. A branch dependency means two frontends can silently run different
versions of their own auth code.

## Providers

Selected by `VITE_AUTH_PROVIDER`:

- `supabase` (default) — the existing behaviour, kept so the switch is reversible
- `cognito` — Authorization Code + PKCE against the Cognito Hosted UI

## Environment

```
VITE_AUTH_PROVIDER=cognito
VITE_COGNITO_DOMAIN=https://lectobe-maker.auth.us-east-1.amazoncognito.com
VITE_COGNITO_CLIENT_ID=...
VITE_COGNITO_REDIRECT_URI=https://studio.lectobe.com/auth/callback
```

## The Cognito flow

1. `signInWithGoogle` generates a 32-byte `code_verifier` and a `state`, stores
   both, and redirects to `/oauth2/authorize` with the S256 challenge and
   `identity_provider=Google`.
2. The user authenticates at Google, then at Cognito.
3. Cognito redirects back with `?code=...&state=...`.
4. `exchangeCodeForSession` **verifies `state` first** — skipping that is a CSRF
   hole — then POSTs the code and verifier to `/oauth2/token`.
5. Tokens are stored in `sessionStorage` and the role is read from
   `cognito:groups`.

## Deliberate differences from the Supabase flow

**Tokens live in `sessionStorage`, not `localStorage`.** A `localStorage` token
survives browser restarts and is readable by any script on the origin, so a
single XSS yields a long-lived replayable credential. The cost is real: sign-in
no longer survives a restart or a duplicated tab.

**`signInWithMagicLink` throws under Cognito.** Passwordless email needs a
custom auth challenge that is not configured. A button that silently does
nothing is worse than one that says it cannot.

## Development

```bash
npm install
npm run build
```
