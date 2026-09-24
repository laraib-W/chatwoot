# mPass SSO (oauth2-proxy ForwardAuth)

How this fork authenticates on the Moneta FOSS platform, and what a deployment has to
guarantee for it to be safe.

Activated by `AUTH_TYPE=SSO`. Unset, every path below is inert and Chatwoot behaves
exactly like upstream — local login, signup and password reset all work as shipped.

## What it replaces

Chatwoot never talks to the identity provider. Traefik asks oauth2-proxy whether each
request carries a valid session; if it doesn't, the browser goes through the mPass QR
login and comes back. Requests that reach Chatwoot carry the user's identity in
`X-Auth-Request-*` headers, and this integration logs that user in.

The app's native OIDC/SAML support is deliberately **not** used. The platform relies on
the header contract only.

```text
browser ──> traefik ──(ForwardAuth)──> oauth2-proxy ──> mpass-auth-proxy ──> Cognito
               │                            │
               │                            └─ no session: 302 to the mPass QR page
               │
               └─ valid session: request + X-Auth-Request-* headers ──> chatwoot
```

## Configuration

| Variable | Meaning |
|---|---|
| `AUTH_TYPE` | `SSO` turns the integration on. Anything else leaves upstream behaviour untouched |
| `DEFAULT_EMAIL_DOMAIN` | Domain used to synthesise an address from a bare mPass id. Required: unset, every bare-id login is refused. **Must be identical on every app in the bundle**, or the same Cognito principal becomes a different user row per app |
| `FRONTEND_URL` | The https origin the browser sees. The handoff builds its redirect from it |
| `LOGOUT_REDIRECT_LINK` | Where the app's Sign out navigates — the platform portal |
| `SESSION_TTL_SECONDS` | devise_token_auth token lifespan, so Chatwoot expires with the rest of the bundle instead of holding its own 2-month default (`config/initializers/devise_token_auth.rb`) |

## Why trusting the headers is safe

`lib/mpass/proxy_identity.rb` reads `X-Auth-Request-Email` without verifying it. That is
only sound while all three of these hold:

1. Chatwoot's port is never published — traffic can arrive only through Traefik.
2. Traefik's `strip-auth-headers` middleware deletes any client-supplied
   `X-Auth-Request-*` header **before** `mpass-auth` re-adds the verified values.
3. oauth2-proxy validates the upstream OIDC session on every ForwardAuth call.

If any one stops holding, every reader of these headers becomes a spoofing vector. The
`AUTH_TYPE` gate is the last line of defence: with it unset, the handoff controller
answers `404` no matter what headers arrive.

Deployment requirements that follow from this:

- No `ports:` on the Chatwoot service.
- Every protected router carries `strip-auth-headers`, then `security-headers`, then
  `mpass-auth` — in that order.
- Bypass routers (no `mpass-auth`) still carry `strip-auth-headers`, so a request that
  skips authentication can never assert an identity either. They are needed for
  `/health`, the precompiled assets (`/packs/`, `/vite/`, `/assets/`), and the
  end-customer surfaces that no mPass session can reach: `/widget`, `/api/v1/widget`,
  `/webhooks/`, `/public/api/`.

## Login

Chatwoot's credential is a devise_token_auth triple that the SPA persists into the
JS-readable `cw_d_session_info` cookie and replays as request headers. The server cannot
mint it in-band, so login is a redirect handoff rather than a server-side session write.

1. A browser reaches any dashboard document with an asserted identity and no session.
   `DashboardController#reconcile_mpass_identity` redirects to `/auth/sso/proxy-login`.
   Without this step first login dead-ends: the user would be served Chatwoot's own
   login form, which under SSO accepts nothing.
2. `Sso::ProxyLoginController#create` resolves or provisions the user, mints the same
   5-minute single-use `sso_auth_token` the SAML and impersonation paths use
   (`SsoAuthenticatable`), and redirects to `/app/login?email=…&sso_auth_token=…`.
3. The existing SPA login route consumes it: `v3/helpers/RouteHelper.js` clears any
   previous user's session cookie, `v3/views/login/Index.vue` auto-submits, and
   `DeviseOverrides::SessionsController` issues the devise_token_auth headers.

No new credential machinery, and no new client code for the happy path.

Two loop guards on step 1, both load-bearing: the handoff's landing page carries
`sso_auth_token` and its failure landing carries `error`, and re-entering the handoff on
either would bounce the browser until it gave up.

## Identity and provisioning

`lib/mpass/proxy_identity.rb`:

- `X-Auth-Request-Email` is the only identity source. `X-Auth-Request-User` (the Cognito
  `sub`) is never used as a fallback. The value is stripped and downcased, and the same normalisation is applied to the DB lookup.
- A value containing `@` is used as is; a bare value becomes
  `<value>@${DEFAULT_EMAIL_DOMAIN}`. Moneta's Cognito pool returns the literal
  placeholder `cognito:default_val` for the email claim, so identity usually arrives as
  a bare numeric `cognito:username`.
- Email-shape detection is `indexOf`-based, never a regex — the canonical email pattern
  backtracks polynomially on adversarial input (CodeQL `js/polynomial-redos`).
- Display name prefers `X-Auth-Request-Preferred-Username` when the local part is a bare
  number, and never persists a `sub` UUID.

`app/builders/mpass_user_builder.rb` resolves or creates the user (`User.from_email`,
exact match — never `LIKE`), then joins the oldest `Account` at role `agent` on **every**
login, not only at creation. Two deliberate differences from `SamlUserBuilder`:

- **No multi-account rejection.** A user legitimately spans accounts.
- **No role mapping.** mPass asserts identity only; elevation is an in-app action.
  `agent` also keeps SSO users out of the administrator-only onboarding wizard — the
  coupling is invisible from the Ruby side, so it is pinned by
  `spec/requests/sso/onboarding_interlock_spec.rb`.

Concurrent first-request races rescue both `RecordNotUnique` and `RecordInvalid` and fall
back to a plain read, re-raising if the row is still absent.

## Session-identity reconciliation

When the browser holds a session for user A but the proxy asserts user B, the stale
session must be flushed before anything else happens. `MpassSessionReconciliation`
defines "mismatch" once, and two paths act on it, because the credential is client-held:

| Path | Where | How |
|---|---|---|
| Document requests | `DashboardController` | Redirect through the handoff, which re-mints for B. The SPA clears the previous cookie on arrival |
| XHR | `Api::BaseController` | Cannot be redirected: evict this client's token, set `X-Mpass-Session-Flushed`, answer 401. `dashboard/helper/APIHelper.js` hard-navigates on that header |

Two properties worth keeping:

- **Header absence is never a mismatch.** Sidekiq, health probes and direct container
  hits legitimately carry no header and must not be logged out.
- **The SPA keys on the flush header, not the bare 401.** Chatwoot answers 401 for
  ordinary permission denials too, and reacting to those would log an agent out for
  opening an admin-only screen.

The XHR flush never fires for requests authenticated by an `api_access_token`: platform
and bot integrations have no user session to flush, and evicting their credential because
a browser elsewhere switched users would break unrelated integrations.

## Local-credential surfaces under SSO

Cognito owns identity, so every path that creates or changes a local credential is closed
server-side. Hiding the UI is not a control — these endpoints answer curl regardless of
what the SPA renders, and `DISABLE_USER_PROFILE_UPDATE` is honoured only by the frontend.

| Endpoint | Under `AUTH_TYPE=SSO` |
|---|---|
| `POST /auth/sign_in` without an `sso_auth_token` (password or MFA) | `404` |
| `POST`/`PUT` `/auth/password` | `404` — the `PUT` also returned a live session, a complete credential path around mPass |
| `GET`/`POST /auth/confirmation`, `POST /resend_confirmation` | `404` |
| `POST /api/v1/accounts` (self-registration) | `404` |
| `PUT /api/v1/profile` password change | rejected |
| `PUT /api/v1/profile` `email` | dropped from the permitted params — changing it breaks the header lookup and locks the user out |

`404` rather than `403`: under SSO these endpoints do not conceptually exist, and a `403`
would confirm the route is there to probe further. The gate lives in
`MpassLocalAuthGuard`; `reject_local_login_under_sso` is the login-specific variant that
lets the handoff's own POST through.

Client side, `v3/helpers/ssoRouteGuard.js` hard-redirects the signup, password-reset and
confirmation routes, the login page renders "Continue with mPass" instead of the local
form, and the profile screen hides the email field, the password section and MFA
enrolment.

## Logout

Per-app Sign out is **navigation-only**: it clears local client state and navigates to
`LOGOUT_REDIRECT_LINK`. It does not call `DELETE /auth/sign_out` and does not end the SSO
session — the next request would re-establish one from the identity header anyway, so the
call only added a failure mode. Ending the session is the portal's "Log out of all apps",
which clears the shared oauth2-proxy cookie.

Stock Chatwoot still issues the sign-out request: without SSO the devise token *is* the
session, and skipping it would leave it valid for its full lifespan.

## Tests

```bash
bundle exec rspec spec/lib/mpass spec/builders/mpass_user_builder_spec.rb spec/requests/sso
pnpm vitest run app/javascript/v3/helpers/specs/ssoRouteGuard.spec.js \
                app/javascript/dashboard/routes/index.spec.js
```

`spec/requests/sso/` carries the platform's six mandatory reconciliation tests plus the
app-specific guards: the `AUTH_TYPE≠SSO` 404, SQL-wildcard literals, the creation race,
hostile `cw_d_session_info` payloads, and the local-credential endpoint gates in both
directions (gated under SSO, untouched without it).

## Known deviations and open items

- **No corporate-tenant gate.** Plane rejects principals whose `custom:corporate_id`
  claim does not match `SMB_CORPORATE_ID`; Chatwoot has no equivalent, so any mPass
  principal in the pool that reaches the host is provisioned at `agent`, which on this
  app means access to end-customer conversations. Harmless while the deployment is
  single-tenant. Tracked in `sso-rules-moneta/apps/chatwoot/security.md` §G5.
- **`cw_d_session_info` cannot be `httpOnly`.** The SPA has to read it to build its
  request headers. `secure` is derived from the page's scheme and `sameSite: Lax` is set
  globally; the cookie carries a token whose lifetime is `SESSION_TTL_SECONDS`. This is
  architectural, not fixable here, and is recorded as a written tradeoff rather than a
  silent gap.
- **Auto-join applies no account status filter**, so a suspended account is a valid
  target. Not exploitable — the request is refused at `Current.account` resolution — but
  it writes a membership row that grants nothing.
