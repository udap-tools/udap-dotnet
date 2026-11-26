# Plan: "Sign out everywhere"

Status: draft, 2026-11-05. Nothing implemented yet.

## Goal

A user can end every sign-in they have — every browser and device, at the IdP and at the authorization server
that federates to it through Tiered OAuth — with one button. Afterwards:

- every other browser holding a session cookie lands on a sign-in page on its next request;
- refresh tokens issued under those sessions are revoked, so no app can quietly obtain a new access token;
- relying parties that registered a back-channel logout URL are told the session ended
  ([OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)).

Access tokens already issued stay valid until they expire. That limit is documented, not solved here (see
"Access tokens" below).

## Why this needs server-side sessions

Without server-side sessions the authentication cookie *is* the session: the server cannot cancel a cookie that
is sitting in another browser. With them, each request checks the cookie against a session row; deleting the
rows signs those browsers out. idp1 and idp2 already call `AddServerSideSessions()`; the authorization server
does not.

## Phase 0: decisions before code

1. **Turn on server-side sessions in `Udap.Auth.Server`.** This changes where its users' sign-ins live (database
   rows instead of the cookie alone). Joe's call. Expect users already signed in to sign in again after the
   change; confirm during phase 3.
2. **Duende edition.** Confirm the license used for the deployed auth server and IdP includes server-side
   sessions (it is not in every Duende edition).
3. **Where the button lives.** Proposal: the IdP's and the auth server's account/grants page, shown only to a
   signed-in user, acting only on that user's own sessions. An admin "sign this user out everywhere" stays on
   the existing ServerSideSessions page and is out of scope.

## Phase 1: the button at the IdP (idp1)

- Add "Sign out everywhere" to idp1 (`examples/Udap.Identity.Provider`), and the same page in `Udap.UI` so any
  host using Udap.UI gets it.
- The handler calls `ISessionManagementService.RemoveSessionsAsync` for the current subject with
  `RemoveServerSideSession`, `RevokeTokens` and `SendBackchannelLogoutNotification` set, then signs the current
  browser out and shows the logged-out page.
- Antiforgery-protected POST; hidden when server-side sessions are not enabled (the service is null).
- `data-testid` on the button for the E2E tests.

Done when: two browsers signed in to idp1, the button in one, the other is sent to sign-in on refresh.

## Phase 2: let the auth server register a back-channel logout URL at the IdP

In Tiered OAuth the authorization server is a client of idp1, registered through UDAP dynamic client
registration. For idp1 to notify it, that registration must carry a back-channel logout URL.

- **Udap.Server (DCR endpoint):** accept the OIDC Back-Channel Logout registration metadata
  `backchannel_logout_uri` and `backchannel_logout_session_required` from the signed software statement;
  validate the URI (absolute https, no fragment, same rules as redirect URIs; loopback http only when
  `AllowLoopbackHttpRedirectUris`); store them on the Duende client (`BackChannelLogoutUri`,
  `BackChannelLogoutSessionRequired`). Advertise `backchannel_logout_supported` and
  `backchannel_logout_session_supported` in discovery when enabled.
- **Udap.TieredOAuth:** when the auth server registers itself at an IdP, include its back-channel logout URL
  (new option, off by default).
- Additive public API only (new options and constants). No existing behaviour changes unless the options are set.
- Tests in UdapServer.Tests: accepted, rejected (http, fragment, relative), stored, re-registration updates it.

## Phase 3: the auth server receives the IdP's logout and passes it on

- `Udap.Auth.Server`: `AddServerSideSessions()` (decision 1).
- **Back-channel logout endpoint for upstream IdPs** (Udap.TieredOAuth, opt-in), e.g.
  `POST /signin-tieredoauth/backchannel-logout`:
  - `logout_token` validated per the spec: signature against the IdP's JWKS (already discovered for the tiered
    flow), `iss` equals a known, enabled `tiered_clients` IdP, `aud` contains the auth server's client_id at that
    IdP, `iat` recent, `events` contains `http://schemas.openid.net/event/backchannel-logout`, `nonce` absent,
    `sub` and/or `sid` present, `jti` not replayed.
  - Map the IdP's `sub` to the local user the same way sign-in does (`FindByExternalProviderAsync(provider,
    providerUserId)` in `UdapExternalLoginService`), then call `RemoveSessionsAsync` for that local subject,
    revoking tokens and sending back-channel logout to the auth server's own clients.
  - With `sid` only: end only the matching session. Record the IdP `sid` as a session claim at sign-in so it can
    be matched.
  - Responses per the spec: 200 on success, 400 on an invalid token; `Cache-Control: no-store`.
- Same "Sign out everywhere" button on the auth server (users who signed in there directly).
- Tests: token validation negatives (bad signature, wrong `iss`/`aud`, missing `events`, `nonce` present, replayed
  `jti`, stale `iat`), the sub→local user mapping, and the cascade.

## Phase 4: end-to-end test (UdapEd.E2E)

New test `SignOutEverywhereTests`, against the local AppHost first, then the deployed servers:

1. Two separate browser contexts each complete the Tiered OAuth flow (idp1 → auth server → UdapEd), keeping
   their tokens.
2. Context A presses "Sign out everywhere" at idp1.
3. Context B: idp1 and the auth server both send it to a sign-in page; its refresh token is rejected at the
   token endpoint (`invalid_grant`).

Strict hooks, headed on request, as with the existing E2E tests.

## Access tokens

Revoking refresh tokens stops renewal; issued JWT access tokens remain usable until `exp`. Options, not part of
this plan: shorter access-token lifetimes for user flows, or reference tokens checked by the FHIR server through
introspection.

## Deployment

Phases 1–3 change idp1 and the auth server. Deploy idp1 first (the auth server's registration in phase 2 only
works against an IdP that accepts `backchannel_logout_uri`), then the auth server. idp2, the TEFCA proxy and the
mTLS proxy are not deployed and are not touched.

## OpenIddict 8.0 parity

Once the Duende version works and the E2E test passes, the same test is the spec for the OpenIddict-based auth
server and IdP:

- Sessions: OpenIddict 8.0 (preview 3 on) has a `Session` entity that binds authorizations and tokens to a
  sign-in, and an `IOpenIddictSessionManager`.
- Back-channel logout: planned for 8.0 preview 6 (openiddict-core issue #2175, open). Until it ships the
  OpenIddict spike would implement the receiver and sender itself.
- Dynamic client registration (RFC 7591/7592) is also on the preview 6 milestone (issue #2404); UDAP DCR
  (software statements) would sit on top of it or beside it.

## Open questions

- Should "sign out everywhere" at the auth server also notify the upstream IdP (front-channel / RP-initiated
  logout at idp1), or only end the auth server's own sessions?
- Do any deployed relying parties (UdapEd, FhirLabs proxy) want back-channel notifications, or is session and
  refresh-token revocation enough for them?
