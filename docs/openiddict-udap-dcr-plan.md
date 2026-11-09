# Plan: UDAP dynamic client registration on OpenIddict 8.0

Status: draft, 2026-11-05. Nothing implemented yet.

## Why

OpenIddict 8.0 is adding dynamic client registration (RFC 7591) and its management protocol (RFC 7592):
[openiddict-core#2404](https://github.com/openiddict/openiddict-core/issues/2404), on the 8.0 preview 6
milestone. Its maintainer has said open registration is generally seen as a security risk, especially without an
initial access token, and wants real use cases before building it.

UDAP is such a use case, and it answers the security concern: every registration is a software statement signed
with a certificate that must chain to a trust anchor of a configured community. The registration is open (no
initial access token) but not anonymous. UDAP dynamic client registration is
[a profile of RFC 7591](specifications/UDAP.org/) used across US healthcare (FHIR, SSRAA, TEFCA).

Goal: show that UDAP registration can be built as an extension of OpenIddict's registration endpoint, find the
extension points it needs while 8.0 is still in preview, and give that feedback upstream so the final 8.0 supports
it. The result is the registration half of a UDAP authorization server that needs no commercial license.

## How UDAP registration differs from plain RFC 7591

What the extension has to be able to do, compared with an RFC 7591 request carrying client metadata as JSON:

| UDAP behaviour | Where it lives today |
|---|---|
| Request body is `software_statement` (signed JWT, `x5c` header), `udap: "1"`, optional `certifications`; client metadata comes from the statement, not top-level fields | `UdapDynamicClientRegistrationEndpoint`, `UdapDynamicClientRegistrationValidator` |
| Statement validation: signature by the `x5c[0]` key; chain to a community trust anchor (CRL checks); `iss` equals `sub` and a SAN URI of the certificate; `aud` equals the registration endpoint; `exp` within 5 minutes; `jti` not replayed (when required) | validator + `TrustChainValidator` |
| Community selection (several communities, each with its own anchors and rules) | `ICommunityRegistrationValidator`, community stores |
| Same SAN + community registers again → update the existing client, same `client_id`, `200 OK`; new → `201 Created` | endpoint + `UdapClientRegistrationStore` |
| Empty `grant_types` → cancel the registration, `200 OK` | processor (`IsCancellation`) |
| Errors `invalid_software_statement`, `unapproved_software_statement`, `invalid_client_metadata` | `UdapDynamicClientRegistrationErrors` |
| No `registration_access_token` / RFC 7592 management: the signed statement *is* the credential for updates | — |
| B2B / TEFCA authorization extensions in the statement (`hl7-b2b`, `tefca-ias`, …) checked at registration | authorization-extension validators |
| Client stores the certificate's anchor/community and SAN, not a JWKS; token-endpoint client assertions are later checked against the `x5c` chain and the registered SAN | `UdapJwtSecretValidator` |
| SSRAA 2.0: PKCE required, https-only redirect URIs (loopback http by option) | validator, `ServerSettings` |

The validation logic is our code. Its few Duende dependencies (the `jti` replay cache, the client and store
types) have direct OpenIddict or ASP.NET Core equivalents; what changes is where it plugs in and where the client
is stored.

## Approach

OpenIddict is built as an event-handler pipeline, so the extension should be a set of handlers rather than a
separate endpoint:

1. **Extract**: read `software_statement`, `udap`, `certifications` from the registration request.
2. **Validate**: run the existing UDAP validator (statement, chain, community, extensions) and reject with UDAP's
   error codes.
3. **Map**: turn the statement's claims into the registration's client metadata (redirect URIs, grant types,
   scopes, `token_endpoint_auth_method=private_key_jwt`, logo, contacts, and, with the sign-out plan,
   `backchannel_logout_uri`).
4. **Upsert / cancel**: look up an existing application by SAN + community; update it (`200`), create it
   (`201`), or delete it on empty `grant_types`; no registration access token in UDAP mode.
5. **Client authentication**: a handler for client assertions that validates the `x5c` chain to the client's
   community anchor and the registered SAN, in place of a stored JWKS.

Packaging: a new `Udap.Server.OpenIddict` package (name to be decided) beside today's Duende-based `Udap.Server`,
sharing the Duende-free validation code. Moving that shared code out of `Udap.Server` is the part that touches
public API and gets reviewed before it is done.

## Phases

0. **Now (no DCR in OpenIddict yet).** Spike an OpenIddict 8.0 preview 5 auth server in the AppHost with its own
   Postgres database; host UDAP registration as our own endpoint writing to `IOpenIddictApplicationManager`; port
   client-assertion validation. This proves storage and token issuance and the
   [sign-out everywhere plan](sign-out-everywhere-plan.md) against OpenIddict sessions.
1. **When preview 6 (or a DCR branch) appears.** Re-host registration as handlers on OpenIddict's registration
   endpoint. List each place we had to work around the design.
2. **Feedback upstream.** Turn that list into concrete, small requests on #2404 (for example: access to
   non-standard request parameters, a hook to replace the "metadata comes from the body" step, custom error codes,
   choosing `200` vs `201`, turning off registration access tokens per request, storing extra application
   properties, a client-authentication hook for `x5c` assertions). Link a public sample.
3. **Prove it.** Run UdapEd's E2E tests (client_credentials, authorization_code, Tiered OAuth) against the
   OpenIddict auth server in the AppHost; add udap.org conformance-style negative tests (bad chain, wrong `aud`,
   expired `exp`, replayed `jti`, SAN mismatch).
4. **Track 8.0 to release.** Rebase on each preview (expect schema changes and migration regeneration), switch to
   8.0 GA when it ships.

## Rules for the upstream conversation

- Joe decides what is posted on openiddict-core and posts it, or approves a draft first.
- Lead with the use case and the security answer (certificate-bound software statements), then concrete API
  asks, each backed by the sample. No requests for UDAP-specific code in OpenIddict itself: the aim is extension
  points general enough for any software-statement profile.
- OpenIddict asks feature requesters to be sponsors or contributors (the issue template checks it); consider
  sponsoring before asking.

## Open questions

- Package split: one `Udap.Server.OpenIddict` package, or OpenIddict handlers inside `Udap.Server` behind a
  separate registration method?
- Do we keep the Duende-based packages maintained in parallel, and for how long?
- `tiered_clients`, communities and anchors stay in our own tables; does the OpenIddict server share the
  `UdapDb` schema or get its own?
