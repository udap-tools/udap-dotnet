# TODO: Tiered OAuth registration-store test coverage

Deferred follow-up after fixing the Tiered OAuth "missing `client_id`" bug
(2026-06). The **fix is already in place**; this is the **regression/coverage**
work that should have caught it and didn't.

## What the bug was (context)
Tiered OAuth challenges built the IdP `/connect/authorize` redirect **without a
`client_id`**, so the IdP rejected with `invalid_request: Invalid client_id`.

Two compounding defects in the **EF** registration store path:
1. `TieredClientMapper.ToModel(null)` returns a **non-null empty** `TieredClient`,
   so `UdapClientRegistrationStore.FindTieredClientById` did `entity.ToModel()` and
   returned a **phantom non-null object** instead of `null` when no row matched.
2. The Tiered OAuth challenge looked the client up **by the wrong column** — it
   called `FindTieredClientById` (matches `ClientId`) but passed the **IdP base URL**.

The phantom object made `idpClient != null`, so the handler's
`if (idpClient == null) idpClientId = document.ClientId;` guard was skipped and the
freshly-issued `client_id` never reached the challenge URL.

**Fix applied:** `FindTieredClientById` now uses `entity?.ToModel()`; added
`FindTieredClientByIdPBaseUrl` (correct column) on the interface, EF store, and
in-memory store; `TieredOAuthAuthenticationHandler` looks up by `IdPBaseUrl`.

## Why existing tests missed it
- All `TieredOauthTests` run against **`InMemoryUdapClientRegistrationStore`**, whose
  `SingleOrDefault(...)` returns **null** on no-match (correct). The **EF**
  `UdapClientRegistrationStore` returned the phantom object. **The two stores diverged**,
  and only the in-memory one is exercised, so the suite stayed green.
- The EF store's `FindTieredClientById` / `FindTieredClientByIdPBaseUrl` /
  `UpsertTieredClient` have **no direct test coverage**.
- `MapperTests.TieredClientMapperTests.ToModel_NullEntity_ReturnsEmptyModel` actually
  **asserts the footgun** (non-null for null), giving false confidence.

## Coverage to add
1. **EF-store tests** (real `UdapDbContext` / SQLite) for the TieredClient methods:
   - `FindTieredClientById` returns **null** when no row matches; the row when it does.
   - `FindTieredClientByIdPBaseUrl` returns **null** when no row matches; the row when it does.
   - `UpsertTieredClient` creates then updates, keyed by `IdPBaseUrl`.
   (Item #1 alone would have caught the original defect.)
2. **Shared store-contract tests** run against **both** `InMemoryUdapClientRegistrationStore`
   and the EF `UdapClientRegistrationStore` so the two implementations can never diverge
   again (the divergence was the root cause).
3. **Tiered re-login / reuse test**: register once, then issue a second challenge and assert
   it **reuses** the stored client (found by `IdPBaseUrl`, no re-registration) and still
   emits `client_id`. No current test does a second/return login.
4. **Revisit `ToModel(null)`**: either change it to return `null` (and flip
   `ToModel_NullEntity_ReturnsEmptyModel` to expect null), or keep the `entity?.ToModel()`
   call-site convention and add a test asserting the **store** returns null on no-match.

## Optional cleanup noticed nearby
`UdapClient.RegisterTieredClient` / `RegisterAuthCodeClient` / `RegisterClientCredentialsClient`
log `"Unable to register..."` on an **inverted** condition
(`if (string.IsNullOrEmpty(resultDocument.GetError()))` — fires on *success*). Should be
`if (!string.IsNullOrEmpty(...))`. This actively misled debugging.
