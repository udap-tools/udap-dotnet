# Udap.Server

![UDAP logo](https://avatars.githubusercontent.com/u/77421324?s=48&v=4)

## 📦 NuGet Package: [Udap.Server](https://www.nuget.org/packages/Udap.Server)

This package adds UDAP Dynamic Client Registration (DCR) and metadata capabilities to authorization servers built on Duende IdentityServer. It provides the `.well-known/udap` metadata endpoint and the `/connect/register` DCR endpoint as extensions to the IdentityServer pipeline.

> **Note:** Duende IdentityServer requires a [license](https://duendesoftware.com/products/identityserver) for production use above $1M annual revenue.

## Features

- UDAP metadata endpoint (`.well-known/udap`)
- Dynamic Client Registration (create, update, cancel)
- Multi-community trust anchor support
- Authorization Extension Object (AEO) enforcement via `IUdapAuthorizationExtensionValidator`
- Optional `udap_community` access-token claim (see [Community Claim](#community-claim))
- Tiered OAuth support

### Profile-Specific Validation

For SSRAA or TEFCA community-specific validation rules, add the corresponding packages:

- [`Udap.Ssraa.Server`](https://www.nuget.org/packages/Udap.Ssraa.Server) — HL7 v3 PurposeOfUse enforcement
- [`Udap.Tefca.Server`](https://www.nuget.org/packages/Udap.Tefca.Server) — TEFCA Exchange Purpose (XP) code validation, SAN matching
- [`Udap.Tefca.Model`](https://www.nuget.org/packages/Udap.Tefca.Model) — TEFCA extension models (`tefca_ias`, XP constants)

## Full Example

The example below shows a typical setup. See also the [Udap.Auth.Server](../../examples/Udap.Auth.Server/) example project.

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddIdentityServer()
    .AddConfigurationStore(options =>
    {
        options.ConfigureDbContext = b => b.UseSqlite(connectionString,
            dbOpts => dbOpts.MigrationsAssembly(migrationsAssembly));
    })
    .AddOperationalStore(options =>
    {
        options.ConfigureDbContext = b => b.UseSqlite(connectionString,
            dbOpts => dbOpts.MigrationsAssembly(migrationsAssembly));
    })
    .AddResourceStore<ResourceStore>()
    .AddClientStore<ClientStore>()
    .AddTestUsers(TestUsers.Users)
    .AddUdapServer(
        options =>
        {
            var udapServerOptions = builder.Configuration.GetOption<ServerSettings>("ServerSettings");
            options.DefaultSystemScopes = udapServerOptions.DefaultSystemScopes;
            options.DefaultUserScopes = udapServerOptions.DefaultUserScopes;
            options.ForceStateParamOnAuthorizationCode = udapServerOptions
                .ForceStateParamOnAuthorizationCode;
        },
        options =>
            options.UdapDbContext = b =>
                b.UseSqlite(connectionString,
                    dbOpts =>
                        dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName)),
        baseUrl: "https://localhost:5002/connect/register"
    );

var app = builder.Build();

app.UseStaticFiles();
app.UseRouting();

app.UseUdapServer();
app.UseIdentityServer();

app.UseAuthorization();
app.MapRazorPages().RequireAuthorization();

app.Run();
```

## Community Validation Rules

UDAP supports multiple trust communities, each with its own validation rules for token requests and client registration. The validation pipeline is pluggable via `ICommunityTokenValidator` and `ICommunityRegistrationValidator`.

### Built-in profiles

Two profile packages are available:

| Package | Communities | POU codes | Max POU | Registration checks |
|---------|-----------|-----------|---------|-------------------|
| [`Udap.Ssraa.Server`](https://www.nuget.org/packages/Udap.Ssraa.Server) | SSRAA / standard UDAP | 62 HL7 v3 codes | unlimited | none |
| [`Udap.Tefca.Server`](https://www.nuget.org/packages/Udap.Tefca.Server) | TEFCA | 12 XP codes | 1 | SAN URI XP code validation |

### Registering community validators

Install the profile packages and map communities to their validation pipelines:

```csharp
// SSRAA rules for standard UDAP communities
builder.Services.AddUdapSsraaValidation(options =>
{
    options.Communities.Add("udap://fhirlabs.net");
});

// TEFCA rules (register model extensions first)
builder.Services.AddUdapTefcaExtensions();
builder.Services.AddUdapTefcaValidation(options =>
{
    options.Communities.Add("tefca://test-community");
});
```

### How it works at runtime

1. A client requests a token with authorization extensions (e.g., `hl7-b2b` with `purpose_of_use`)
2. `DefaultUdapAuthorizationExtensionValidator` resolves the client's community from the registration store
3. The validator iterates through registered `ICommunityTokenValidator` implementations until one matches via `AppliesToCommunity()`
4. The matching validator returns `CommunityValidationRules` specifying required extensions, allowed POU codes, and max POU count
5. The framework enforces those rules, then calls the validator's `ValidateAsync()` for any domain-specific checks

### Custom community validators

Implement `ICommunityTokenValidator` for custom rules:

```csharp
public class MyValidator : ICommunityTokenValidator
{
    public bool AppliesToCommunity(string communityName)
        => communityName == "udap://my-community";

    public CommunityValidationRules? GetValidationRules(string? grantType)
        => new CommunityValidationRules
        {
            RequiredExtensions = grantType == "client_credentials"
                ? new HashSet<string> { "hl7-b2b" } : null,
            AllowedPurposeOfUse = new HashSet<string> { /* your codes */ },
            MaxPurposeOfUseCount = 1
        };

    public Task<AuthorizationExtensionValidationResult> ValidateAsync(
        UdapAuthorizationExtensionValidationContext context)
        => Task.FromResult(AuthorizationExtensionValidationResult.Success());
}

// Register it
builder.Services.AddSingleton<ICommunityTokenValidator, MyValidator>();
```

See the [`Udap.Ssraa.Server`](../../Udap.Ssraa.Server/docs/README.md) and [`Udap.Tefca.Server`](../../Udap.Tefca.Server/docs/README.md) READMEs for detailed documentation on each profile.

## Client Storage During Registration

When a client registers via UDAP Dynamic Client Registration, the server creates a Duende IdentityServer `Client` entity with UDAP-specific secrets and properties. Knowing what is stored (and when it is updated) helps with admin tooling and certificate lifecycle management.

### What is stored

| Storage Type | Duende Type | Key / Type Field | Value | Expiration |
|-------------|-------------|-----------------|-------|-----------|
| Client Secret | `ClientSecret` | `UDAP_SAN_URI_ISS_NAME` | The URI Subject Alternative Name (SAN) from the client's X.509 certificate, used as the issuer identity | Certificate `NotAfter` |
| Client Secret | `ClientSecret` | `UDAP_COMMUNITY` | The community ID (integer as string) the client registered under | Certificate `NotAfter` |
| Client Secret | `ClientSecret` | `X509CertificateBase64` (`UDAP_X509_CERTIFICATE`) | Base64 DER-encoded public certificate from the client's x5c chain — stored for admin visibility (expiration monitoring, revocation checking) | Certificate `NotAfter` |
| Client Property | `ClientProperty` | `org` | Organization identifier — the query parameter **name** on the registration endpoint (see [Organization / Data Holder scoping](#organization--data-holder-scoping)) | — |
| Client Property | `ClientProperty` | `data_holder` | Data holder identifier — the query parameter **value** on the registration endpoint (see [Organization / Data Holder scoping](#organization--data-holder-scoping)) | — |
| Client Property | `ClientProperty` | `community` | The community name (URI) the client registered under — written only when `ServerSettings.IncludeCommunityClaim` is enabled (see [Community Claim](#community-claim)) | — |

Other standard Duende `Client` fields are also populated: `ClientId` (generated), `ClientName`, `AllowedGrantTypes`, `AllowedScopes`, `RedirectUris`, `LogoUri`, `RequirePkce`, `RequireDPoP`, and `Created`.

### Client identity matching

A client is uniquely identified by the combination of four values: SAN URI (`UDAP_SAN_URI_ISS_NAME`), community (`UDAP_COMMUNITY`), organization (`org`), and data holder (`data_holder`). When a registration request matches an existing client on all four, the server performs an **upsert** — updating scopes, grant types, redirect URIs, and the stored certificate rather than creating a new client. When any of the four differ, a **new** client (new `client_id`) is created.

### Organization / Data Holder scoping

The `org` and `data_holder` properties are how a deployer controls whether multiple
registrations collapse into one `client_id` or stay separate. They come from a single
query parameter on the registration endpoint, using an unusual encoding:

> The query parameter **name** becomes `org`; its **value** becomes `data_holder`.

```
https://as.example.com/connect/register?SurescriptsDirectory=BobsClinic
                                         └──── org ────┘ └ data_holder ┘
   → org = "SurescriptsDirectory", data_holder = "BobsClinic"
```

**Where the value comes from.** The server reads this query string first from the
registration software statement's `aud` claim, then falls back to the actual POST URL
(`UdapDynamicClientRegistrationValidator.ResolveOrgAndDataHolder`). Because a conformant
client sets `aud` equal to the `registration_endpoint` it discovered in your metadata,
**whatever query string you publish in `registration_endpoint` is what gets stored** as
`org`/`data_holder`.

**Default.** If no query parameter is present, both `org` and `data_holder` default to
`empty` (`DefaultOrgMap`), so all such clients share the same org/data-holder pair.

**Scope.** This query parameter is read **only** at `/connect/register`. It is ignored at
`/connect/token` and `/connect/authorize`, where the client is identified by its issued
`client_id` and authenticated by the signed `private_key_jwt` client assertion.

#### Choosing one `client_id` vs. many

Because `org` + `data_holder` are part of the [identity 4-tuple](#client-identity-matching),
they are the lever for sharing or splitting registrations across endpoints (e.g. a client
that discovers two FHIR base URLs served by the **same** authorization server and community):

- **One `client_id`, one set of scopes (per org name).** If a client should resolve to a
  single registration across endpoints that belong to the same organization, publish the
  **identical** `org` (=`data_holder`) query string in the `registration_endpoint` of every
  one of those endpoints' `.well-known/udap` documents (or omit it everywhere, so all
  default to `empty`). The four values then match, the server upserts, and the original
  `client_id` is returned — so the client ends up with **one** registration and **one**
  `AllowedScopes` set keyed to that org name, no matter how many endpoints it discovered.

- **Different scopes → register again under a different key.** If an endpoint needs a
  distinct scope set (or any distinct registration), publish a **different** `org=data_holder`
  query string for it. The differing key produces a separate `client_id` with its own
  `AllowedScopes`, independent of the first.

In short: **same `org=data_holder` key ⇒ one shared `client_id` and one scope set; a
different key ⇒ a separate `client_id` you can scope independently.** If clients are
registering more times than you expect, diff the `registration_endpoint` query strings
across your metadata documents — a mismatch (including "present at one endpoint, absent at
another") is the usual cause.

### Certificate rollover

UDAP allows certificate rotation without re-registration. When a client authenticates at the token endpoint with a new certificate (different from the one used at registration), `UdapJwtSecretValidator` invokes `RolloverClientSecrets`. This updates:

- The `Expiration` on the `UDAP_SAN_URI_ISS_NAME` and `UDAP_COMMUNITY` secrets to match the new certificate's `NotAfter`
- The `Value` and `Expiration` on the `X509CertificateBase64` secret to reflect the new certificate

Rollover only occurs if the new certificate is currently valid (`NotBefore < now < NotAfter`). Existing PKI chain validation against community trust anchors is unchanged; rollover is purely a metadata update.

### What is NOT stored

- The client's **private key** — only the public certificate is stored
- The full **certificate chain** — intermediates and anchors are managed separately in the UDAP trust store
- **Certificate thumbprint** — not stored as a separate field (can be derived from the stored certificate)

## Community Claim

UDAP clients register under a specific trust community, but by default nothing surfaces that
community to a resource server. Enabling the `IncludeCommunityClaim` setting on `ServerSettings`
turns this on, with two effects:

1. **At registration** — the community **name** (URI) is written to the client's `community`
   property (see the [storage table](#what-is-stored) above) for admin visibility.
2. **At token time** — a `udap_community` claim is added to issued access tokens for UDAP
   clients, on both the `client_credentials` and `authorization_code` flows.

The claim value is resolved from the client's stored community **id** at token time rather than
from the registration-time property, so if a community is later renamed the claim automatically
reflects the new name without re-registering the client.

```csharp
builder.Services.AddUdapServer(
    options =>
    {
        var udapServerOptions = builder.Configuration.GetOption<ServerSettings>("ServerSettings");
        options.DefaultSystemScopes = udapServerOptions.DefaultSystemScopes;
        options.DefaultUserScopes = udapServerOptions.DefaultUserScopes;
        options.IncludeCommunityClaim = udapServerOptions.IncludeCommunityClaim; // default false
    },
    /* ... */);
```

Or via configuration:

```json
{
  "ServerSettings": {
    "IncludeCommunityClaim": true
  }
}
```

The setting defaults to `false`, so existing tokens are unchanged unless it is explicitly enabled.
The emitted claim is unprefixed (`udap_community`, not `client_udap_community`).

## Database Configuration

EF Core migration projects are available for both database providers:

- [UdapDb.SqlServer](../../migrations/UdapDb.SqlServer/) — SQL Server migrations
- [UdapDb.Postgres](../../migrations/UdapDb.Postgres/) — PostgreSQL migrations

These projects create all UDAP and Duende IdentityServer tables and seed data required to run local tests. See `SeedData.cs` for details.

## Examples

- [Udap.Auth.Server](../../examples/Udap.Auth.Server/)
- [Udap.Auth.Server Deployed](https://securedcontrols.net/.well-known/udap)

---

- FHIR® is the registered trademark of HL7 and is used with the permission of HL7. Use of the FHIR trademark does not constitute endorsement of the contents of this repository by HL7.
- UDAP® and the UDAP gear logo, ecosystem gears, and green lock designs are trademarks of UDAP.org.
