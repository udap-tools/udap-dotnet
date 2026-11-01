# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

UDAP SDK for .NET - A comprehensive implementation of the UDAP (Unified Data Access Profiles) security framework. UDAP is a PKI extension profile to OAuth2 designed primarily for FHIR healthcare servers, enabling secure dynamic client registration and authentication.

**Repository**: https://github.com/JoeShook/udap-dotnet
**Target Frameworks**: .NET 8.0, 9.0 and 10.0 (libraries); the examples target .NET 10.0
**Primary Maintainer**: Joseph Shook (Surescripts)

## Line Endings

**CRITICAL: This is a Windows repository using CRLF line endings. Never change line endings.**

- All files in this repository use CRLF (`\r\n`) line endings
- Do NOT use the Write tool to rewrite files that only need targeted edits — use the Edit tool instead, which preserves line endings
- Do NOT use bash `sed`, `awk`, or other Unix tools that strip CRLF
- After any bulk file operations, verify with `git diff --stat` that only intended files show code changes (not just line-ending diffs)
- Files showing only CRLF→LF changes in `git diff` must be restored with `git restore <file>`

## Build Commands

```bash
# Restore dependencies
dotnet restore

# CRITICAL: Generate test PKI certificates (run FIRST, one-time setup)
dotnet test _tests/Udap.PKI.Generator

# Build solution
dotnet build Udap.sln
```

## Running Tests

```bash
# Primary test suites (run in CI)
dotnet test _tests/Udap.Common.Tests
dotnet test _tests/UdapMetadata.Tests
dotnet test _tests/UdapServer.Tests

# Run a single test by filter
dotnet test _tests/UdapServer.Tests --filter "FullyQualifiedName~ClientCredentialsUdapModeTests"

# Run specific test class
dotnet test _tests/Udap.Common.Tests --filter "ClassName=TrustChainValidatorTests"
```

**Important test notes:**
- Always run `Udap.PKI.Generator` first - all other tests depend on generated certificates
- Avoid `Udap.Client.System.Tests` in CI - these test against live servers
- If SQLite DB sync issues occur, clean the bin folder in affected test projects

### Known issue: Udap.Idi.Patient.Match.Tests and the FHIR package cache

If every validation test in `Udap.Idi.Patient.Match.Tests` fails with
`An item with the same key has already been added. Key: hl7.terminology.r4`,
the cause is the machine's FHIR package cache (`~/.fhir/packages`), not the code.

- The test fixture loads the identity-matching IG from a local `.tgz`
  (`examples/Udap.Proxy.Server/IDIPatientMatch/Packages/`), but Firely silently
  consults the global cache when building the IG's dependency closure — test
  results depend on machine state.
- Firely.Fhir.Packages **4.9.1** (pinned) crashes when two manifests declare the
  same *missing* package at different versions (raw `Dictionary.Add` writing the
  missing-deps lock file). Trigger: cache contains `hl7.fhir.us.core#6.1.0` but
  NOT `hl7.terminology.r4` / `hl7.fhir.uv.extensions.r4` — the IG wants
  terminology 6.4.0 / extensions 5.2.0, cached us.core wants 5.0.0 / 1.0.0 →
  duplicate names in the missing list → crash.
- **Fix:** install `hl7.terminology.r4#6.4.0` and `hl7.fhir.uv.extensions.r4#5.2.0`
  into `~/.fhir/packages` (tgz from `https://packages.simplifier.net/<name>/<version>`,
  extracted so the layout is `<name>#<version>/package/...`).
- **Do not bump Firely.Fhir.Packages past 4.9.1** to get the upstream fix (5.0.2):
  it pulls Hl7.Fhir.Base 6.x, which removed `BaseFhirParser`/`CommonFhirJsonSerializer`
  still used by `Udap.Proxy.Server` — that is the deferred Hl7.Fhir 6.x migration
  (rolled back in commits 881c0581 / b58d9868). Pinned combo:
  Firely.Fhir.Packages 4.9.1 + Firely.Fhir.Validation.R4B 2.7.1 + Hl7.Fhir 5.13.x.
  When the 6.x migration happens, bump Firely.Fhir.Packages ≥ 5.0.2 and this
  failure class disappears.

## Running Examples Locally

```bash
# Aspire AppHost: Postgres + pgAdmin (persistent containers), the UdapDb.Postgres seeders, and the servers
dotnet run --project examples/Udap.AppHost
```

- Every server answers on `https://udap-<name>.dev.localhost:<port>` (auth-server 5002, idp1 5055, idp2 5057,
  fhirlabs-api 7016, cert-server 5033 over http, proxy 7074, tefca-proxy 7075, mtls-proxy 7057, auth-admin 5253).
  HTTPS is the ASP.NET dev cert (SAN `*.dev.localhost`); `*.localhost` resolves to loopback with no hosts file.
- The UDAP test certificates' SANs, CRL distribution points and AIA URLs use these names. When a name changes,
  regenerate only the local PKIs (never the whole generator, never the SureFhirLabs CA):
  `dotnet test _tests/Udap.PKI.Generator --filter "FullyQualifiedName~MakeCaWithIntermediateUdapForLocalhostCommunity|FullyQualifiedName~MakeNegativeTestCerts|FullyQualifiedName~MakeMultiDomainCertsForSureFhirLabs|FullyQualifiedName~BuildTefcaTestPkiDesk"`
- New anchors leave UdapServer.Tests' SQLite files (`bin/Debug/net10.0/Udap.Idp.db.*`) seeded with the old
  ones; delete them before rerunning those tests.
- SAN URIs are written verbatim through `SubjectAltName.FromUris` (BouncyCastle), never through .NET's
  `SubjectAlternativeNameBuilder.AddUri`, which canonicalizes a path-less URI to end in `/`. SSRAA requires the
  JWT `iss` to match the SAN exactly, so a SAN never ends in a trailing slash; the helper throws if one does.
- The desktop-only generators (`MakeEndCertsForDefaultCommunity`, `MakeIdentityProviderCertificates`) reissue
  end-entity certs from the on-disk SureFhirLabs CA. `MakeEndCertsForDefaultCommunity` also overwrites the
  tracked `examples/Udap.Auth.Server/SureFhirLabs_CA.cer`; run `git restore` on it afterwards.

## Architecture

### Core SDK Libraries (NuGet Packages)

- **Udap.Model** - Data models (zero external dependencies)
- **Udap.Common** - Certificate validation, trust chain validation, `ICertificateStore`, `ITrustAnchorStore`
- **Udap.Client** - Client-side UDAP operations: discovery, registration, token requests via `IUdapClient`
- **Udap.Metadata.Server** - Server-side `.well-known/udap` endpoint implementation
- **Udap.Server** - Authorization Server integration (Duende IdentityServer extensions), DCR endpoint
- **Udap.Server.Storage** - EF Core persistence layer (SQLite, SQL Server, PostgreSQL)
- **Udap.TieredOAuth** - Federated OAuth / external IdP integration

### Key Patterns

**Certificate Management:**
- `ITrustAnchorStore` - Interface for loading trusted root certificates (file, memory, custom)
- `ICertificateStore` - Interface for loading signing certificates
- `TrustChainValidator` - Full X.509 chain validation with CRL checking

**Event-Driven Validation:**
```csharp
udapClient.Problem += (element) => { /* handle validation problem */ };
udapClient.Untrusted += (cert) => { /* handle untrusted certificate */ };
udapClient.TokenError += (msg) => { /* handle token error */ };
```

**Service Registration:**
```csharp
// Resource Server (FHIR Server)
builder.Services.AddUdapMetaDataServer(Configuration);

// Authorization Server
builder.Services.AddUdapServer(options => { ... });

// Tiered OAuth
builder.Services.AddAuthentication().AddTieredOAuth(options => { ... });
```

**Multi-Community Support:** Each community can have different trust anchors and signing algorithms, configured via `udap.metadata.options.json`.

### Example Projects (`/examples`)

- **FhirLabsApi** - Primary FHIR R4B server reference implementation (passes udap.org conformance tests)
- **Udap.Auth.Server** - Primary authorization server with Duende IdentityServer + UDAP extensions
- **Udap.Proxy.Server** - YARP-based reverse proxy to secure existing FHIR servers with UDAP
- **Udap.Identity.Provider / Udap.Identity.Provider.2** - Tiered OAuth IdP examples
- **Udap.CA** - Web UI for generating UDAP certificates
- **Sigil → Sigyll** (moved out) - The PKI management tool formerly at `examples/CA/` was renamed to **Sigyll** and extracted to its own repository: https://github.com/JoeShook/Sigyll. `examples/CA/` now contains only a pointer README.

### Test Projects (`/_tests`)

- **Udap.PKI.Generator** - Generates test PKI hierarchy (MUST run first)
- **Udap.Common.Tests** - Core certificate validation tests
- **UdapServer.Tests** - Authorization server integration tests using `UdapAuthServerPipeline`
- **UdapMetadata.Tests** - Metadata endpoint tests

### Database Migrations (`/migrations`)

- **UdapDb.SqlServer** - SQL Server migrations
- **UdapDb.Postgres** - PostgreSQL migrations

## Key Dependencies

- **Duende.IdentityServer 7.1.0** - Identity/auth platform
- **BouncyCastle.Cryptography 2.6.2** - X.509 PKI operations
- **Hl7.Fhir.Specification.R4B** - FHIR models
- **YARP 2.1.0** - Reverse proxy (for proxy examples)

Package versions are centrally managed in `Directory.Packages.props`.

## Specifications

- **UDAP.org** is the base specification for this SDK. All 7 specs are in `docs/specifications/UDAP.org/` (see `README.md` there for index). SSRAA and TEFCA are profiles layered on top of UDAP.org.
