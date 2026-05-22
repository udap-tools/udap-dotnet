<p align="center">
  <img src="artwork/UDAP_Ecosystem_Gears.png" alt="UDAP Ecosystem Gears" width="200" />
</p>

<h1 align="center">udap-dotnet</h1>

<p align="center">
  <strong>UDAP SDK and reference implementation for .NET</strong>
</p>

<p align="center">
  <a href="https://github.com/JoeShook/udap-dotnet/actions/workflows/dotnet.yml"><img src="https://github.com/JoeShook/udap-dotnet/actions/workflows/dotnet.yml/badge.svg" alt="Build" /></a>
  <a href="https://www.nuget.org/packages/Udap.Server"><img src="https://img.shields.io/nuget/v/Udap.Server?label=NuGet" alt="NuGet" /></a>
  <a href="https://github.com/JoeShook/udap-dotnet/blob/main/LICENSE"><img src="https://img.shields.io/github/license/JoeShook/udap-dotnet" alt="License" /></a>
  <a href="https://github.com/JoeShook/udap-dotnet/stargazers"><img src="https://img.shields.io/github/stars/JoeShook/udap-dotnet?style=flat" alt="Stars" /></a>
</p>

---

> **Note:** Active development happens on the [`develop`](https://github.com/JoeShook/udap-dotnet/tree/develop) branch. The `main` branch contains the latest stable release.

---

UDAP is a PKI extension profile to OAuth 2.0. One or more PKIs can be hosted by a **Community**. Joining a community results in a public/private key issued to a client. The client explicitly trusts one of the issuing certificates in that chain. Full certificate chain validation including certificate revocation to a trusted root is performed.

> - FHIR® is the registered trademark of HL7 and is used with the permission of HL7. Use of the FHIR trademark does not constitute endorsement of the contents of this repository by HL7.
> - UDAP® and the UDAP gear logo, ecosystem gears, and green lock designs are trademarks of UDAP.org.

---

## Specifications Supported

| Specification | Status | Description |
|:---|:---:|:---|
| [UDAP.org](https://www.udap.org/) | ![Complete](https://img.shields.io/badge/status-complete-brightgreen) | Base UDAP specs — server metadata, DCR, JWT client auth, authorization grants, tiered OAuth, C&E, TLS client auth. All 7 specs in [`docs/specifications/UDAP.org/`](docs/specifications/UDAP.org/) |
| [HL7 FHIR UDAP Security IG (SSRAA)](http://hl7.org/fhir/us/udap-security/) | ![Complete](https://img.shields.io/badge/status-complete-brightgreen) | Security for Scalable Registration, Authentication, and Authorization |
| [TEFCA Facilitated FHIR](https://rce.sequoiaproject.org/) | ![In Progress](https://img.shields.io/badge/status-~80%25-yellow) | Trusted Exchange Framework and Common Agreement. B2B flows, XP code validation, IAS extensions. Specs in [`docs/specifications/TEFCA/`](docs/specifications/TEFCA/) |

---

## Features at a Glance

<details open>
<summary><h3>Discovery & Registration</h3></summary>

| Feature | Status |
|:---|:---:|
| `.well-known/udap` metadata endpoint | :white_check_mark: |
| [Multiple Trust Communities](http://hl7.org/fhir/us/udap-security/discovery.html#multiple-trust-communities) | :white_check_mark: |
| [Multi-Domain Metadata](./docs/multi-domain-metadata.md) — dynamic cert selection by request URL | :white_check_mark: |
| Metadata JWT & certificate chain validation | :white_check_mark: |
| [Dynamic Client Registration](http://hl7.org/fhir/us/udap-security/registration.html) (create / update / cancel) | :white_check_mark: |
| [Certifications & Endorsements](https://www.udap.org/udap-certifications-and-endorsements-stu1.html) | :white_check_mark: |

</details>

<details open>
<summary><h3>Authorization & Authentication</h3></summary>

| Feature | Status |
|:---|:---:|
| [Consumer-Facing](http://hl7.org/fhir/us/udap-security/consumer.html) (authorization_code) | :white_check_mark: |
| [Business-to-Business](http://hl7.org/fhir/us/udap-security/b2b.html) (client_credentials) | :white_check_mark: |
| [Tiered OAuth](http://hl7.org/fhir/us/udap-security/user.html) — federated user authentication | :white_check_mark: |

</details>

<details open>
<summary><h3>Authorization Extension Objects (AEOs)</h3></summary>

| Extension | Spec | Status | Description |
|:---|:---|:---:|:---|
| `hl7-b2b` | SSRAA / TEFCA | :white_check_mark: | B2B extension for client_credentials — purpose_of_use enforcement |
| `hl7-b2b-user` | SSRAA | :white_check_mark: | B2B extension for authorization_code with user context (FHIR Person) |
| `tefca-ias` | TEFCA | :white_check_mark: | Individual Access Services — patient/user info, consent, id_token |

**Pluggable validation** via `IUdapAuthorizationExtensionValidator` with per-community rules:
- **SSRAA** — validates against HL7 v3 PurposeOfUse value set (60+ codes)
- **TEFCA** — validates against 12 TEFCA Exchange Purpose (XP) codes, enforces single purpose_of_use, SAN URI matching

</details>

<details>
<summary><h3>TEFCA-Specific Features</h3></summary>

| Feature | Status |
|:---|:---:|
| Exchange Purpose validation (all 12 XP codes) | :white_check_mark: |
| SAN URI exchange purpose matching | :white_check_mark: |
| Organization ID validation (RCE Directory format) | :white_check_mark: |
| TEFCA Authorization Error extension (consent_required) | :white_check_mark: |
| IAS flow via `tefca-ias` extension | :white_check_mark: |

</details>

---

## NuGet Packages

### Core

| Package | Description |
|:---|:---|
| [![Udap.Model](https://img.shields.io/nuget/v/Udap.Model?label=Udap.Model)](https://www.nuget.org/packages/Udap.Model) | Data models and constants (zero external dependencies) |
| [![Udap.Common](https://img.shields.io/nuget/v/Udap.Common?label=Udap.Common)](https://www.nuget.org/packages/Udap.Common) | Certificate & trust chain validation, `ICertificateStore`, `ITrustAnchorStore` |
| [![Udap.Client](https://img.shields.io/nuget/v/Udap.Client?label=Udap.Client)](https://www.nuget.org/packages/Udap.Client) | Discovery, registration, token requests via `IUdapClient` |
| [![Udap.Metadata.Server](https://img.shields.io/nuget/v/Udap.Metadata.Server?label=Udap.Metadata.Server)](https://www.nuget.org/packages/Udap.Metadata.Server) | `.well-known/udap` endpoint for resource servers |
| [![Udap.Server](https://img.shields.io/nuget/v/Udap.Server?label=Udap.Server)](https://www.nuget.org/packages/Udap.Server) | Authorization server extensions (Duende IdentityServer), DCR |
| [![Udap.Server.Storage](https://img.shields.io/nuget/v/Udap.Server.Storage?label=Udap.Server.Storage)](https://www.nuget.org/packages/Udap.Server.Storage) | EF Core persistence (SQLite, SQL Server, PostgreSQL) |
| [![Udap.TieredOAuth](https://img.shields.io/nuget/v/Udap.TieredOAuth?label=Udap.TieredOAuth)](https://www.nuget.org/packages/Udap.TieredOAuth) | Federated OAuth / external IdP integration |

### Profile-Specific

| Package | Description |
|:---|:---|
| [![Udap.Ssraa.Server](https://img.shields.io/nuget/v/Udap.Ssraa.Server?label=Udap.Ssraa.Server)](https://www.nuget.org/packages/Udap.Ssraa.Server) | SSRAA community validation (purpose_of_use value set, required extensions) |
| [![Udap.Tefca.Model](https://img.shields.io/nuget/v/Udap.Tefca.Model?label=Udap.Tefca.Model)](https://www.nuget.org/packages/Udap.Tefca.Model) | TEFCA extension models (`tefca-ias`, XP constants) |
| [![Udap.Tefca.Server](https://img.shields.io/nuget/v/Udap.Tefca.Server?label=Udap.Tefca.Server)](https://www.nuget.org/packages/Udap.Tefca.Server) | TEFCA community validation (XP codes, SAN matching) |

### Configuration Docs

- **Resource Server** — [Udap.Metadata.Server docs](./Udap.Metadata.Server/docs/README.md) | [Multi-domain metadata](./docs/multi-domain-metadata.md)
- **Client** — [Udap.Client docs](./Udap.Client/docs/README.md)
- **Authorization Server** — [Udap.Server docs](./Udap.Server/docs/README.md)

---

## Examples

See the [`examples/`](./examples) folder. Full list below.

<details open>
<summary><h3>Servers</h3></summary>

| Project | Description |
|:---|:---|
| [FhirLabsApi](./examples/FhirLabsApi/) | FHIR R4B resource server — passes all [udap.org](https://udap.org) conformance tests |
| [Udap.Auth.Server](./examples/Udap.Auth.Server/) | Authorization server with Duende IdentityServer + UDAP |
| [Udap.Proxy.Server](./examples/Udap.Proxy.Server/) | YARP reverse proxy — add UDAP security to existing FHIR servers |
| [Tefca.Proxy.Server](./examples/Tefca.Proxy.Server/) | TEFCA-configured reverse proxy |

</details>

<details>
<summary><h3>Identity Providers</h3></summary>

| Project | Description |
|:---|:---|
| [Udap.Identity.Provider](./examples/Udap.Identity.Provider/) | Tiered OAuth IdP |
| [Udap.Identity.Provider.2](./examples/Udap.Identity.Provider.2/) | Second IdP for federation testing |

</details>

<details>
<summary><h3>Admin & Tooling</h3></summary>

| Project | Description |
|:---|:---|
| [Udap.Auth.Server.Admin](./examples/Auth.Server.Admin/) | Admin UI for UDAP tables |
| [Udap.Pki.Cli](./examples/Udap.Pki.Cli/) | CLI tool for PKI operations |
| [UdapEd](https://github.com/JoeShook/UdapEd) | UDAP testing and exploration tool *(separate repository)* |

</details>

<details open>
<summary><h3>Sigil — PKI Management Tool</h3></summary>

[**Sigil**](./examples/CA/) is a modern certificate authority and PKI management tool built with .NET, Blazor Server, FluentUI v4, and PostgreSQL.

:arrow_right: [Full feature list](./examples/CA/Sigil/docs/FEATURES.md) | [Roadmap](./examples/CA/ROADMAP.md)

| Capability | Details |
|:---|:---|
| **Certificate Explorer** | Hierarchical tree view, color-coded status badges, chain validation, ASN.1 viewer |
| **Certificate Issuance** | Configurable templates (Root CA, Intermediate CA, UDAP Client, SSL Server), RSA & ECDSA |
| **Certificate Lifecycle** | Import (drag & drop, batch), renewal (re-key / re-sign), archive, revocation |
| **CRL Management** | Import, online resolution via CDP, revocation status tracking |
| **Remote Signing** | Pluggable `ISigningProvider` — HashiCorp Vault Transit and Google Cloud KMS |
| **Aspire Orchestration** | Dev / Docker / GCP launch profiles via `Sigil.AppHost` |

</details>

---

## Getting Started

### Build

```bash
dotnet restore
dotnet test _tests/Udap.PKI.Generator   # Generate test PKI (required once)
dotnet build Udap.sln
```

### Test

```bash
dotnet test _tests/Udap.Common.Tests
dotnet test _tests/UdapMetadata.Tests
dotnet test _tests/UdapServer.Tests
```

> **Tip:** Avoid `Udap.Client.System.Tests` in CI — those test against live servers.
> If SQLite DB sync issues occur, clean the `bin` folder in affected test projects.

### Run Examples Locally

```bash
# Install Tye (one-time)
dotnet tool install -g Microsoft.Tye --version "0.12.0-*" \
  --add-source https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet6/nuget/v3/index.json

# Start all services with hot reload
tye run --watch
```

### Quick Start — Tiered OAuth

```csharp
builder.Services.AddAuthentication()
    .AddTieredOAuth(options =>
    {
        options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
    });
```

---

## Database Migrations

| Project | Target |
|:---|:---|
| [UdapDb.SqlServer](./migrations/UdapDb.SqlServer/) | SQL Server |
| [UdapDb.Postgres](./migrations/UdapDb.Postgres/) | PostgreSQL |

## Key Dependencies

| Package | Purpose |
|:---|:---|
| [Duende.IdentityServer](https://duendesoftware.com/) | Identity & auth platform |
| [BouncyCastle.Cryptography](https://www.bouncycastle.org/csharp/) | X.509 PKI operations |
| [Hl7.Fhir.R4B](https://fire.ly/products/firely-net-sdk/) | FHIR models |
| [YARP](https://microsoft.github.io/reverse-proxy/) | Reverse proxy |

Versions centrally managed in [`Directory.Packages.props`](./Directory.Packages.props).
