# Sigil — Implemented Features

**Stack**: .NET 10, Blazor Server (InteractiveServer), FluentUI v4, PostgreSQL, BouncyCastle, Serilog, Aspire
**Location**: `examples/CA/` in udap-dotnet repo (see Architecture section for full project structure)

---

## Phase 1: Foundation (Complete)

### Communities
- CRUD page for PKI communities (multi-tenant hierarchy separator)
- Each community is an independent PKI namespace with its own CA tree
- Community selector always visible in Explorer header for quick switching

### Certificate Explorer
- **Tree view** with hierarchical display: Root CA → Intermediate CA → End-entity certs → CRLs
- **Detail panel** with draggable splitter (FluentSplitter) between tree and details
- Color-coded status badges: Valid, Expiring, Expired, Revoked, Untrusted
- CRL time status badges: Valid, Expiring Soon, Expired
- Collapsible tree items (InitiallyExpanded)

### Certificate Detail Panel
- General information: Subject, Issuer, Serial, Thumbprint, Validity, Algorithm, Key info, Private key status
- Subject Alternative Names display
- Chain validation with trust anchor detection
- Extension table with resizable columns (JS interop column drag)
- ASN.1 structure viewer (collapsible tree with OID friendly names)
- Operational/Trust Only badges based on private key availability

### Issuer Navigation
- Clickable link icon on the Issuer field to load issuer certificate details
- Issuer detail panel appears below the primary cert details with blue left border
- Chain walking: click issuer's issuer to navigate up the chain
- Issuer lookup via AKI → SKI matching with DN fallback
- **Tree highlighting** via JS shadow DOM styling:
  - Green highlight on selected cert's tree item
  - Blue highlight on issuer cert's tree item
  - Highlights target the `positioning-region` inside FluentTreeItem's shadow DOM
- Detail panel title bars color-coded to match tree highlights

### Certificate Import
- Drag & drop file upload (.pfx, .p12, .cer, .crt, .pem, .der, .crl)
- Folder upload with recursive file discovery (up to 500 files)
- **Auto-detection** of certificate role (Root CA, Intermediate CA, End-entity) via BasicConstraints
- PEM fallback for .cer files containing PEM text
- **Batch import** with role-detection pre-sort (Root → Intermediate → End-entity → CRL) and retry pass
- Password dialog queue for PFX files
- Confirm import dialog with parsed cert preview
- **Chain matching** via AKI/SKI, with DN + BouncyCastle signature verification fallback
- **CA selection dialog** for unmatched/untrusted certs (for test harness scenarios)
- Duplicate detection and merge (public-only → PFX upgrade)

### CRL Handling
- CRL import with signature validation against issuing CA
- CRL number tracking and next update dates
- Revocation entry parsing with reason codes
- CRL detail panel with revoked certificate list

### Chain Validation
- Full chain validation with revocation checking
- **Online CRL resolution** via CDP (CRL Distribution Points) extension
- Parallel async CRL downloads with 5-second timeout per download
- Pre-computed validation results during tree load (batch validation)
- On-demand revalidation button ("Revalidate" — uses stored CRLs from database)
- **Online-only validation** ("Validate Online" — resolves intermediates via AIA, CRLs via CDP only, no database CRLs)
  - Simulates external relying party behavior
  - Issuer resolution via AIA `caIssuers` OID (1.3.6.1.5.5.7.48.2)
  - "Issuer resolved via AIA" annotation in chain display
  - CRL check runs after issuer resolution (CRL signature verified against issuer's public key)
- CRL status indicators: CRL OK, Revoked, No CRL, CRL Expired, CRL Fetch Failed
- Downloaded CRL source URL display

### Download Endpoints
- `GET /api/ca/{id}/download/cer` — PEM-encoded CA certificate
- `GET /api/ca/{id}/download/pfx` — CA certificate with private key
- `GET /api/ca/{id}/download/pem` — PEM format (.pem extension)
- `GET /api/issued/{id}/download/cer` — PEM-encoded end-entity certificate
- `GET /api/issued/{id}/download/pfx` — End-entity with private key
- `GET /api/issued/{id}/download/pem` — PEM format (.pem extension)
- `GET /api/crl/{id}/download` — DER-encoded CRL

### Dashboard (Home Page)
- **Quick stats**: Community count, CA count, Issued cert count, Template count
- **Community health cards**: Per-community summary with CA/Issued counts, expired/expiring/overdue CRL counts, healthy indicator
- **Expiring certificates table**: Certs within 60 days of expiry (not yet expired), sorted by NotAfter
- **Expired certificates table**: Most recent 20 expired certs
- **Overdue CRLs table**: CRLs past NextUpdate, sorted by days overdue
- **Revoked certificate count**
- **Deep-linking**: Clickable names navigate to `/explorer/{communityId}?thumbprint={thumbprint}` for auto-selection
- All tables filter out archived items

### Certificate Management
- **Rename**: Inline rename of certificate display name (pencil icon, Enter to save, Escape to cancel)
- **Archive** (soft-delete): Hides certificate/CRL from tree, preserves in database with `IsArchived` + `ArchivedAt` timestamp
- **Permanent delete**: Full removal from database with cascade cleanup (CRLs, revocations)
  - Safety check: CAs with children or issued certs cannot be deleted until dependents are removed/moved
- **Move**: Relocate certificates between communities with AKI/SKI chain re-linking

### Pre-issuance Validation
- **CDP/AIA URL validation**: HEAD requests to verify endpoints are reachable (5s timeout)
- Warns about missing CDP/AIA when template has them enabled
- Warns about unreachable endpoints with HTTP status or error details
- User can proceed anyway or cancel to fix URLs
- **Template URL token expansion**: `{CAName}` replaced with issuing CA name in CDP/AIA URL templates

### Issuer Verification (Backend)
- **Signature verification guard** (`CertificateIssuanceService.VerifyIssuedBy`): BouncyCastle DN match + signature verification
- Validates before saving in: issuance, re-sign, manual CA assignment during import, and confirmed import
- Prevents certificates from being linked to a CA that didn't sign them

### UI
- Dark/light theme toggle with FluentDesignTheme
- Collapsible navigation menu (FluentNavMenu)
- Draggable splitter between tree and detail panels
- Copyable toast notifications (icon-only copy button on error/warning toasts, 15s timeout)
- Communication toasts for success messages (5s timeout)
- **Loading indicator**: Progress ring with "Loading certificates..." shown during tree load
- **Deep-link auto-selection**: Thumbprint query parameter consumed once, then cleared from URL to prevent stale state

---

## Phase 2: Certificate Issuance & Templates (Complete)

### Certificate Templates
- CRUD page with FluentDataGrid + Add/Edit/Clone/Delete dialog
- **4 preset templates** (seeded on startup, non-deletable):
  - Root CA (RSA-4096, 10yr, CertSign+CrlSign)
  - Intermediate CA (RSA-4096, 5yr, DigSig+CertSign+CrlSign, CDP+AIA, URI SANs)
  - UDAP Client (RSA-2048, 2yr, DigSig, TLS Client Auth EKU, CDP+AIA, URI SANs)
  - SSL Server (RSA-2048, 1yr, DigSig, TLS Server Auth EKU, CDP, DNS SANs)
- Clone preset templates to customize
- Configurable fields:
  - General: Name, Description, Certificate Type, Validity Days
  - Key Parameters: Algorithm (RSA/ECDSA), Key Size (2048/3072/4096), ECDSA Curve (P-256/P-384/P-521), Hash Algorithm (SHA256/384/512)
  - Extensions: Key Usage (checkbox flags), Key Usage criticality, BasicConstraints (CA + path length), BasicConstraints criticality
  - **EKU picker**: Checkboxes for 10 common OIDs with friendly names (TLS Client/Server Auth, Code Signing, S/MIME, etc.) plus custom OID text field
  - Distribution: CDP URL template, AIA URL template
  - SAN type hints: URI, DNS, Email, IP (guides issuance UI)

### Certificate Issuance Engine (`CertificateIssuanceService`)
- Located in `Sigil.Common` for reuse by CLI/API consumers
- Uses .NET `CertificateRequest` API with BouncyCastle extension helpers
- **RSA + ECDSA** key generation
- Self-signed root CA creation
- CA-signed intermediate and end-entity certificate creation
- Extension building from template: BasicConstraints, KeyUsage, SKI, AKI, EKU, CDP, AIA, SANs
- **Extension helpers** (`CertificateExtensionHelpers`): AddAuthorityKeyIdentifier, MakeCdp, BuildAiaExtension — extracted from Udap.PKI.Generator for reuse
- Serial numbers: `RandomNumberGenerator.GetBytes(16)`
- **Validity clamping**: NotAfter automatically clamped to issuing CA's NotAfter
- PFX + PEM export and database storage

### Issue Certificate Flow (Explorer UI)
- **"New Root CA"** button in Explorer header (self-signed, Root CA templates only)
- **"Issue Certificate"** button on CA detail panel (visible when CA has private key)
- Issuance dialog with:
  - Template selector (filtered by cert type)
  - Subject DN field
  - Display name field
  - Validity date pickers (auto-calculated from template, clamped to issuer)
  - CDP/AIA URL fields (conditional on template flags)
  - Dynamic SAN entries (add/remove, type selector: URI/DNS/Email/IP)
  - PFX password
  - Template summary showing key params
- Post-generation: toast with thumbprint, tree refresh

### Certificate Renewal

#### Re-key (New Key Pair)
- Available on all certificate types
- Creates new certificate with new key pair, new serial, new validity
- Pre-fills subject, name, and SANs from existing cert
- SAN parsing handles all formats: `URL=`, `DNS Name=`, `RFC822 Name=`, `IP Address=`, and DB storage format

#### Re-sign (Same Key, New Validity)
- Available on Root CA and Intermediate CA certs with private keys
- **Updates the existing entity in-place** — same DB row, all child relationships preserved
- Loads existing private key from PFX
- Builds new CertificateRequest with same public key
- Copies all extensions from original cert (preserves SKI, AKI, BasicConstraints, etc.)
- Signs with parent CA (or self-signs for roots)
- New serial number + new validity period
- Downstream certs continue to validate (AKI→SKI match unchanged)
- Validity clamped to parent CA's NotAfter

---

### Certificate Export
- **Copy Key**: Extracts private key as PKCS#8 PEM and copies to clipboard (equivalent to `openssl pkcs12 -nocerts -nodes | openssl pkcs8 -topk8 -nocrypt`)
- **Copy Cert**: Extracts certificate as base64-encoded DER and copies to clipboard (for `x5c` JWT headers in UDAP registration/token requests)
- Both operations delegated to `CertificateExportService` in `Sigil.Common`
- Security level enforcement: keys stored in HSM/Cloud KMS (`CertSecurityLevel != Software`) cannot be exported

### Renewal Validation
- **CDP/AIA URL change warning**: When renewing a certificate, if the selected template would change CDP or AIA URLs compared to the original certificate, a warning banner appears in the issuance dialog listing each added/removed URL
- Business logic in `IssuanceValidator` (injected into `CertificateIssuanceService`), not in UI code-behind
- Warnings are advisory — user can proceed or adjust the template

### UI Enhancements
- **Draggable dialog resize**: Issue Certificate and Template Add/Edit dialogs have a resize handle on the right edge. Uses center-based mouse tracking and sets `--dialog-width` CSS variable to penetrate FluentDialog's shadow DOM
- Dialog min-width increased to 900px for better form layout

---

## Phase 5: Remote Signing & Aspire Orchestration (Complete)

### Signing Provider Architecture
- **`ISigningProvider` interface** in `Sigil.Common` — pluggable signing abstraction
  - `GenerateKeyAsync` — creates key pair in the provider
  - `GetPublicKeyAsync` — retrieves public key for certificate building
  - `SignDataAsync` — signs TBS (to-be-signed) data
- **`SigningKeyReference`** record — identifies a key across provider boundaries (provider, keyId, algorithm, size)
- **`SigningProviderOptions`** — configuration-driven provider selection: `"local"`, `"vault-transit"`, or `"gcp-kms"`
- **`RemoteCertificateBuilder`** — BouncyCastle-based certificate assembly with async remote signing (avoids sync-over-async deadlock in Blazor Server)

### Signing Providers (Separate Projects)
- **`LocalSigningProvider`** (in `Sigil.Common`) — in-memory RSA/ECDSA keys, default provider
- **`Sigil.Vault.Transit`** — HashiCorp Vault Transit secrets engine
  - Private keys never leave Vault; signs via REST API
  - P1363→DER ECDSA signature format conversion
  - Key lifecycle: create, get public key, sign, delete
- **`Sigil.Gcp.Kms`** — Google Cloud KMS
  - Private keys never leave Cloud HSM/KMS
  - Uses Application Default Credentials (gcloud CLI or service account)
  - Pre-computed digest signing via `AsymmetricSign` API
  - Key ring auto-creation, key version lifecycle management

### Three Signing Paths
1. **Full Remote** — key generation AND signing in remote provider (Vault/GCP KMS); no PFX export; `StoreProviderHint = "{provider}:{keyId}"`
2. **Hybrid** — local key generation (PFX exportable) + remote CA signing (e.g., end-entity cert with local key, signed by Vault-backed CA)
3. **Full Local** — both key and signing local (existing behavior)

### Docker & GCP Integration
- **Dockerfile** — multi-stage build for VS Container Tools compatibility
- **Dockerfile.gcp** — same + gcloud CLI installed, persistent credential volume
- **VS launch profiles**: Sigil (desktop), Docker, Docker-GCP
- **Aspire `WithHttpsCertificateConfiguration`** — injects trusted dev cert into containers
- **GCP credential isolation** — Docker named volume (`sigil-gcloud-config`), never committed to source

### Aspire Orchestration (`Sigil.AppHost`)
- **Vault container** with Transit engine auto-configured (key creation via lifecycle hook)
- **Switchable hosting modes** via launch profiles: `project`, `docker`, `docker-gcp`
- **Switchable signing providers** via `Sigil:SigningProvider`: `vault-transit` or `gcp-kms`
- **Launch profiles**: `https`, `https-docker`, `https-docker-gcp`, `https-docker-gcp-kms`, `http`

### Unit Tests (`_tests/Sigil.Signing.Tests`)
- **LocalSigningProvider**: key generation (RSA/ECDSA), signature verification round-trip, multi-hash support, error handling
- **VaultTransitSigningProvider**: P1363→DER conversion correctness (P-256, P-384), high-bit padding, leading-zero trimming, fuzz-style round-trip
- **SigningKeyReference**: record equality, deconstruction

---

## Architecture

### Project Structure
```
examples/CA/
├── Sigil/                 # Blazor Server host (Program.cs, App.razor, wwwroot)
├── Sigil.Common/          # Class library (entities, services, ViewModels, migrations)
│   ├── Data/Entities/     # Community, CaCertificate, IssuedCertificate, Crl, CertificateTemplate, Job
│   ├── Services/          # Issuance, Validation, Parsing, Import, Export, CRL, Dashboard, Template, Community, Management, Publishing
│   ├── Services/Signing/  # ISigningProvider, LocalSigningProvider, RemoteCertificateBuilder
│   ├── Validators/        # IssuanceValidator (pre-issuance business rules, injected into services)
│   └── ViewModels/        # DTOs for UI and API consumers
├── Sigil.UI/              # Razor Class Library (all components, pages, shared, layout)
│   ├── Components/Pages/  # Explorer, Communities, Templates, Import, Home, Jobs
│   ├── Components/Shared/ # Asn1TreeView, CertBadge, CrlBadge, ExtensionTable, CopyableToast
│   └── Services/          # Toast extensions
├── Sigil.Vault.Transit/   # ISigningProvider implementation for HashiCorp Vault Transit
├── Sigil.Gcp.Kms/         # ISigningProvider implementation for Google Cloud KMS
├── Sigil.Vault.Hosting/   # Aspire hosting integration for Vault dev container
├── Sigil.ServiceDefaults/  # Aspire service defaults (OpenTelemetry, health checks)
├── Sigil.AppHost/         # Aspire orchestrator (Vault + Sigil)
└── _tests/
    └── Sigil.Signing.Tests/  # Unit tests for signing providers
```

### Key Design Decisions
- **Sigil.Common has no UI dependencies** — reusable by CLI tools, APIs, tests
- **Service layer enforced**: Business logic lives in `Sigil.Common/Services/` (not in UI code-behinds). UI pages inject services, not `IDbContextFactory`. Services extracted: `DashboardService`, `TemplateService`, `CommunityService`, `CertificateManagementService`, `CertificatePublishingService`, `CertificateExportService`
- **Validators as a separate concern**: `Sigil.Common/Validators/` contains business rule validators injected into services (e.g., `IssuanceValidator` into `CertificateIssuanceService`)
- **Provider projects are separate assemblies** — `Sigil.Vault.Transit` and `Sigil.Gcp.Kms` implement `ISigningProvider` from `Sigil.Common`, keeping provider-specific dependencies (Vault HTTP, Google.Cloud.Kms) out of the core library
- **CertificateIssuanceService** and all DTOs in Common for multi-host consumption
- **Extension helpers** extracted from Udap.PKI.Generator test project into Sigil.Common
- **Tree highlighting** via JS interop into FluentTreeItem shadow DOM (avoids Blazor re-render/collapse)
- **Re-sign updates in-place** to preserve child relationships (vs creating new entity)
- **Preset templates** seeded idempotently on startup
- **`StoreProviderHint`** metadata tracks which provider holds each key (e.g., `"vault-transit:sigil-abc123"`, `"gcp-kms:sigil-def456"`)
