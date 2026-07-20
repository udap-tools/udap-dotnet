# TEFCA SOP July 2026 Updates — SDK Impact Assessment

Date: July 9, 2026
Status: Findings recorded; implementation deferred until Duende package upgrade (`duende-8`) lands.

## New/updated specifications

Markdown conversions (committed alongside this document; source PDFs are kept locally only —
`*.pdf` is gitignored repo-wide):

| Document (markdown) | Version | Effective | Supersedes |
|---|---|---|---|
| [Exchange-Purposes-SOP-v5.1.md](Exchange-Purposes-SOP-v5.1.md) ([PDF source](https://rce.sequoiaproject.org/wp-content/uploads/2026/07/Exchange-Purposes-SOP-v5.1_7.1.2026_508.pdf)) | 5.1 (pub. July 8, 2026) | August 3, 2026 | Exchange Purposes SOP v4.0 |
| [Treatment-XP-SOP-v2.0.md](Treatment-XP-SOP-v2.0.md) ([PDF source](https://rce.sequoiaproject.org/wp-content/uploads/2026/07/Treatment-XP-SOP-v2.0_7.1.2026_508.pdf)) | 2.0 (pub. July 8, 2026) | August 3, 2026 | v1.2 (not previously in repo) |
| [IAS-XP-SOP-v3.0.md](IAS-XP-SOP-v3.0.md) ([PDF source](https://rce.sequoiaproject.org/wp-content/uploads/2026/07/SOP-IAS-XP-v3_June2026_Clean_508.pdf)) | 3.0 final (pub. July 1, 2026) | August 3, 2026 | v3 March 2026 draft |

The Facilitated FHIR Implementation SOP remains at v2.0 (the copy already in this folder is current).

## Impact 1 — XP code set is stale (v4.0 → v5.1)

`TefcaConstants.ExchangePurposeCodes` implements the 12 codes from XP SOP v4.0.
XP SOP v5.1 Table 1 defines **17 codes**:

- **Added:** `T-HCO-QAI` (Quality Assessment and Improvement), `T-HCO-POP` (Population-Based
  Activities), `T-HCO-PTSAFETY` (Patient Safety), `T-HCO-PERF` (Performance Review),
  `T-GOVDTRM-SSD` (Social Security Determination), `T-GOVDTRM-ACP` (Access Consent Policy,
  only used in conjunction with T-GOVDTRM-SSD)
- **Removed:** `T-HCO-QM` (Quality Measure Reporting) — effectively replaced by `T-HCO-QAI`
- Also noteworthy: v5.1 marks `T-PH-ECR` and `T-PH-ELR` as message-delivery/push-only (no Queries)

Consequence today: a TEFCA auth server using this SDK rejects registrations/token requests
for the six new codes and accepts the retired `T-HCO-QM`.

Affected code:
- `Udap.Tefca.Model/TefcaConstants.cs` — `ExchangePurposeCodes`
- `Udap.Tefca.Server/TefcaTokenValidator.cs` — `AllTefcaXpCodes`
- `Udap.Tefca.Server/TefcaRegistrationValidator.cs` — allowed exchange purposes list
- `_tests/UdapServer.Tests/Validators/TefcaCommunityValidatorTests.cs` — `T-HCO-QM` inline data
- `_tests/Udap.PKI.Generator/TefcaBuild.cs` — `T-HCO-QM` SAN URI

## Impact 2 — Conformance bug: `tefca-ias` should be `tefca_ias`

Facilitated FHIR SOP v2.0 Table 4 defines the IAS Authorization Extension Object key as
**`tefca_ias`** (underscore). The SDK uses `"tefca-ias"` (hyphen) via
`TefcaConstants.UdapAuthorizationExtensions.TEFCAIAS`, flowing into:

- `Udap.Tefca.Model/TefcaIasDeserializer.cs` (`ExtensionKey`)
- `Udap.Tefca.Server/TefcaTokenValidator.cs` (required-extension check for T-IAS + client_credentials)
- `README.md` (extension tables)
- `examples/FhirLabsApi/udap.metadata.options.Development.json` (`UdapAuthorizationExtensionsSupported`)

The SDK is internally consistent (tests pass), but non-conformant on the wire: a conformant
client sending `tefca_ias` is rejected, and tokens built by the SDK are not recognized by
other conformant implementations. Fix independent of the new SOPs.

## Impact 3 — Treatment XP SOP v2.0 §6.2 hl7-b2b content rules

For FHIR Queries using Treatment XP codes (`T-TREAT`, `T-TRTMNT`):

1. `organization_name` MUST include the Health Care Provider's individual or organizational
   NPI and/or TIN appended to the human-readable name.
2. `organization_id` MUST be the ResourceID of the Organization entry in the RCE Directory
   Service (consistent with Facilitated FHIR SOP Table 2).
3. Member ID/Subscriber ID, if known, go in the Query Patient Resource as identifiers with
   system `http://hl7.org/fhir/us/davinci-hrex/CodeSystem/hrex-temp`, code `umb`
   (FHIR data layer — outside the security SDK).

`HL7B2BAuthorizationExtension` carries the fields; there is no Treatment-specific content
validation. Candidate enhancement in `TefcaTokenValidator` when registered XP is a Treatment
code. §6.1 (SAML/IHE attributes) and §7 (RCE Directory NPI population) are QHIN/directory
obligations, out of SDK scope.

Compliance dates: Treatment XP code usage — August 3, 2026 (QHINs/Participants/Subparticipants);
Directory NPI population — September 3, 2026 (QHINs).

## Impact 4 — IAS XP SOP v3.0 final

No change to the `tefca_ias` extension model — field definitions remain in the Facilitated
FHIR SOP v2.0. The March 2026 draft copy in this folder is superseded by the June clean/final.

## Planned work items (after Duende upgrade)

1. Fix `tefca-ias` → `tefca_ias` (SDK, README, FhirLabsApi metadata options).
2. Update XP codes to v5.1 (constants, validators, tests, PKI generator).
3. Optional: Treatment §6.2 `organization_name` NPI/TIN + `organization_id` validation for
   Treatment XP tokens.
4. Update the **udaped** UI tool (`C:\Source\GitHub\JoeShook\udap-tools\udaped`) that builds
   `hl7-b2b` and `tefca_ias` extensions — same key rename and XP code list refresh.
