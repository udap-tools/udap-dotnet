# Udap.Tefca.Server

TEFCA community-specific validators for UDAP registration and token issuance, implementing the [TEFCA SOP: Facilitated FHIR Implementation v2.0](https://rce.sequoiaproject.org/wp-content/uploads/2026/02/SOP-Facilitated-FHIR-Implementation-2.0-Draft-508.pdf) requirements.

## Setup

Register both the TEFCA model extensions and the validators:

```csharp
// Register TEFCA authorization extension types (tefca_ias, etc.)
builder.Services.AddUdapTefcaExtensions();

// Register TEFCA community validators
builder.Services.AddUdapTefcaValidation(options =>
{
    options.Communities.Add("tefca://test-community");
});
```

`AddUdapTefcaExtensions()` comes from the [Udap.Tefca.Model](../../Udap.Tefca.Model/docs/README.md) package and registers TEFCA-specific authorization extension object types. Call it before `AddUdapTefcaValidation()`.

The default community URI (`tefca://tefca`) is included automatically. Use the options delegate to add additional communities.

## What it enforces

### Token request validation

| Rule | `client_credentials` | `authorization_code` |
|------|---------------------|---------------------|
| Required extensions | `hl7-b2b` | none |
| Allowed `purpose_of_use` | 17 TEFCA XP codes | 17 TEFCA XP codes |
| Max `purpose_of_use` count | 1 | 1 |
| POU must match SAN URI | yes | yes |
| IAS + client_creds requires `tefca_ias` | yes | n/a |
| `tefca_ias` must carry `id_token` | yes | yes |
| Treatment org identifiers (opt-in) | yes | yes |

The allowed `purpose_of_use` codes come from the [TEFCA SOP: Exchange Purposes v5.1](https://rce.sequoiaproject.org/wp-content/uploads/2026/07/Exchange-Purposes-SOP-v5.1_7.1.2026_508.pdf) Table 1 (OID: `2.16.840.1.113883.3.7204.1.5.2.1`), exposed as `TefcaConstants.ExchangePurposeCodes.All`:

`T-TREAT`, `T-TRTMNT`, `T-PYMNT`, `T-HCO`, `T-HCO-CC`, `T-HCO-HED`, `T-HCO-QAI`, `T-HCO-POP`, `T-HCO-PTSAFETY`, `T-HCO-PERF`, `T-PH`, `T-PH-ECR`, `T-PH-ELR`, `T-IAS`, `T-GOVDTRM`, `T-GOVDTRM-SSD`, `T-GOVDTRM-ACP`

### Registration validation

At dynamic client registration time, `TefcaRegistrationValidator` validates that the client certificate's SAN URI contains a valid TEFCA Exchange Purpose code in the fragment (e.g., `https://example.com/fhir#T-TREAT`).

### IAS conditional logic

When a client is registered with exchange purpose `T-IAS` and requests a `client_credentials` token, the `tefca_ias` authorization extension object must be present in the request (SOP v2.0 Section 6.11). Whenever a `tefca_ias` extension is present, it must carry an `id_token` (SOP v2.0 Table 4).

### Treatment organization identifiers (opt-in)

The [Treatment XP Implementation SOP v2.0](https://rce.sequoiaproject.org/wp-content/uploads/2026/07/Treatment-XP-SOP-v2.0_7.1.2026_508.pdf) Section 6.2 requires Treatment FHIR Queries to carry the provider's NPI and/or TIN appended to `organization_name` and the RCE Directory Organization ResourceID as `organization_id` in the `hl7-b2b` extension. Because the SOP does not prescribe an exact format for the appended identifiers, enforcement is opt-in:

```csharp
builder.Services.AddUdapTefcaValidation(options =>
{
    options.EnforceTreatmentOrganizationIdentifiers = true;
});
```

When enabled, token requests for clients registered with `T-TREAT` or `T-TRTMNT` fail with `invalid_grant` if `organization_id` is missing or `organization_name` contains no 9-10 digit identifier.

## SSRAA vs TEFCA comparison

| Rule | SSRAA | TEFCA |
|------|-------|-------|
| `hl7-b2b` required | `client_credentials` only | `client_credentials` only |
| Allowed POU codes | 62 (HL7 v3 full set) | 17 (TEFCA XP codes, SOP v5.1) |
| Max POU count | unlimited | 1 |
| POU must match SAN URI | no | yes |
| Registration validation | none | SAN URI XP code validation |
| IAS support | n/a | `tefca_ias` AEO required |

## How it works

`TefcaTokenValidator` and `TefcaRegistrationValidator` implement `ICommunityTokenValidator` and `ICommunityRegistrationValidator` respectively. At runtime:

1. **Registration**: `TefcaRegistrationValidator` checks if the client's SAN URI contains a valid XP code fragment
2. **Token request**: `TefcaTokenValidator` returns rules for the grant type, then validates that the `purpose_of_use` in the `hl7-b2b` extension matches the registered SAN URI's XP code

See [Udap.Server](../../Udap.Server/docs/README.md) for the full auth server setup and the [Udap.Auth.Server example](../../examples/Udap.Auth.Server/) for a working reference.
