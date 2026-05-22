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
| Allowed `purpose_of_use` | 12 TEFCA XP codes | 12 TEFCA XP codes |
| Max `purpose_of_use` count | 1 | 1 |
| POU must match SAN URI | yes | yes |
| IAS + client_creds requires `tefca_ias` | yes | n/a |

The allowed `purpose_of_use` codes come from the [TEFCA SOP: Exchange Purposes v4.0](https://rce.sequoiaproject.org/wp-content/uploads/2025/01/SOP-Exchange-Purposes_CA-v2_v4-508.pdf) (OID: `2.16.840.1.113883.3.7204.1.5.2.1`):

`T-TREAT`, `T-REQTREAT`, `T-HPO`, `T-PAY`, `T-COC`, `T-HEDIS`, `T-QMR`, `T-PH`, `T-ECR`, `T-ELR`, `T-IAS`, `T-GBD`

### Registration validation

At dynamic client registration time, `TefcaRegistrationValidator` validates that the client certificate's SAN URI contains a valid TEFCA Exchange Purpose code in the fragment (e.g., `https://example.com/fhir#T-TREAT`).

### IAS conditional logic

When a client is registered with exchange purpose `T-IAS` and requests a `client_credentials` token, the `tefca_ias` authorization extension object must be present in the request (SOP v2.0 Section 6.11).

## SSRAA vs TEFCA comparison

| Rule | SSRAA | TEFCA |
|------|-------|-------|
| `hl7-b2b` required | `client_credentials` only | `client_credentials` only |
| Allowed POU codes | 62 (HL7 v3 full set) | 12 (TEFCA XP subset) |
| Max POU count | unlimited | 1 |
| POU must match SAN URI | no | yes |
| Registration validation | none | SAN URI XP code validation |
| IAS support | n/a | `tefca_ias` AEO required |

## How it works

`TefcaTokenValidator` and `TefcaRegistrationValidator` implement `ICommunityTokenValidator` and `ICommunityRegistrationValidator` respectively. At runtime:

1. **Registration**: `TefcaRegistrationValidator` checks if the client's SAN URI contains a valid XP code fragment
2. **Token request**: `TefcaTokenValidator` returns rules for the grant type, then validates that the `purpose_of_use` in the `hl7-b2b` extension matches the registered SAN URI's XP code

See [Udap.Server](../../Udap.Server/docs/README.md) for the full auth server setup and the [Udap.Auth.Server example](../../examples/Udap.Auth.Server/) for a working reference.
