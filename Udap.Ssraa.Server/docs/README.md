# Udap.Ssraa.Server

SSRAA community-specific validators for UDAP token issuance with HL7 v3 PurposeOfUse enforcement.

## Setup

```csharp
builder.Services.AddUdapSsraaValidation(options =>
{
    options.Communities.Add("udap://fhirlabs.net");
});
```

Multiple communities can share the same SSRAA rules:

```csharp
builder.Services.AddUdapSsraaValidation(options =>
{
    options.Communities.Add("udap://fhirlabs.net");
    options.Communities.Add("udap://another-community.example.com");
});
```

## What it enforces

| Rule | `client_credentials` | `authorization_code` |
|------|---------------------|---------------------|
| Required extensions | `hl7-b2b` | none |
| Allowed `purpose_of_use` | All 62 HL7 v3 codes | All 62 HL7 v3 codes |
| Max `purpose_of_use` count | unlimited | unlimited |

The allowed `purpose_of_use` codes come from the [HL7 v3 PurposeOfUse value set](https://terminology.hl7.org/ValueSet-v3-PurposeOfUse.html) (OID: `2.16.840.1.113883.5.8`).

## Customizing required extensions

The defaults match the SSRAA IG, but you can override per grant type:

```csharp
builder.Services.AddUdapSsraaValidation(options =>
{
    options.Communities.Add("udap://fhirlabs.net");

    // Require hl7-b2b for both grant types (default only requires it for client_credentials)
    options.AuthorizationCodeExtensionsRequired = ["hl7-b2b"];

    // Or remove the client_credentials requirement
    options.ClientCredentialsExtensionsRequired = null;
});
```

## How it works

`SsraaTokenValidator` implements `ICommunityTokenValidator`. At token request time:

1. `DefaultUdapAuthorizationExtensionValidator` resolves the client's community from the registration store
2. Iterates registered `ICommunityTokenValidator` implementations
3. `SsraaTokenValidator.AppliesToCommunity()` matches if the community is in the configured set
4. `GetValidationRules()` returns the rules for the grant type
5. The framework enforces required extensions and validates `purpose_of_use` codes

See [Udap.Server](../../Udap.Server/docs/README.md) for the full auth server setup and the [Udap.Auth.Server example](../../examples/Udap.Auth.Server/) for a working reference.
