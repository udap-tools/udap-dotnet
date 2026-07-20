# Udap.Metadata.Server

![UDAP logo](https://avatars.githubusercontent.com/u/77421324?s=48&v=4)

## 📦 Nuget Package: [Udap.Metadata.Server](https://www.nuget.org/packages/Udap.Metadata.Server)

This package provides the `.well-known/udap` metadata endpoint for FHIR resource servers and other UDAP-secured APIs. It includes an extension method for service registration, middleware for dynamic metadata serving, and a built-in `FileCertificateStore` implementation of `ICertificateStore`.

For multi-domain metadata support (serving signed metadata for multiple domains within a single community), see [Multi-Domain Metadata Support](../../docs/multi-domain-metadata.md).

## Quick Start

Program.cs can be as simple as:

```csharp
using Udap.Metadata.Server;

var builder = WebApplication.CreateBuilder(args);
builder.Services
    .AddControllers()
    .AddUdapMetadataServer(builder.Configuration);

var app = builder.Build();
app.UseUdapMetadataServer();
app.MapControllers();
app.Run();
```

You can provide your own certificate store implementation:

```csharp
builder.Services.AddSingleton<ICertificateStore, MyCustomCertificateStore>();
```

## Setup

```bash
dotnet add package Udap.Metadata.Server
```

Add the `AddUdapMetadataServer` service extension and `UseUdapMetadataServer` middleware to Program.cs:

```csharp
builder.Services
    .AddControllers()
    .AddUdapMetadataServer(builder.Configuration);

// ...

// Place before UseRouting() and UseAuthentication() so metadata
// requests are handled anonymously
app.UseUdapMetadataServer();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
```

By default, `AddUdapMetadataServer` registers `UdapMetadataOptionsProvider` which reads the metadata options file path from AppSettings:

```json
"UdapMetadataOptionsFile": "udap.metadata.options.json"
```

udap.metadata.options.json:
```json
{
  "UdapVersionsSupported": [ "1" ],
  "UdapProfilesSupported": [ "udap_dcr", "udap_authn", "udap_authz", "udap_to" ],
  "ScopesSupported": [ "openid", "system/*.read", "user/*.read", "patient/*.read" ],
  "UdapCertificationsSupported": [ "http://MyUdapCertification", "http://MyUdapCertification2" ],
  "UdapCertificationsRequired": [ "http://MyUdapCertification" ],
  "GrantTypesSupported": [ "authorization_code", "refresh_token", "client_credentials" ],

  "UdapMetadataConfigs": [
    {
      "Community": "http://localhost",
      "SignedMetadataConfig": {
        "AuthorizationEndpoint": "https://securedcontrols.net:5001/connect/authorize",
        "TokenEndpoint": "https://securedcontrols.net:5001/connect/token",
        "RegistrationEndpoint": "https://securedcontrols.net:5001/connect/register"
      }
    }
  ]
}
```

## UDAP Metadata Options

See [Required UDAP Metadata](http://hl7.org/fhir/us/udap-security/discovery.html#signed-metadata-elements).

The `UdapMetadataOptions` class defines the configurable properties:

- **UdapVersionsSupported**: Array of supported UDAP versions (e.g., `["1"]`)
- **UdapProfilesSupported**: Array of supported UDAP profiles (e.g., `["udap_dcr", "udap_authn"]`)
- **UdapAuthorizationExtensionsSupported**: Array of supported authorization extensions (e.g., `["hl7-b2b", "tefca_ias"]`)
- **UdapAuthorizationExtensionsRequired**: Array of required authorization extensions
- **UdapCertificationsSupported**: Array of supported certifications
- **UdapCertificationsRequired**: Array of required certifications
- **GrantTypesSupported**: Array of supported OAuth2 grant types
- **ScopesSupported**: Array of supported scopes
- **TokenEndpointAuthSigningAlgValuesSupported**: Array of supported signing algorithms for the token endpoint
- **RegistrationEndpointJwtSigningAlgValuesSupported**: Array of supported signing algorithms for the registration endpoint
- **UdapMetadataConfigs**: Array of community-specific metadata configurations
- **CertificateResolveTimeoutSeconds**: Timeout in seconds for certificate resolution (default: 10)

### Extending Metadata

Any extra properties in your `udap.metadata.options.json` file not listed above will be loaded and made available in the published metadata via the `ExtensionData` dictionary.

## Certificate Store

To serve UDAP metadata, certificates are loaded through an implementation of `ICertificateStore`. Below is the built-in file-based implementation:

```csharp
builder.Services.Configure<UdapFileCertStoreManifest>(builder.Configuration.GetSection("UdapFileCertStoreManifest"));
builder.Services.AddSingleton<ICertificateStore, FileCertificateStore>();
```

Configure certificate paths in appsettings.json. The community name links `UdapMetadataConfigs` to `UdapFileCertStoreManifest`. Community names are [constrained as a URI](http://hl7.org/fhir/us/udap-security/discovery.html#multiple-trust-communities).

```json
"UdapFileCertStoreManifest": {
  "Communities": [
    {
      "Name": "http://localhost",
      "IssuedCerts": [
        {
          "FilePath": "CertStore/issued/weatherApiClientLocalhostCert.pfx",
          "Password": "udap-test"
        }
      ]
    }
  ]
}
```

## Examples

- [FhirLabsApi example project](../../examples/FhirLabsApi/)
- [FhirLabs Published](https://fhirlabs.net/fhir/r4/.well-known/udap)
- [UdapEd Tool](https://udaped.fhirlabs.net)

---

- FHIR® is the registered trademark of HL7 and is used with the permission of HL7. Use of the FHIR trademark does not constitute endorsement of the contents of this repository by HL7.
- UDAP® and the UDAP gear logo, ecosystem gears, and green lock designs are trademarks of UDAP.org.
