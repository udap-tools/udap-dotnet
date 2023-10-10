# Udap.Metadata.Server

![UDAP logo](https://avatars.githubusercontent.com/u/77421324?s=48&v=4)

## 📦 Nuget Package: [Udap.Client](https://www.nuget.org/packages?q=udap.metadata.server)

This package includes a MVC controller, an extension method to load, and an implementation if `ICertificateStore` as `FileCertificateStore` so you can get a sample up and running quickly.

Program.cs could be as easy as this example.

```csharp

using Udap.Common;
using Udap.Metadata.Server;

var builder = WebApplication.CreateBuilder(args);
builder.Services
    .AddControllers()
    .UseUdapMetaDataServer(builder.Configuration);

builder.Services.AddSingleton<ICertificateStore, MyCustomCertificateStore>();

```

## Full Example

Below is a full example.  Alternatively the [2023 FHIR® DevDays Tutorial](udap-devdays-2023) is another great way to learn how to use ```Udap.Metadata.Server```.

Add this package to your FHIR® server or any web api server to.  

```csharp

dotnet new sln -o WebApiProject1
cd WebApiProject1

dotnet new webapi -o WebApi1 -minimal
dotnet sln add ./WebApi1/WebApi1.csproj

cd WebApi1

```

```csharp
dotnet add package Udap.Metadata.Server 
```

Or until a first release use the --prerelease tag.

```csharp

dotnet add package Udap.Metadata.Server --prerelease

dotnet build

```

Add UseUdapMetaData to program.cs

```csharp

 builder.Services
    .AddControllers()
    .AddUdapMetaDataServer(builder.Configuration);

```

```AddUdapMetaDataServer``` extension will find the UdapMetadataOptions in AppSettings.  These settings will match the issued certificate.  

Reference [Required UDAP Metadata](http://hl7.org/fhir/us/udap-security/discovery.html#signed-metadata-elements).

Issuer and Subject must match the issued certificates, Subject Alternative Name extension.  The issued certificate is the first certificate present in the `x5c` JWT header.

```json

"UdapMetadataOptions": {
    "UdapMetadataConfigs": [
      {
        "Community": "http://localhost",
        "SignedMetadataConfig": {
          "AuthorizationEndPoint": "https://securedcontrols.net:5001/connect/authorize",
          "TokenEndpoint": "https://securedcontrols.net:5001/connect/token",
          "RegistrationEndpoint": "https://securedcontrols.net:5001/connect/register"
        }
      }
    ]
  }

```

To serve UDAP metadata, certificates will be loaded through an implementation of ```ICertificatStore```.  Below is a built-in file-based implementation for lab experiments.  

```csharp

// UDAP CertStore
builder.Services.Configure<UdapFileCertStoreManifest>(builder.Configuration.GetSection("UdapFileCertStoreManifest"));
builder.Services.AddSingleton<ICertificateStore, FileCertificateStore>();

```

To continue this example, copy the following files from the Udap.PKI.Generator test project output to the following directory structure at the root of the WebApi1 project.  Ensure each file's "Copy to Output Directory" is set to copy.

- CertStore
  - anchors
    - anchorLocalhostCert.cer
  - issued
    - weatherApiClientLocalhostCert.pfx
  - anchors
    - caLocalhostCert.cer

Add configuration to AppSettings to point to the certificates.

**Note From AppSettings**

UdapMetadataOptions:UdapMetadataConfigs:Community value is the link to UdapFileCertStoreManifest:ResourceServers:Communities.Name.  So in this example the community is identified by the name `http://localhost`.  Community names are [constrained as a URI](http://hl7.org/fhir/us/udap-security/discovery.html#multiple-trust-communities)

```json

/*   
  Normally put someplace safer like secrets.json or secured database
  and add this to Program.cs.    
*/

"UdapFileCertStoreManifest": {
  "Communities": [
    {
      "Name": "http://localhost",
      "Anchors": [
        {
          "FilePath": "CertStore/anchors/caLocalhostCert.cer"
        }
      ],
      "Intermediates": [
        "CertStore/intermediates/anchorLocalhostCert.cer"
      ],
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

```csharp
dotnet run
```

Navigate to http://localhost:5079/.well-known/udap or http://localhost:5079/swagger.

A this point a success would result in a result similar to the following json.  Ensure the signed_metadata property contains a signed JWT token.

<details open><summary><a>View Metadata</></summary>

```json

{
  "udap_versions_supported": [
    "1"
  ],
  "udap_profiles_supported": [
    "udap_dcr",
    "udap_authn",
    "udap_authz"
  ],
  "udap_authorization_extensions_supported": [
    "hl7-b2b"
  ],
  "udap_authorization_extensions_required": [
    "hl7-b2b"
  ],
  "udap_certifications_supported": [
    "http://MyUdapCertification",
    "http://MyUdapCertification2"
  ],
  "udap_certifications_required": [
    "http://MyUdapCertification"
  ],
  "grant_types_supported": [
    "client_credentials"
  ],
  "scopes_supported": [
    "openid",
    "system/Patient.read",
    "system/AllergyIntolerance.read",
    "system/Procedures.read",
    "system/Observation.read"
  ],
  "authorization_endpoint": "https://securedcontrols.net/connect/authorize",
  "token_endpoint": "https://securedcontrols.net/connect/token",
  "token_endpoint_auth_methods_supported": [
    "private_key_jwt"
  ],
  "token_endpoint_auth_signing_alg_values_supported": [
    "RS256"
  ],
  "registration_endpoint": "https://securedcontrols.net/connect/register",
  "registration_endpoint_jwt_signing_alg_values_supported": [
    "RS256"
  ],
  "signed_metadata": "eyJhbGciOiJSUzI1NiIsIng1YyI6WyJNSUlGR3pDQ0JBT2dBd0lCQWdJSUZSVVJqcWdlTkdNd0RRWUpLb1pJaHZjTkFRRUxCUUF3Z2JNeEN6QUpCZ05WQkFZVEFsVlRNUk13RVFZRFZRUUlEQXBEWVd4cFptOXlibWxoTVJJd0VBWURWUVFIREFsVFlXNGdSR2xsWjI4eEV6QVJCZ05WQkFvTUNrVk5VaUJFYVhKbFkzUXhQekE5QmdOVkJBc01ObFJsYzNRZ1VFdEpJRU5sY25ScFptbGpZWFJwYjI0Z1FYVjBhRzl5YVhSNUlDaGpaWEowY3k1bGJYSmthWEpsWTNRdVkyOXRLVEVsTUNNR0ExVUVBd3djUlUxU0lFUnBjbVZqZENCVVpYTjBJRU5zYVdWdWRDQlRkV0pEUVRBZUZ3MHlNakE1TVRVeU1ETXpOVEphRncweU16QTVNVFV5TURNek5USmFNSUdwTVFzd0NRWURWUVFHRXdKVlV6RVBNQTBHQTFVRUNBd0dUM0psWjI5dU1TZ3dKZ1lEVlFRS0RCOVRkWEpsYzJOeWFYQjBjeUJNVEVNZ0tITmxiR1lnWVhOelpYSjBaV1FwTVRNd01RWURWUVFMRENwVlJFRlFJRlJsYzNRZ1EyVnlkR2xtYVdOaGRHVWdUazlVSUVaUFVpQlZVMFVnVjBsVVNDQlFTRWt4S2pBb0JnTlZCQU1NSVdoMGRIQnpPaTh2Wm1ocGNteGhZbk11Ym1WME9qY3dNVFl2Wm1ocGNpOXlORENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFJQkgrSUtIRUJ4SDIyN09BYkRsTGYxS0k4b1UxZE8vZmp2ZzFQbkJNSlQ0RjQrL1BFWmlOdkRhS0dFT09lOXVvTmVMdGlEWEt0aFVQSEdEMm54RXVSL2lQeXluVmFETmtHYkZvc2d3c01JMXU4bGFJbHNwQWVrR2d5VWlPZzB3a1NRbEF4TjJuaFVqR3dMbjllUzBPWld0eGhUcHBNNEFGbElwY1hackFLeTlOZm53S2NGeUtvUmg3Zlo4bDlSR1hHeFl6ZXh2ejJ0LzhCbG5xb3ZQODZlWktHaFBxTTlFTGZPNTc4R1UrNWJCcFNqWUdsenhwemVnanZaUkR5bnBVbEJBdEtvWDBOdXh6ZjJ6SURvOVZwaldoVG9TKzZ0eDZJRFVNZVdEZHZjQytPQnNTNjNUdisxN2VFSVdpRjlGb0xNYUNUZXJRMFluaWlwVGQ3NDdGT2NDQXdFQUFhT0NBVGt3Z2dFMU1Ga0dDQ3NHQVFVRkJ3RUJCRTB3U3pCSkJnZ3JCZ0VGQlFjd0FvWTlhSFIwY0RvdkwyTmxjblJ6TG1WdGNtUnBjbVZqZEM1amIyMHZZMlZ5ZEhNdlJVMVNSR2x5WldOMFZHVnpkRU5zYVdWdWRGTjFZa05CTG1OeWREQWRCZ05WSFE0RUZnUVVuMDUzdk9jYVdINzRsR1c4VVlYazk4WU5nOUV3REFZRFZSMFRBUUgvQkFJd0FEQWZCZ05WSFNNRUdEQVdnQlNqbFcxcnZTdFJ6ZUhQNVpCdjF5WlB2OTArM2pCTUJnTlZIUjhFUlRCRE1FR2dQNkE5aGp0b2RIUndPaTh2WTJWeWRITXVaVzF5WkdseVpXTjBMbU52YlM5amNtd3ZSVTFTUkdseVpXTjBWR1Z6ZEVOc2FXVnVkRk4xWWtOQkxtTnliREFPQmdOVkhROEJBZjhFQkFNQ0I0QXdMQVlEVlIwUkJDVXdJNFloYUhSMGNITTZMeTltYUdseWJHRmljeTV1WlhRNk56QXhOaTltYUdseUwzSTBNQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUJBUUI1VkswWkhWZXpMdUYvY2FieW1ZOWFLa0pENXhxY0JWVFNjeGVYQ3NMaWloLzhFS0NwdmVVSWl6NDJ5U3JtbHBJS2ljby95c1ByWHZKbU8vVnJHMjFWbnpZNkZKQjE3empXbkQ2bncvRnRFNXU0V2laTTE2aGcxUzJpa01FYXMzRjU3L3FrYjNLMzdXUm1IVDdickphUUtGZFYzWWRrVFloZ1cvbjFTellqWnEwZ0w0bDZWcVBSeCsxSWpaUkQxNWowZVFOV1hrR1lvWmlsR3duSFFJOUhKSGxadmMxZ1VLeFl2dDhwR2hlL0ZwZmF0cW9QVlhVY09CRVlBTHNrNmdlUDBhR0Z1M0xQa3NxdjZpZTM2M01tZWp5WEtxeE1uUThHcUR1bVNBU1ZhbDhyVmw4ZjE1NzlwUDc4aGxDYWNzam4zdTBnNVJLRDVPUk4rQTlJTTRDMyJdfQ.eyJpc3MiOiJodHRwczovL3N0YWdlLmhlYWx0aHRvZ28ubWU6ODE4MSIsInN1YiI6Imh0dHBzOi8vc3RhZ2UuaGVhbHRodG9nby5tZTo4MTgxIiwiaWF0IjoxNjc2OTM3NjI3LCJleHAiOjE2NzY5Mzc2ODcsImp0aSI6Ik95N0RaenVhXzBYbDhEaFNRXzVONzFxeHFBcllLdEI3OUdmRkVGQVFaUkUiLCJhdXRob3JpemF0aW9uX2VuZHBvaW50IjoiaHR0cHM6Ly9zZWN1cmVkY29udHJvbHMubmV0L2Nvbm5lY3QvYXV0aG9yaXplIiwidG9rZW5fZW5kcG9pbnQiOiJodHRwczovL3NlY3VyZWRjb250cm9scy5uZXQvY29ubmVjdC90b2tlbiIsInJlZ2lzdHJhdGlvbl9lbmRwb2ludCI6Imh0dHBzOi8vc2VjdXJlZGNvbnRyb2xzLm5ldC9jb25uZWN0L3JlZ2lzdGVyIn0.Y9qWVQFs9HXWipN8YDrH7gf89FoA0V7f3p9vqc6bPuqrcI0B6wgqZ2ZC3FYi46nGvpe6G_H20edXYR7zIHqcXqhtjfYNmCYoH-ceVwvq6kCAm0c4v8BXN23SM1Eh72_481Bbf7PidHUzcAIOn7fJ9DAk-LiVsT9aa7TD2Aj11cLC5ZiuoHyLCOaf6sjK-yX707ov313TEQREgLbSnl-YTwbIgmm_h3fW4eSZH2eszdr3a3Q8BWKKVBphWos5TvQ77WsYfTt60JfFHEXO8Psq7n4bGm2ZcNApzoa9PIuimmzeN8vjyaLBu7lDi93cc9jKphYz3KpLh_-8ruHF2HqmNw"
}

```

</details>
<br/>

### UDAP Resource Server Examples

- [FhirLabsApi example project](./examples//FhirLabsApi/)
- [WeatherApi example project](./examples//WeatherApi/)
- [FhirLabs Published](https://fhirlabs.net/fhir/r4/.well-known/udap)
- [FhirLabs UdapEd Tool | Discovery | Registration | B2B | Patient Match | National Directory ](https://udaped.fhirlabs.net)

- FHIR® is the registered trademark of HL7 and is used with the permission of HL7. Use of the FHIR trademark does not constitute endorsement of the contents of this repository by HL7.
- UDAP® and the UDAP gear logo, ecosystem gears, and green lock designs are trademarks of UDAP.org. UDAP Draft Specifications are referenced and displayed in parts of this source code to document specification implementation.
