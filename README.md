# udap-dotnet

UDAP reference implementation for .NET.  

In short UDAP is a PKI extension profile to OAuth2.  One or more PKIs can be hosted by a `Community`.  Joining a `Community` results in a public/private key issued to a client.  The client also chooses to explicitly trust one of the issuing certificates in that chain by installing in your client.  In addition, all certificate chain validation including certificate revocation to a trusted root are performed.

Note: This is a new project.  It will take me some time to document.  It should be very active in code changes and document additions.  But feel free to try it out and add issues and/or pull requests.

I example apps are in the examples folder.

## What does it support

The repository contains components and example uses to support the following items from [Security for Scalable Registration, Authentication, and Authorization](http://hl7.org/fhir/us/udap-security/).  The intent is to also support generic UDAP, but the driving force currently is supporting auto registration to FHIR® servers.  FHIR® is the registered trademark of HL7 and is used with the permission of HL7. Use of the FHIR trademark does not constitute endorsement of the contents of this repository by HL7

| Feature   | Sub Feature             | Supported           | Comments                                               |
|-------------------------|---|---------------------|--------------------------------------------------------|
| Client                  | |Not Started         | Seems I ignored this in favor of server features.  I will get back to it soon. After all we need a client that can easily validated trust |
| [Discovery](http://hl7.org/fhir/us/udap-security/discovery.html) || ✔️ Including [Multi Trust Communities](http://hl7.org/fhir/us/udap-security/discovery.html#multiple-trust-communities) |  Client certificate storage is a file strategy.  User can implement their own ICertificateStore.  May add a Entity Framework example in future. |
| [Registration](http://hl7.org/fhir/us/udap-security/registration.html)|| ✔️ Including [Multi Trust Communities](http://hl7.org/fhir/us/udap-security/discovery.html#multiple-trust-communities)  |  Highly Functional.  The Deployed example FHIR® Server, "FhirLabsApi" is passing all udap.org Server Tests.  I am going to revisit the Client Secrets persistence layer.  Packages are dependent on Duende's Identity Server Nuget Packages. |
||Inclusion of Certifications and Endorsements|Started|Some example certification integration tests included from the client side |
Authorization and Authentication 
| [Consumer-Facing](http://hl7.org/fhir/us/udap-security/consumer.html)|| Not Started | |
| [Business-to-Business](http://hl7.org/fhir/us/udap-security/b2b.html)|| ✔️ | Works with client_credentials and authorization_code flows. |
||JWT Claim Extensions|Started|Some work completed for the B2B Authorization Extension (hl7-b2b) extension within integration tests. }  
| [Tiered OAuth for User Authentication](http://hl7.org/fhir/us/udap-security/user.html) || Not Started | |

## PKI support

### Generate PKI for integration tests

Part of this repository is a xUnit test project that will generate a couple PKI hierarchies for testing UDAP.  The test is called `Udap.PKI.Generator`.  I think showing the mechanics of what it takes to build out a PKI for UDAP will aid education and provide the flexibility to test interesting use cases.  Run all the tests in the `Udap.PKI.Generator` project.  The results include a folder with root a root certificate authority that issues intermediate certificates, certificate revocation lists, used certificates for community members and certs for web TLS certs.  Each of the example web services located in the [examples](/examples) use MSBuild `Link`s to link to certificates appropriate to its PKI needs.  So, if you would like to change something in the PKI just edit and run the tests.  All examples will automatically pick up the changes.  To enable crl lookup and AIA, Certification Authority Issuer resolution I just mapped crl, cert and anchor as static content via something like IIS on my Windows box.  I may create a dotnet core app to make this easier and it into ci/cd better but this is where I am at so far.

I am not sure if this will stay in unit test form or not, but for now this is the technique.  

### Certificate Authority tool

A .NET UI and CLI tool to generate certificates for UDAP communities.  A UI version of this tool is partially done in the [Udap.CA](/examples/Udap.CA/) project.  The plan is to deploy this or install it yourself and allow quick generations of certificates and PKI hierarchies that can generate valid and various invalid certificates for testing to aid in experimenting with behaviors such as certificate revocation, expirations and other interesting potential certification use cases. 

# Components (Nuget packages)

See the following Udap.Metadata.Server and Udap.Server sections.  The Udap.Metadata.Server is for the resource server such a FHIR® Server.  Udap.Server.Server is for the Identity Server.

## Udap.Metadata.Server

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

```AddUdapMetaDataServer``` extension will find the UdapConfig in AppSettings.  These settings will match the issued certificate.  

Reference [Required UDAP Metadata](http://hl7.org/fhir/us/udap-security/discovery.html#signed-metadata-elements).

Issuer and Subject must match the issued certificates, Subject Alternative Name extension.  The issued certificate is the first certificate present in the `x5c` JWT header.

```json
"UdapConfig": {
    "UdapMetadataConfigs": [
      {
        "Community": "http://localhost",
        "SignedMetadataConfig": {
          "Issuer": "http://localhost/",
          "Subject": "http://localhost/",
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
  - roots
    - caLocalhostCert.cer

Add configuration to AppSettings to point to the certificates.

**Note From AppSettings**

UdapConfig:UdapMetadataConfigs:Community value is the link to UdapFileCertStoreManifest:ResourceServers:Communities.Name.  So in this example the community is identified by the name `http://localhost`.  Community names are [constrained as a URI](http://hl7.org/fhir/us/udap-security/discovery.html#multiple-trust-communities)

```json
/*   
  Normally put someplace safer like secrets.json or secured database
  and add this to Program.cs.    
*/

"UdapFileCertStoreManifest": {
    "ResourceServers": [
      {
        "Communities": [
          {
            "Name": "http://localhost",
            "Anchors": [
              {
                "FilePath": "CertStore/anchors/anchorLocalhostCert.cer"
              }
            ],
            "RootCAFilePaths": [
              "CertStore/roots/caLocalhostCert.cer"
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

### UDAP Metadata Examples

- [FhirLabsApi example project](/examples//FhirLabsApi/)
- [WeatherApi example project](/examples//WeatherApi/)
- [FhirLabs Published](https://fhirlabs.net/fhir/r4/.well-known/udap)
- [FhirLabs UdapEd Tool | Discovery | Registration | B2B ](https://fhirlabs-udaped-v46zp6zteq-uw.a.run.app/udapDiscovery)

### Udap.Client

- No library formalized yet.  
  
- ### Udap.Idp.Server

- [Udap.Idp](/examples/Udap.Idp/)
- [Udap.Idp Deployed](https://securedcontrols.net/.well-known/udap)

## Udap.Server

Add this package to your Identity Server.  

See database setup at end of this document.  
Assumptions:  An Identity Sever exists is backed by a relational database.  Use [Udap.Idp](/examples/Udap.Idp/) as an example.  I may revisit this in the future and build an in memory version but this reference implementation. For now it assumes a relational database is deployed.

The following explains a basic dependency injection setup.

```csharp

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddIdentityServer()
    .AddConfigurationStore(
      storeOptions => storeOptions.ConfigureDbContext = b => 
              b.UseSqlServer(connectionString, dbOpts => 
                  dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName))
    )
    .AddOperationalStore(
      storeOptions => storeOptions.ConfigureDbContext = b => 
              b.UseSqlServer(connectionString, dbOpts => 
                  dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName))
    )
    .AddResourceStore<ResourceStore>()
    .AddClientStore<ClientStore>()
    .AddUdapServer(
          udapServerOptions => udapServerOptions.ServerSupport = udapServerOptions.ServerSupport,
          storeOptions => storeOptions.UdapDbContext = b => 
              b.UseSqlServer(connectionString, dbOpts => 
                  dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName))
    )

  var app = builder.Build();

  // uncomment if you want to add a UI
  app.UseStaticFiles();
  app.UseRouting();

  app.UseUdapServer();
  app.UseIdentityServer();

  // uncomment if you want to add a UI
  app.UseAuthorization();
  app.MapRazorPages().RequireAuthorization();

  app.Run;

```

### Udap Admin UI Tool

The is a MVP version of an Admin UI Tool.  It is only capable of administering the Udap prefixed tables.

See [Udap.Idp.Admin](/examples/Udap.Idp.Admin/)

## Build and test

From root.

```csharp
dotnet restore
```

If this is first build or you want to reset you certificates change to /_tests/Udap.PKI.Generator

```csharp
dotnet test
```

Return to root

```csharp
dotnet build
```

### Running tests

It is probably best to avoid running Udap.PKI.Generator unless you need the certificates regenerated.  May migrate this away from unit test in future.  Or create a src folder to isolate.  
It is also best to avoid Udap.Client.System.Tests as they are for experimenting with live servers.  Eventually the [FhirLabs UdapEd client tool](/examples/clients/UdapEd/Server/) will replace the need for this.

The following tests are normal to run and the build server runs these same tests.  

- [Udap.CA.Tests](/_tests/Udap.CA.Tests/)
- [Udap.Common.Tests](/_tests/Udap.Common.Tests/)
- [Udap.Support.Tests](/_tests/Udap.Support.Tests/)
- [UdapMetadata.Tests](/_tests/UdapMetadata.Tests/), tests two against the two example web services, FhirLabsApi and WeatherApi.
- [UdapServer.Tests](_tests/UdapServer.Tests/)


## Udap.Idp Database Configuration

For your convenience a EF Migrations Project called [UdapDb.SqlServer](/migrations/UdapDb.SqlServer/) can deploy the database schema.  Run from Visual Studio using the UdapDb profile (/properties/launchSettings.json).  This project will create all the Udap tables and Duende Identity tables.  It will seed data needed for running local system tests.  See the SeedData.cs for details.

If you need another database such as PostgreSQL I could be motivated to create one.

Not the [UdapDb.SqlServer](/migrations/UdapDb.SqlServer/) project includes two migrations for Duende's Identity Server tables.  I have not put anytime into migrating a schema.  At this point I my pattern is to just delete the database and re-create it.  At some point I will version this and start migrating officially.