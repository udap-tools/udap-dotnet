# udap-dotnet

UDAP reference implementation for .NET.  

In short UDAP is a PKI extension profile to OAuth2.  One or more PKIs can be hosted by a `Community`.  Joining a `Community` results in a public/private key issued to a client.  The client also chooses to explicitly trust one of the issuing certificates in that chain by installing in your client.  In addition, all certificate chain validation including certificate revocation to a trusted root are performed.

Note: This is a new project.  It will take me some time to document.  It should be very active in code changes and document additions.  But feel free to try it out and add issues and/or pull requests.

I am using .NET 7 for a couple projects in here.  In a few weeks .NET 7 will be released.

- `Udap.PKI.Generator`, because there are new X509 features.
- `Udap.Idp.Admin`, because of an annoying bug in Blazor Server related to uploading files.

## What does it support

The repository contains components and example uses to support the following items from [Security for Scalable Registration, Authentication, and Authorization](http://hl7.org/fhir/us/udap-security/).  The intent is to also support generic UDAP, but the driving force currently is supporting auto registration to FHIR servers.

| Feature                 | Supported           | Comments                                               |
|-------------------------|---------------------|--------------------------------------------------------|
| [Discovery](http://hl7.org/fhir/us/udap-security/discovery.html) | ✔️ Including [Multi Trust Communities](http://hl7.org/fhir/us/udap-security/discovery.html#multiple-trust-communities) | Highly functional.  Could use some advanced tests such as certificate revocation. |
| [Registration](http://hl7.org/fhir/us/udap-security/registration.html)| ✔️ Including [Multi Trust Communities](http://hl7.org/fhir/us/udap-security/discovery.html#multiple-trust-communities)  |  Functional but needs a lot more tests |
| [Consumer-Facing](http://hl7.org/fhir/us/udap-security/consumer.html)| Not Started | |
| [Business-to-Business](http://hl7.org/fhir/us/udap-security/b2b.html)| In progress | |
| [Tiered OAuth for User Authentication](http://hl7.org/fhir/us/udap-security/user.html) | Not Started | |

### PKI support

Part of this repository is a xUnit test project that will generate a couple PKI hierarchies for testing UDAP.  The test is called `Udap.PKI.Generator`.  I think showing the mechanics of what it takes to build out a PKI for UDAP will aid education and provide the flexibility to test interesting use cases.  Run all the tests in the `Udap.PKI.Generator` project.  The results include a folder with root a root certificate authority that issues intermediate certificates, certificate revocation lists, used certificates for community members and certs for web TLS certs.  Each of the example web services located in the [examples](/examples) use MSBuild `Link`s to link to certificates appropriate to its PKI needs.  So, if you would like to change something in the PKI just edit and run the tests.  All examples will automatically pick up the changes.  To enable crl lookup and AIA, Certification Authority Issuer resolution I just mapped crl, cert and anchor as static content via something like IIS on my Windows box.  I may create a dotnet core app to make this easier and it into ci/cd better but this is where I am at so far.

I am not sure if this will stay in unit test form or not, but for now this is the technique.  

## Components (Nuget packages)

### Udap.Metadata.Server

Add this package to your FHIR server or any web api server to.  

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

Or for until an first release

```csharp
dotnet add package Udap.Metadata.Server --prerelease

dotnet build
```

Add UseUdapMetaData to program.cs

```csharp
 builder.Services
    .AddControllers()
    .UseUdapMetaDataServer(builder.Configuration);
```

```UseUdapMetaData``` extension will find the UdapConfig in AppSettings.  These settings will match the issued certificate.  

Reference [Required UDAP Metadata](https://build.fhir.org/ig/HL7/fhir-udap-security-ig/branches/main/discovery.html#signed-metadata-elements).

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

UdapConfig:UdapMetadataConfigs:Community value is the link to UdapFileCertStoreManifest:ResourceServers:Communities.Name.  So in this example the community is identified by the name `http://localhost`.  Community names are [constrained as a URI](https://build.fhir.org/ig/HL7/fhir-udap-security-ig/branches/main/discovery.html#multiple-trust-communities)

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

```json
{
"udap_versions_supported": [
"1"
],
"udap_profiles_supported": [
"udap_dcr",
"udap_authn",
"udap_authz",
"udap_to"
],
"udap_authorization_extensions_supported": [
"hl7-b2b",
"acme-ext"
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
"authorization_code",
"refresh_token",
"client_credentials"
],
"scopes_supported": [
"openid",
"system/Patient.read",
"system/AllergyIntolerance.read",
"system/Procedures.read",
"system/Observation.read"
],
"authorization_endpoint": "https://securedcontrols.net:5001/connect/authorize",
"token_endpoint": "https://securedcontrols.net:5001/connect/token",
"token_endpoint_auth_methods_supported": [
"private_key_jwt"
],
"token_endpoint_auth_signing_alg_values_supported": [
"RS256"
],
"registration_endpoint": "https://securedcontrols.net:5001/connect/register",
"registration_endpoint_jwt_signing_alg_values_supported": [
"RS256"
],
"signed_metadata": "eyJhbGciOiJSUzI1NiIsIng1YyI6WyJNSUlGR3pDQ0F3T2dBd0lCQWdJRUFRSURCREFOQmdrcWhraUc5dzBCQVFzRkFEQjRNUXN3Q1FZRFZRUUdFd0pWVXpFUE1BMEdBMVVFQ0JNR1QzSmxaMjl1TVJFd0R3WURWUVFIRXdoUWIzSjBiR0Z1WkRFVU1CSUdBMVVFQ2hNTFJtaHBjaUJEYjJScGJtY3hEekFOQmdOVkJBc1RCa0Z1WTJodmNqRWVNQndHQTFVRUF4TVZWVVJCVUMxTWIyTmhiR2h2YzNRdFFXNWphRzl5TUI0WERUSXlNVEF6TVRFMk1qRXlOMW9YRFRJME1URXdNVEUyTWpFeU4xb3djREVMTUFrR0ExVUVCaE1DVlZNeER6QU5CZ05WQkFnVEJrOXlaV2R2YmpFUk1BOEdBMVVFQnhNSVVHOXlkR3hoYm1ReEZEQVNCZ05WQkFvVEMwWm9hWElnUTI5a2FXNW5NUk13RVFZRFZRUUxFd3BYWldGMGFHVnlRWEJwTVJJd0VBWURWUVFERXdsc2IyTmhiR2h2YzNRd2dnRWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUUREeW1lSCs5SmFCdWdRbVdoNVk5SUVxR1N1UkRvS1VFWEhVbjM2ZzcwMW5Sek9rODVVQVI5KzNzeFAyQzdRbTZoQWlud05IQnNyUlZrMmRrandaS0JtSFFwTzlJOTBydnpZYmx1Y2tRUW9Sa3htSVZmYlNYZ2RLeWV0THZ4OXF0blEzY0VvaFVWNHAyOTYveHBZcG14VTJUZUY0RnJDeU03b2hETVZoUDdzTTB0eDY3czhaMG94azRPNWl0OFQwWmhhV04zVzRFc1dIdzF4TFdrM2JTV1VqQ0daY0Rhdk01eGFFbCtqbDVZM0NIM1NlMDg2b0l3VlZYM0diMHdHOUdrSlZPUnZIQ2lZU2VrRXNzcFVTbjVwSWRqWXYyRnFwR0lyZ1Z5aW9mU3BpbHRSbW04bUV3SVJVaVNTUnZ0M01zZVp3MC8xVFMyMGJLSkYzWk91TjNhVkFnTUJBQUdqZ2JRd2diRXdEQVlEVlIwVEFRSC9CQUl3QURBT0JnTlZIUThCQWY4RUJBTUNCNEF3SFFZRFZSME9CQllFRkV5N0hZTFdLaUx1aVVBZXM5SDk2aFIwVUt1QU1COEdBMVVkSXdRWU1CYUFGRVJBQjdVWDNtZHRBbi9kTTdaek9CV3FyTGhDTURNR0ExVWRId1FzTUNvd0tLQW1vQ1NHSW1oMGRIQTZMeTlzYjJOaGJHaHZjM1F2WTNKc0wyeHZZMkZzYUc5emRDNWpjbXd3SEFZRFZSMFJCQlV3RTRZUmFIUjBjRG92TDJ4dlkyRnNhRzl6ZEM4d0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dJQkFFUEEzdjRkM3VyRWliTnRBSm5vR1luVjdvWUFiVUJPTjZqY3hZdDlDWXoydzR1eEk1VmI4Zi9RUG9jekY2NTFCNHp3Y3RmQy9taDBFZTgySU1FQXFsMzlBRFpuckllcGdLQ2VWQmNhWGF1bld6ZlY5YlpWNEtaSFBnL0c1UE1YNlptWWozaGRLSktZMmR3amh6ck9MZzcxRG1tdlkwaWk0STNhWHkxdXpIandWWGc0b1c5cVpkWnM2dWhXakpMa09idVQ2MGZsTktIUU9PbzMydHZxQ1gwVmtNMnEzdC9zWFp1aTlFK1liSGM4SCt4M0x6TGszWlVWdVE1WHp1NnI1Q0FzSHl2aVRGL2hwcnpkNmtDZnp6bTFLdzZzL1dDR1VKU3pYUHpxWHZQWDQ2S0RoYjhBVGZYSEI0V0ZLMTd2MTZUMCsrNTFjdzZmaWVRNUNXbkFPSDd3MXlub1E4S0lML2RQRjhVc1lsWng4QkZGY0hKcGFQaEg5ejJMakdJc0I0aTNkanZtQjZUNTNFSjllT203U0NFTGFoWk94aUx6dStVZHVpUlNoQm9xekNCeTl3NzFWcjg3R2IxL3NFRkR2am9GbUFUN2xGaE5pMVZLcTBwQlV5dDJYdnBhVDVaQVBaTHozdDZGODFYWlZvTjExVVhrdytFaGJBMTBNWGVOZFc2SEVDMHJyMjNaRUNmcnlHV083Qlh2QU5aV3E4TGo3bkJvQjdKa3lpdDdRQXNETzk1SjdXbDlDWm1MVGxpZjRSZlRoMXpxK2FFVXBCNFJrd1FBYkFLUmNlQWh5OE1qTFhFaW1HUXc5bUI4OGd4YWpxTElwYzEvalhlT1h4R0srUWNRKzBqaDRZR0RoN0pkSTZIdzlKaWR0VTFNMW80L0pzUUtjY01yalJYaiJdfQ.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0LyIsInN1YiI6Imh0dHA6Ly9sb2NhbGhvc3QvIiwiaWF0IjoxNjY3NDk1MjU0LCJleHAiOjE2Njc0OTUzMTQsImp0aSI6IjliNjRqVGZMTmRVTzctRkJweVVfYWRycEtyM0lyekNmWHZFal90c2kwUTQiLCJhdXRob3JpemF0aW9uX2VuZHBvaW50IjoiaHR0cHM6Ly9zZWN1cmVkY29udHJvbHMubmV0OjUwMDEvY29ubmVjdC9hdXRob3JpemUiLCJ0b2tlbl9lbmRwb2ludCI6Imh0dHBzOi8vc2VjdXJlZGNvbnRyb2xzLm5ldDo1MDAxL2Nvbm5lY3QvdG9rZW4iLCJyZWdpc3RyYXRpb25fZW5kcG9pbnQiOiJodHRwczovL3NlY3VyZWRjb250cm9scy5uZXQ6NTAwMS9jb25uZWN0L3JlZ2lzdGVyIn0.p35Zsijh62u8mqIMDjaCHSHZgE3VaI9O25YQekBwgicxvnxGUubJE1Vz31RfDwrNHTXy43DgxrSVODAtjTRVZtg2RmlalRe3ZOkFNqDim-SireKHT5Q7ua4cIJWsip8XhgmWD61r_Wc70627D22iR-ZEpzE8XWCar0GWRFd9qIjk2fgQEFVTjF9dmMUwPdtv9qwDDMkHg1D_1cT6ddMaMBBtYkuwBbe46kvgdmAATp8crV23fVTfxWIGkpIMdnHcwJkt7wMSA_6820iU1Y7Fii_asFng0UG2gMXvE0AT2gdTWTRR8y_j4DX_-DWQZ1CPv1aCNl9xCKXXMjhAFOVuZA"
}
```

### Udap.Client

### Udap.Idp.Server

## Build and test

### Running tests

Run the WebApi.Tests.  This should result in all tests passing.  WebApi.Tests will test the Udap.Metadata.Server package, configured agains the FhirLabsApi and WeatherApi web service projects.  FhirLabsApi is a simple
