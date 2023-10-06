# Udap.Client

![UDAP logo](https://avatars.githubusercontent.com/u/77421324?s=48&v=4)

## 📦 Nuget Package: [Udap.Client](https://www.nuget.org/packages?q=udap.client)

## Udap.Config simple dependency injection example configuration

If you chose to load a trust anchor yourself or non at all then registration can be a simple as the following.

```csharp
builder.Services.AddScoped<TrustChainValidator>();
builder.Services.AddHttpClient<IUdapClient, UdapClient>();
```

The Udap.Client returns a ```UdapDiscoveryDocumentResponse``` .  For convenience it contains a IsError property.  If you need to understand why there is an error then you can investigate the ```Error```, ```Exception```, ```ErrorType```, and ```HttpErrorReason``` depending on the reason for the error.  There are also events you can subscribe to to get details about JWT and Certificate chaining errors.  The Problem events come from the ```TrustChainValidator``` and are very useful.  See example below.

```csharp
var udapClient = serviceProvider.GetRequiredService<IUdapClient>();
var loggerFactory = serviceProvider.GetRequiredService<ILoggerFactory>();
var logger = loggerFactory.CreateLogger(typeof(Program));

udapClient.Problem += element => logger.LogWarning(element.ChainElementStatus
    .Summarize(TrustChainValidator.DefaultProblemFlags));

udapClient.Untrusted += certificate2 => logger.LogWarning("Untrusted: " + certificate2.Subject);
udapClient.TokenError += message => logger.LogWarning("TokenError: " + message);

var response = await udapClient.ValidateResource(options.BaseUrl, trustAnchorStore, community);

if (response.IsError)
{
    logger.LogError(response.HttpErrorReason);
}
else
{
    logger.LogInformation(JsonSerializer.Serialize(
        response, 
        new JsonSerializerOptions{WriteIndented = true})); 
}

```

Experiment with this example code in the [1_UdapClientMetadata CLI Project](../../examples/clients/1_UdapClientMetadata)

Example command line run: ```dotnet run  --baseUrl https://fhirlabs.net/fhir/r4 --trustAnchor "C:\SureFhirLabs_CA.cer" --community udap://ECDSA/```
 
 ---

 **NOTE** The above example [trust anchor (download)](https://storage.googleapis.com/crl.fhircerts.net/certs/SureFhirLabs_CA.cer) is used by most communities in the https://fhirlabs.net/fhir/r4 test server.

---

## Udap.Client configuration with a ITrustAnchorStore implementation

Implement the ITrustAnchorStore to load trust anchors from a store.  Below is dependency injection example of a file system store implementation.  Note the CertStore folder in this project with anchors and intermediates folders.  Also take note of the ```appsettings.json``` configuration.  Notice each community has an Anchors and Intermediates collection of file references.  In accompanying example project all communities issue certificates through a sub-certificate authority, yet the configuration only configured one Intermediate.  Why is this?  If the published certificate at the resource ```./well-known/udap``` endpoint contains a AIA extension then the .NET ```X509Chain.Build``` method will follow the URL in the extension.  This is true on Windows and Linux.  Some Certificate Authorities may not follow this practice and you will have to configure for the intermediate certificate.  

---
Note: An anchor must be chosen for each community.  When you receive signed metadata the client will proceed to build a certificate chain from the first x5c header certificate and the anchor as the root certificate.  

---

There is another way for intermediate certificates to be discovered.  That is within the x5c header of the signed metadata.  While the first certificate in the x5c header must be the signing certificate, the rest of the certificates may be the rest of the chain.  But again you must have an anchor deliberately chosen and loaded into the client.  The client will no load and trust an anchor from the x5c header.

<details><summary><a>View Metadata</></summary>

```json
"UdapFileCertStoreManifest": {
  "Communities": [
    {
      "Name": "udap://stage.healthtogo.me/",
      "Anchors": [
        {
          "FilePath": "CertStore/anchors/EMRDirectTestCA.crt"
        }
      ]
    },
    {
      "Name": "udap://fhirlabs.net/",
      "Intermediates": [
        "CertStore/intermediates/SureFhirLabs_Intermediate.cer"
      ],
      "Anchors": [
        {
          "FilePath": "CertStore/anchors/SureFhirLabs_CA.cer"
        }
      ]
    },
    {
      "Name": "udap://expired.fhirlabs.net/",
      "Anchors": [
        {
          "FilePath": "CertStore/anchors/SureFhirLabs_CA.cer"
        }
      ]
    },
    {
      "Name": "udap://revoked.fhirlabs.net/",
      "Anchors": [
        {
          "FilePath": "CertStore/anchors/SureFhirLabs_CA.cer"
        }
      ]
    },
    {
      "Name": "udap://untrusted.fhirlabs.net/",
      "Anchors": [
        {
          "FilePath": "CertStore/anchors/SureFhirLabs_CA.cer"
        }
      ]
    },
    {
      "Name": "udap://Iss.Miss.Match.To.SubjAltName/",
      "Anchors": [
        {
          "FilePath": "CertStore/anchors/SureFhirLabs_CA.cer"
        }
      ]
    },
    {
      "Name": "udap://Iss.Miss.Match.To.BaseUrl//",
      "Anchors": [
        {
          "FilePath": "CertStore/anchors/SureFhirLabs_CA.cer"
        }
      ]
    },
    {
      "Name": "udap://ECDSA/",
      "Anchors": [
        {
          "FilePath": "CertStore/anchors/SureFhirLabs_CA.cer"
        }
      ]
    }
  ]
}
```

</details>
<br/>

```csharp
services.Configure<UdapFileCertStoreManifest>(context.Configuration.GetSection("UdapFileCertStoreManifest"));
services.AddSingleton<ITrustAnchorStore, TrustAnchorFileStore>();
services.AddScoped<TrustChainValidator>();
services.AddHttpClient<IUdapClient, UdapClient>();
```

Experiment with this example code in the [1_UdapClientMetadata CLI Project](../../examples/clients/2_UdapClientMetadata)

## Udap.Client advanced configuration

The TrustChainValidator a couple ways to control it's behavior when validating a chain.  One is the control the ```Problem Flags``` identified in the .NET ```X509ChainStatusFlags``` settings.  The defaults are recommended.  Perhaps you are running some unit tests that do not publish a certificate revocation list.  Then your code might look something like the following where we mask out ```OfflineRevocation``` and ```RevocationStatusUnknown``` flags.

```csharp
services.Configure<UdapFileCertStoreManifest>(context.Configuration.GetSection("UdapFileCertStoreManifest"));
                    
var problemFlags = X509ChainStatusFlags.NotTimeValid |
                    X509ChainStatusFlags.Revoked |
                    X509ChainStatusFlags.NotSignatureValid |
                    X509ChainStatusFlags.InvalidBasicConstraints |
                    X509ChainStatusFlags.CtlNotTimeValid |
                    X509ChainStatusFlags.UntrustedRoot |
                    // X509ChainStatusFlags.OfflineRevocation |
                    X509ChainStatusFlags.CtlNotSignatureValid;
                    // X509ChainStatusFlags.RevocationStatusUnknown;

services.AddSingleton<ITrustAnchorStore, TrustAnchorFileStore>();
services.AddScoped<TrustChainValidator>(sp => new TrustChainValidator(new X509ChainPolicy(), problemFlags, sp.GetService<ILogger<TrustChainValidator>>()));
services.AddHttpClient<IUdapClient, UdapClient>();
```

TODO: Cover X509ChainPolicy


## Udap.Client Dynamic Client Registration with a ICertificateStore implementation

### Example projects

- [Udap.Config simple dependency injection](./examples/clients/1_UdapClientMetadata/README.md)
- [Udap.Client configuration with a ITrustAnchorStore implementation](./examples/clients/2_UdapClientMetadata/README.md)
