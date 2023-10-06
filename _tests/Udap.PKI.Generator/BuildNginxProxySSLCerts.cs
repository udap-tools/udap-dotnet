#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;
using Udap.Util.Extensions;
using Xunit.Abstractions;

namespace Udap.PKI.Generator;

[Collection("Udap.PKI.Generator")]
public class BuildNginxProxySSLCerts : CertificateBase
{
    private readonly ITestOutputHelper _testOutputHelper;

    private static string SureFhirLabsCertStore
    {
        get
        {
            var baseDir = BaseDir;

            return $"{baseDir}/certstores/nginx_proxy_ssl";
        }
    }
    
    public BuildNginxProxySSLCerts(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;

        IConfiguration config = new ConfigurationBuilder()
            .AddUserSecrets<SecretSettings>()
            .Build();

        DefaultPKCS12Password = config["CertPassword"];
    }

    [Fact(Skip = "Enabled on desktop when needed.")]
    public void MakeCaWithIntermediateUdapAndSSLForDefaultCommunity()
    {
        using (RSA parentRSAKey = RSA.Create(4096))
        {
            var parentReq = new CertificateRequest(
                "CN=ngnix-proxy-TestCA, OU=Root, O=Fhir Coding, L=Portland, S=Oregon, C=US",
                parentRSAKey,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            parentReq.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(true, false, 0, true));

            parentReq.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyCertSign,
                    true));

            parentReq.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(
                    new OidCollection
                    {
                        new Oid("1.3.6.1.5.5.7.3.2"), // TLS Client auth
                        new Oid("1.3.6.1.5.5.7.3.1"), // TLS Server auth
                        new Oid("1.3.6.1.5.5.7.3.8") // Time Stamping
                    },
                    true));

            parentReq.CertificateExtensions.Add(
                new X509SubjectKeyIdentifierExtension(parentReq.PublicKey, false));

            using (var caCert = parentReq.CreateSelfSigned(
                       DateTimeOffset.UtcNow.AddDays(-1),
                       DateTimeOffset.UtcNow.AddYears(10)))
            {
                var parentBytes = caCert.Export(X509ContentType.Pkcs12, "udap-test");
                SureFhirLabsCertStore.EnsureDirectoryExists();
                File.WriteAllBytes($"{SureFhirLabsCertStore}/ngnix-proxy-TestCA.pfx", parentBytes);
                char[] caPem = PemEncoding.Write("CERTIFICATE", caCert.RawData);
                File.WriteAllBytes($"{SureFhirLabsCertStore}/ngnix-proxy-TestCA.cer",
                    caPem.Select(c => (byte)c).ToArray());
                UpdateWindowsMachineStore(caCert);
                
            }
        }
    }

    public static IEnumerable<object[]> SSLProxyCerts()
    {
        yield return new object[]
        {
            "CN=fhirlabs.net",                  //DistinguishedName
            "fhirlabs.net"                      //SubjAltName
            
        };

        yield return new object[]
        {
            "CN=securedcontrols.net",                  //DistinguishedName
            "securedcontrols.net"                      //SubjAltName
            
        };

        yield return new object[]
        {
            "CN=idp1.securedcontrols.net",                  //DistinguishedName
            "idp1.securedcontrols.net"                      //SubjAltName
            
        };

        yield return new object[]
        {
            "CN=idp2.securedcontrols.net",                  //DistinguishedName
            "idp2.securedcontrols.net"                      //SubjAltName
            
        };

        yield return new object[]
        {
            "CN=qk1rg.wiremockapi.cloud",                  //DistinguishedName
            "qk1rg.wiremockapi.cloud"                      //SubjAltName
            
        };

        yield return new object[]
        {
            "CN=securefhir.zimt.work",                  //DistinguishedName
            "securefhir.zimt.work"                      //SubjAltName
            
        };

        yield return new object[]
        {
            "CN=udap.zimt.work",                  //DistinguishedName
            "udap.zimt.work"                      //SubjAltName
            
        };

        yield return new object[]
        {
            "CN=test.udap.org",                  //DistinguishedName
            "test.udap.org"                      //SubjAltName
            
        };

        yield return new object[]
        {
            "CN=mktac-restapis-stable.meditech.com",                  //DistinguishedName
            "mktac-restapis-stable.meditech.com"                      //SubjAltName
            
        };

        yield return new object[]
        {
            "CN=udap.fhir.poolnook.me",                  //DistinguishedName
            "udap.fhir.poolnook.me"                      //SubjAltName

        };

        yield return new object[]
        {
            "CN=udap.fast.poolnook.me", //DistinguishedName
            "udap.fast.poolnook.me" //SubjAltName

        };

        yield return new object[]
        {
            "CN=stage.healthtogo.me",                  //DistinguishedName
            "stage.healthtogo.me"                      //SubjAltName

        };
    }

    [Theory(Skip = "Enabled on desktop when needed.")]
    [MemberData(nameof(SSLProxyCerts))]
    public void MakeIdentityProviderCertificates(string dn, string san)
    {
        using var rootCA = new X509Certificate2($"{SureFhirLabsCertStore}/ngnix-proxy-TestCA.pfx", "udap-test");

        $"{SureFhirLabsCertStore}/ssl".EnsureDirectoryExists();

        BuildSslCertificate(
            rootCA,
            dn,
            san,
            $"{SureFhirLabsCertStore}/ssl/{san}"
        );
    }


    private X509Certificate2 BuildSslCertificate(
        X509Certificate2? caCert,
        string distinguishedName,
        string subjectAltNames,
        string sslCertFilePath,
        string? crl = default,
        // string? buildAIAExtensionsPath = null,
        DateTimeOffset notBefore = default,
        DateTimeOffset notAfter = default)
    {

        if (notBefore == default)
        {
            notBefore = DateTimeOffset.UtcNow;
        }

        if (notAfter == default)
        {
            notAfter = DateTimeOffset.UtcNow.AddYears(2);
        }


        using RSA rsaKey = RSA.Create(2048);

        var sslRequest = new CertificateRequest(
            distinguishedName,
            rsaKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        sslRequest.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, true));

        sslRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature,
                true));

        sslRequest.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(sslRequest.PublicKey, false));

        AddAuthorityKeyIdentifier(caCert, sslRequest, _testOutputHelper);

        if (crl != null)
        {
            sslRequest.CertificateExtensions.Add(MakeCdp(crl));
        }

        var subAltNameBuilder = new SubjectAlternativeNameBuilder();
        subAltNameBuilder.AddDnsName(subjectAltNames);
        var x509Extension = subAltNameBuilder.Build();
        sslRequest.CertificateExtensions.Add(x509Extension);

        sslRequest.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection {
                    new Oid("1.3.6.1.5.5.7.3.2"), // TLS Client auth
                    new Oid("1.3.6.1.5.5.7.3.1"), // TLS Server auth
                },
                true));

        var clientCert = sslRequest.Create(
            caCert,
            notBefore,
            notAfter,
            new ReadOnlySpan<byte>(RandomNumberGenerator.GetBytes(16)));
        // Do something with these certs, like export them to PFX,
        // or add them to an X509Store, or whatever.
        var clientCertWithKey = clientCert.CopyWithPrivateKey(rsaKey);


        var certPackage = new X509Certificate2Collection();
        certPackage.Add(clientCertWithKey);
        certPackage.Add(new X509Certificate2(caCert.Export(X509ContentType.Cert)));
        
        var clientBytes = certPackage.Export(X509ContentType.Pkcs12, "udap-test");
        File.WriteAllBytes($"{sslCertFilePath}.pfx", clientBytes);
        var clientPem = PemEncoding.Write("CERTIFICATE", clientCert.RawData);
        File.WriteAllBytes($"{sslCertFilePath}.cer", clientPem.Select(c => (byte)c).ToArray());
        File.WriteAllBytes($"{sslCertFilePath}.pem", clientPem.Select(c => (byte)c).ToArray());

        var key = PemEncoding.Write("RSA PRIVATE KEY", rsaKey.ExportRSAPrivateKey());
        File.WriteAllBytes($"{sslCertFilePath}.key", key.Select(c => (byte)c).ToArray());

        return clientCert;
    }

}
