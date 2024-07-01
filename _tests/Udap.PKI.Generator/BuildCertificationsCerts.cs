using Microsoft.Extensions.Configuration;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using Udap.Util.Extensions;
using Xunit.Abstractions;
using System.Formats.Asn1;
using static Udap.Common.Standard.ObjectIdentifiers.UdapExperimental;

namespace Udap.PKI.Generator;

[Collection("Udap.PKI.Generator")]
public class BuildCertificationsCerts : CertificateBase
{
    private readonly ITestOutputHelper _testOutputHelper;

    public BuildCertificationsCerts(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;

        IConfiguration config = new ConfigurationBuilder()
            .AddUserSecrets<SecretSettings>()
            .Build();
    }

    //
    // Community:SureFhirCertificationLabs:: Certificate Store File Constants
    //
    private static string SureFhirCertificationLabsCertStore
    {
        get
        {
            var baseDir = BaseDir;

            return $"{baseDir}/certstores/SurefhirCertificationLabs_Community";
        }
    }

    private static string SureFhirCertificationLabsRootPkcsFileCrl { get; } = "SureFhirCertificationLabsRootCrl.crl";
    private static string SureFhirCertificationLabsIntermediatePkcsFileCrl { get; } = "SureFhirCertificationLabsIntermediateCrl.crl";
    private static string SureFhirCertificationLabsRootCrl { get; } = $"http://crl.fhircerts.net/crl/{SureFhirCertificationLabsRootPkcsFileCrl}";
    private static string SureFhirCertificationLabsIntermediateCrl { get; } = $"http://crl.fhircerts.net/crl/{SureFhirCertificationLabsIntermediatePkcsFileCrl}";
    private static string SureFhirCertificationLabsCaPublicCertHosted { get; } = $"http://crl.fhircerts.net/certs/SureFhirCertificationLabs_CA.cer";
    private static string SureFhirCertificationLabsIntermediatePublicCertHosted { get; } = "http://crl.fhircerts.net/certs/intermediates/SureFhirCertificationLabs_Intermediate.cer";
    private static string SureFhirCertificationLabsUdapIntermediates { get; } = $"{SureFhirCertificationLabsCertStore}/intermediates";
    private static string SureFhirCertificationLabsUdapIssued { get; } = $"{SureFhirCertificationLabsCertStore}/issued";

    /// <summary>
    /// 
    /// default community uri = udap://fhirlabs.net
    ///
    /// </summary>
    [Fact]
    public void MakeCaWithIntermediateUdapAndSSLForDefaultCommunity()
    {
        Console.WriteLine("*************************************");
        Console.WriteLine(BaseDir);
        Console.WriteLine("*************************************");


        #region SureFhir CA

        using (RSA parentRSAKey = RSA.Create(4096))
        using (RSA intermediateRSAKey = RSA.Create(4096))
        {
            var parentReq = new CertificateRequest(
                "CN=SureFhirCertification-CA, OU=Root, O=Fhir Coding, L=Portland, S=Oregon, C=US",
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
                SureFhirCertificationLabsCertStore.EnsureDirectoryExists();
                File.WriteAllBytes($"{SureFhirCertificationLabsCertStore}/SureFhirCertificationLabs_CA.pfx",
                    parentBytes);
                char[] caPem = PemEncoding.Write("CERTIFICATE", caCert.RawData);
                File.WriteAllBytes($"{SureFhirCertificationLabsCertStore}/SureFhirCertificationLabs_CA.cer",
                    caPem.Select(c => (byte)c).ToArray());
                UpdateWindowsMachineStore(caCert);

                #endregion

                #region SureFireLabs Intermediate

                var intermediateReq = new CertificateRequest(
                    "CN=SureFhirCertification-Intermediate, OU=Intermediate, O=Fhir Coding, L=Portland, S=Oregon, C=US",
                    intermediateRSAKey,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);

                // Referred to as intermediate Cert or Intermediate
                intermediateReq.CertificateExtensions.Add(
                    new X509BasicConstraintsExtension(true, false, 0, true));

                intermediateReq.CertificateExtensions.Add(
                    new X509KeyUsageExtension(
                        X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyCertSign,
                        true));

                intermediateReq.CertificateExtensions.Add(
                    new X509SubjectKeyIdentifierExtension(intermediateReq.PublicKey, false));

                AddAuthorityKeyIdentifier(caCert, intermediateReq, _testOutputHelper);
                intermediateReq.CertificateExtensions.Add(MakeCdp(SureFhirCertificationLabsRootCrl));



                var subAltNameBuilder = new SubjectAlternativeNameBuilder();
                subAltNameBuilder.AddUri(
                    new Uri("udap://fhirlabs.net")); // embedding a community uri in intermediate cert
                var x509Extension = subAltNameBuilder.Build();
                intermediateReq.CertificateExtensions.Add(x509Extension);

                var authorityInfoAccessBuilder = new AuthorityInformationAccessBuilder();
                authorityInfoAccessBuilder.AddCertificateAuthorityIssuerUri(
                    new Uri(SureFhirCertificationLabsCaPublicCertHosted));
                var aiaExtension = authorityInfoAccessBuilder.Build();
                intermediateReq.CertificateExtensions.Add(aiaExtension);


                using var intermediateCertWithoutKey = intermediateReq.Create(
                    caCert,
                    DateTimeOffset.UtcNow.AddDays(-1),
                    DateTimeOffset.UtcNow.AddYears(5),
                    new ReadOnlySpan<byte>(RandomNumberGenerator.GetBytes(16)));
                var intermediateCertWithKey = intermediateCertWithoutKey.CopyWithPrivateKey(intermediateRSAKey);

                SureFhirCertificationLabsUdapIntermediates.EnsureDirectoryExists();
                var intermediateBytes = intermediateCertWithKey.Export(X509ContentType.Pkcs12, "udap-test");
                File.WriteAllBytes(
                    $"{SureFhirCertificationLabsUdapIntermediates}/SureFhirCertificationLabs_Intermediate.pfx",
                    intermediateBytes);
                char[] intermediatePem = PemEncoding.Write("CERTIFICATE", intermediateCertWithoutKey.RawData);
                File.WriteAllBytes(
                    $"{SureFhirCertificationLabsUdapIntermediates}/SureFhirCertificationLabs_Intermediate.cer",
                    intermediatePem.Select(c => (byte)c).ToArray());
                UpdateWindowsMachineStore(intermediateCertWithoutKey);

                #endregion

                SureFhirCertificationLabsUdapIssued.EnsureDirectoryExists();

                #region Administration Certification

                BuildClientCertificationCertificate(
                    intermediateCertWithoutKey,
                    caCert,
                    intermediateRSAKey,
                    "CN=FhirLabs Administrator, OU=UDAP, O=Fhir Coding, L=Portland, S=Oregon, C=US",
                    $"{SureFhirCertificationLabsUdapIssued}/FhirLabsAdminCertification",
                    SureFhirCertificationLabsIntermediateCrl,
                    null, //No Subject Alt Name
                    SureFhirCertificationLabsIntermediatePublicCertHosted);

                #endregion
            }
        }
    }


    private X509Certificate2 BuildClientCertificationCertificate(
            X509Certificate2 intermediateCert,
            X509Certificate2 caCert,
            RSA intermediateKey,
            string distinguishedName,
            string clientCertFilePath,
            string? crl,
            List<string>? subjectAltNames = null,
            string? buildAIAExtensionsPath = null,
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


        var intermediateCertWithKey = intermediateCert.HasPrivateKey ?
            intermediateCert :
            intermediateCert.CopyWithPrivateKey(intermediateKey);

        using RSA rsaKey = RSA.Create(2048);

        var clientCertRequest = new CertificateRequest(
            distinguishedName,
            rsaKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        clientCertRequest.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, true));

        clientCertRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature,
                true));

        clientCertRequest.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(clientCertRequest.PublicKey, false));

        AddAuthorityKeyIdentifier(intermediateCert, clientCertRequest, _testOutputHelper);

        if (crl != null)
        {
            clientCertRequest.CertificateExtensions.Add(MakeCdp(crl));
        }

        if (subjectAltNames != null)
        {
            var subAltNameBuilder = new SubjectAlternativeNameBuilder();
            foreach (var subjectAltName in subjectAltNames)
            {
                subAltNameBuilder.AddUri(new Uri(subjectAltName)); //Same as iss claim
            }
            var x509Extension = subAltNameBuilder.Build();
            clientCertRequest.CertificateExtensions.Add(x509Extension);
        }

        var certificatePolicyBuilder = new CertificatePolicyBuilder();
        certificatePolicyBuilder.AddPolicyOid(UdapAccessControl.General.Admin); 
        // certificatePolicyBuilder.AddPolicyOid("1.3.6.1.4.1.12345.1.2");
        certificatePolicyBuilder.AddPolicyOid("1.3.6.1.4.1.123456.1.2", "https://acme.local/cps");  // Some private policy
        var policyExtension = certificatePolicyBuilder.Build();
        clientCertRequest.CertificateExtensions.Add(policyExtension);
        

        if (buildAIAExtensionsPath != null)
        {
            var authorityInfoAccessBuilder = new AuthorityInformationAccessBuilder();
            authorityInfoAccessBuilder.AddCertificateAuthorityIssuerUri(new Uri(buildAIAExtensionsPath));
            var aiaExtension = authorityInfoAccessBuilder.Build();
            clientCertRequest.CertificateExtensions.Add(aiaExtension);
        }

        var clientCert = clientCertRequest.Create(
            intermediateCertWithKey,
            notBefore,
            notAfter,
            new ReadOnlySpan<byte>(RandomNumberGenerator.GetBytes(16)));
        // Do something with these certs, like export them to PFX,
        // or add them to an X509Store, or whatever.
        var clientCertWithKey = clientCert.CopyWithPrivateKey(rsaKey);


        var certPackage = new X509Certificate2Collection();
        certPackage!.Add(clientCertWithKey);
        certPackage.Add(new X509Certificate2(intermediateCert.Export(X509ContentType.Cert)));
        certPackage.Add(new X509Certificate2(caCert.Export(X509ContentType.Cert)));

        var clientBytes = certPackage.Export(X509ContentType.Pkcs12, "udap-test");
        File.WriteAllBytes($"{clientCertFilePath}.pfx", clientBytes!);
        var clientPem = PemEncoding.Write("CERTIFICATE", clientCert.RawData);
        File.WriteAllBytes($"{clientCertFilePath}.cer", clientPem.Select(c => (byte)c).ToArray());

        return clientCert;
    }

}