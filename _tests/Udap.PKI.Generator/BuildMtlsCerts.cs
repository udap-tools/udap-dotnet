#region (c) 2024 Joseph Shook. All rights reserved.
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
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Udap.Support.Tests.Extensions;
using Xunit.Abstractions;
using X509Extensions = Org.BouncyCastle.Asn1.X509.X509Extensions;

namespace Udap.PKI.Generator;


public class BuildMtlsCerts : CertificateBase
{
    private readonly ITestOutputHelper _testOutputHelper;

    public BuildMtlsCerts(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;

        _ = new ConfigurationBuilder()
            .AddUserSecrets<SecretSettings>() 
            .Build();
    }

    //
    // Community:SureFhirmTLS:: Certificate Store File Constants
    //
    private static string SureFhirmTLSCertStore
    {
        get
        {
            var baseDir = BaseDir;

            return $"{baseDir}/certstores/Surefhir_mTLS";
        }
    }
    private static string SurefhirlabsCrl { get; } = $"{SureFhirmTLSCertStore}/crl";


    private static string SureFhirmTLSRootPkcsFileCrl { get; } = "SureFhirmTLSRootCrl.crl";
    private static readonly string sureFhirIntermediateCrlFilename = $"{SurefhirlabsCrl}/{SureFhirmTLSRootPkcsFileCrl}";
    private static string SureFhirmTLSIntermediatePkcsFileCrl { get; } = "SureFhirmTLSIntermediateCrl.crl";
    private static readonly string sureFhirClientCrlFilename = $"{SurefhirlabsCrl}/{SureFhirmTLSIntermediatePkcsFileCrl}";
    private static string SureFhirmTLSRootCrl { get; } = $"http://crl.fhircerts.net/crl/{SureFhirmTLSRootPkcsFileCrl}";
    private static string SureFhirmTLSIntermediateCrl { get; } = $"http://crl.fhircerts.net/crl/{SureFhirmTLSIntermediatePkcsFileCrl}";
    
    private static string SureFhirmTLSCaPublicCertHosted { get; } = $"http://crl.fhircerts.net/certs/SureFhirmTLS_CA.cer";
    private static string SureFhirmTLSIntermediatePublicCertHosted { get; } = "http://crl.fhircerts.net/certs/intermediates/SureFhirmTLS_Intermediate.cer";
    private static string SureFhirmTLSIntermediates { get; } = $"{SureFhirmTLSCertStore}/intermediates";
    private static string SureFhirmTLSIssued { get; } = $"{SureFhirmTLSCertStore}/issued";

    
    [Fact]
    public void Make_mTLS()
    {
        #region SureFhir CA

        using RSA parentRSAKey = RSA.Create(4096);
        using RSA intermediateRSAKey = RSA.Create(4096);
        var parentReq = new CertificateRequest(
            "CN=SureFhirmTLS-CA, OU=Root, O=Fhir Coding, L=Portland, S=Oregon, C=US",
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
            new X509SubjectKeyIdentifierExtension(parentReq.PublicKey, false));

        using var caCert = parentReq.CreateSelfSigned(
                   DateTimeOffset.UtcNow.AddDays(-1),
                   DateTimeOffset.UtcNow.AddYears(10));
        var parentBytes = caCert.Export(X509ContentType.Pkcs12, "udap-test");

        SureFhirmTLSCertStore.EnsureDirectoryExists();
        File.WriteAllBytes($"{SureFhirmTLSCertStore}/SureFhirmTLS_CA.pfx",
            parentBytes);
        char[] caPem = PemEncoding.Write("CERTIFICATE", caCert.RawData);
        File.WriteAllBytes($"{SureFhirmTLSCertStore}/SureFhirmTLS_CA.cer",
            caPem.Select(c => (byte)c).ToArray());
        UpdateWindowsMachineStore(caCert);

        var pemCert = File.ReadAllText($"{SureFhirmTLSCertStore}/SureFhirmTLS_CA.cer");
        File.WriteAllText($"{SureFhirmTLSCertStore}/SureFhirmTLS_CA_SingleLine.cer",
            pemCert.ReplaceLineEndings("\\n"));

        #endregion

        #region SureFireLabs Intermediate

        var intermediateReq = new CertificateRequest(
            "CN=SureFhirmTLS-Intermediate, OU=Intermediate, O=Fhir Coding, L=Portland, S=Oregon, C=US",
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
        intermediateReq.CertificateExtensions.Add(MakeCdp(SureFhirmTLSRootCrl));

        var authorityInfoAccessBuilder = new AuthorityInformationAccessBuilder();
        authorityInfoAccessBuilder.AddCertificateAuthorityIssuerUri(
            new Uri(SureFhirmTLSCaPublicCertHosted));
        var aiaExtension = authorityInfoAccessBuilder.Build();
        intermediateReq.CertificateExtensions.Add(aiaExtension);


        using var intermediateCertWithoutKey = intermediateReq.Create(
            caCert,
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(5),
            new ReadOnlySpan<byte>(RandomNumberGenerator.GetBytes(16)));
        var intermediateCertWithKey = intermediateCertWithoutKey.CopyWithPrivateKey(intermediateRSAKey);

        SureFhirmTLSIntermediates.EnsureDirectoryExists();
        var intermediateBytes = intermediateCertWithKey.Export(X509ContentType.Pkcs12, "udap-test");
        File.WriteAllBytes(
            $"{SureFhirmTLSIntermediates}/SureFhirmTLS_Intermediate.pfx",
            intermediateBytes);
        char[] intermediatePem = PemEncoding.Write("CERTIFICATE", intermediateCertWithoutKey.RawData);
        File.WriteAllBytes(
            $"{SureFhirmTLSIntermediates}/SureFhirmTLS_Intermediate.cer",
            intermediatePem.Select(c => (byte)c).ToArray());
        UpdateWindowsMachineStore(intermediateCertWithoutKey);

        var intermediateCert = File.ReadAllText($"{SureFhirmTLSIntermediates}/SureFhirmTLS_Intermediate.cer");
        File.WriteAllText($"{SureFhirmTLSIntermediates}/SureFhirmTLS_Intermediate_SingleLine.cer",
            intermediateCert.ReplaceLineEndings("\\n"));

        #endregion

        SureFhirmTLSIssued.EnsureDirectoryExists();

        #region mTLS Certificates

        BuildClientmTLSCertificate(
            intermediateCertWithoutKey,
            caCert,
            intermediateRSAKey,
            "E=Joseph.Shook@fhirlabs.net, CN=Joseph.Shook, OU=UDAP, O=Fhir Coding, L=Portland, S=Oregon, C=US",
            $"{SureFhirmTLSIssued}/FhirLabs_mTLS_Client",
            SureFhirmTLSIntermediateCrl,
            new List<string> { "joseph.shook@fhirlabs.net" },
            SureFhirmTLSIntermediatePublicCertHosted);

        BuildServermTLSCertificate(
            intermediateCertWithoutKey,
            caCert,
            intermediateRSAKey,
            "CN=server/emailAddress=support@fhirlabs.net, OU=UDAP, O=Fhir Coding, L=Portland, S=Oregon, C=US",
            $"{SureFhirmTLSIssued}/FhirLabs_mTLS_Server",
            SureFhirmTLSIntermediateCrl,
            new List<string> { "mtls.fhirlabs.net", "localhost" },
            SureFhirmTLSIntermediatePublicCertHosted);

        #endregion


        #region SureFhir Intermediate CRL

        // Certificate Revocation
        var bouncyCaCert = DotNetUtilities.FromX509Certificate(caCert);

        var crlIntermediateGen = new X509V2CrlGenerator();
        var intermediateNow = DateTime.UtcNow;
        crlIntermediateGen.SetIssuerDN(bouncyCaCert.SubjectDN);
        crlIntermediateGen.SetThisUpdate(intermediateNow);
        crlIntermediateGen.SetNextUpdate(intermediateNow.AddYears(1));

        //crlIntermediateGen.AddCrlEntry(BigInteger.One, intermediateNow, CrlReason.PrivilegeWithdrawn);

        crlIntermediateGen.AddExtension(X509Extensions.AuthorityKeyIdentifier,
            false,
            new AuthorityKeyIdentifierStructure(bouncyCaCert.GetPublicKey()));

        var nextsureFhirIntermediateCrlNum = GetNextCrlNumber(sureFhirIntermediateCrlFilename);

        crlIntermediateGen.AddExtension(X509Extensions.CrlNumber, false, nextsureFhirIntermediateCrlNum);

        // var intermediateRandomGenerator = new CryptoApiRandomGenerator();
        // var intermediateRandom = new SecureRandom(intermediateRandomGenerator);

        var intermediateAkp = DotNetUtilities.GetKeyPair(caCert.GetRSAPrivateKey()).Private;

        // var intermediateCrl = crlIntermediateGen.Generate(new Asn1SignatureFactory("SHA256WithRSAEncryption", intermediateAkp, intermediateRandom));
        var intermediateCrl = crlIntermediateGen.Generate(new Asn1SignatureFactory("SHA256WithRSAEncryption", intermediateAkp));

        SurefhirlabsCrl.EnsureDirectoryExists();
        File.WriteAllBytes(sureFhirIntermediateCrlFilename, intermediateCrl.GetEncoded());

        #endregion

        #region SureFhir client CRL

        // Certificate Revocation
        var bouncyIntermediateCert = DotNetUtilities.FromX509Certificate(intermediateCertWithKey);

        var crlGen = new X509V2CrlGenerator();
        var now = DateTime.UtcNow;
        crlGen.SetIssuerDN(bouncyIntermediateCert.SubjectDN);
        crlGen.SetThisUpdate(now);
        crlGen.SetNextUpdate(now.AddYears(1));
        // crlGen.SetSignatureAlgorithm("SHA256withRSA");

        //crlGen.AddCrlEntry(BigInteger.One, now, CrlReason.PrivilegeWithdrawn);

        crlGen.AddExtension(X509Extensions.AuthorityKeyIdentifier,
            false,
            new AuthorityKeyIdentifierStructure(bouncyIntermediateCert.GetPublicKey()));

        var nextSureFhirClientCrlNum = GetNextCrlNumber(sureFhirClientCrlFilename);

        crlGen.AddExtension(X509Extensions.CrlNumber, false, nextSureFhirClientCrlNum);


        // var randomGenerator = new CryptoApiRandomGenerator();
        // var random = new SecureRandom(randomGenerator);

        var Akp = DotNetUtilities.GetKeyPair(intermediateCertWithKey.GetRSAPrivateKey()).Private;

        //var crl = crlGen.Generate(Akp, random);
        var crl = crlGen.Generate(new Asn1SignatureFactory("SHA256WithRSAEncryption", Akp));

        SurefhirlabsCrl.EnsureDirectoryExists();
        File.WriteAllBytes(sureFhirClientCrlFilename, crl.GetEncoded());

        #endregion
    }

    
    private X509Certificate2 BuildClientmTLSCertificate(
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
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                true));

        clientCertRequest.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection
                {
                    new Oid("1.3.6.1.5.5.7.3.2"), // TLS Client auth
                },
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
                subAltNameBuilder.AddEmailAddress(subjectAltName);
            }
            var x509Extension = subAltNameBuilder.Build();
            clientCertRequest.CertificateExtensions.Add(x509Extension);
        }


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
        File.WriteAllText($"{clientCertFilePath}.key", rsaKey.ExportRSAPrivateKeyPem());

        return clientCert;
    }

    private X509Certificate2 BuildServermTLSCertificate(
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
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                true));

        clientCertRequest.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection
                {
                    new Oid("1.3.6.1.5.5.7.3.1"), // TLS Server auth
                },
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
                subAltNameBuilder.AddDnsName(subjectAltName);
            }
            var x509Extension = subAltNameBuilder.Build();
            clientCertRequest.CertificateExtensions.Add(x509Extension);
        }



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
        File.WriteAllText($"{clientCertFilePath}.key", rsaKey.ExportRSAPrivateKeyPem());

        return clientCert;
    }
}