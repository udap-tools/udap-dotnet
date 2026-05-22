#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Udap.Support.Tests.Extensions;
using Xunit.Abstractions;
using X509Extensions = Org.BouncyCastle.Asn1.X509.X509Extensions;
// ReSharper disable All
#pragma warning disable xUnit1004

namespace Udap.PKI.Generator;

/// <summary>
/// Generates a self-contained TEFCA test PKI hierarchy and client certificates.
///
/// The local test hierarchy simulates an RCE-issued trust chain:
///   TEFCA-Test-CA → TEFCA-Test-Intermediate → Client Certificates
///
/// Client certificates are issued with SAN URIs containing exchange purposes
/// in the path, per SOP: Facilitated FHIR Implementation v2.0 Section 6.11 Registration #5a.
///
/// Two variants are generated:
///   - TEFCA_Community: AIA/CRL point to crl.fhircerts.net (for deployment)
///   - TEFCA_Community_Desk: AIA/CRL point to host.docker.internal:5033 (for local dev)
///
/// <a href="https://rce.sequoiaproject.org/wp-content/uploads/2026/02/SOP-Facilitated-FHIR-Implementation-2.0-Draft-508.pdf#page=14">SOP v2.0 — Section 6.11</a>
/// </summary>
public class TefcaBuild : CertificateBase
{
    private readonly ITestOutputHelper _testOutputHelper;

    public TefcaBuild(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
    }

    /// <summary>
    /// Generates TEFCA PKI for deployment — AIA/CRL URLs point to crl.fhircerts.net.
    /// Output directory: certstores/TEFCA_Community
    /// </summary>
    [Fact]
    public void BuildTefcaTestPki()
    {
        var config = new TefcaPkiConfig
        {
            CertStoreName = "TEFCA_Community",
            IntermediateCrlFilename = "TefcaTestIntermediateCrl.crl",
            RootCrlFilename = "TefcaTestRootCrl.crl",
            CrlBaseUrl = "http://crl.fhircerts.net/crl",
            CaPublicCertUrl = "http://crl.fhircerts.net/certs/TEFCA_Test_CA.cer",
            IntermediatePublicCertUrl = "http://crl.fhircerts.net/certs/intermediates/TEFCA_Test_Intermediate.cer",
            ServerSans = new List<string>
            {
                "https://fhirlabs.net/fhir/r4"
            }
        };

        BuildTefcaPki(config);
    }

    /// <summary>
    /// Generates TEFCA PKI for local desktop development — AIA/CRL URLs point to
    /// host.docker.internal:5033 (Udap.Certificates.Server).
    /// Output directory: certstores/TEFCA_Community_Desk
    /// </summary>
    [Fact]
    public void BuildTefcaTestPkiDesk()
    {
        var config = new TefcaPkiConfig
        {
            CertStoreName = "TEFCA_Community_Desk",
            IntermediateCrlFilename = "TefcaTestIntermediateCrl.crl",
            RootCrlFilename = "TefcaTestRootCrl.crl",
            CrlBaseUrl = "http://host.docker.internal:5033/crl",
            CaPublicCertUrl = "http://host.docker.internal:5033/certs/TEFCA_Test_CA.cer",
            IntermediatePublicCertUrl = "http://host.docker.internal:5033/certs/intermediates/TEFCA_Test_Intermediate.cer",
            ServerSans = new List<string>
            {
                "https://localhost:7016/fhir/r4",
                "https://localhost:7074/fhir/r4"
            }
        };

        BuildTefcaPki(config, distribute: true);
    }

    /// <summary>
    /// Core PKI generation method parameterized by URL configuration.
    ///
    /// Hierarchy:
    ///   TEFCA-Test-CA (Root, self-signed, 4096-bit RSA)
    ///     └── TEFCA-Test-Intermediate (Intermediate CA, 4096-bit RSA)
    ///           ├── T-TRTMNT client cert (SAN: urn:oid:2.999#T-TRTMNT)
    ///           ├── T-IAS client cert (SAN: urn:oid:2.999#T-IAS)
    ///           ├── T-TREAT client cert (SAN: urn:oid:2.999#T-TREAT)
    ///           ├── T-PYMNT client cert (SAN: urn:oid:2.999#T-PYMNT)
    ///           └── server cert (SANs: fhirlabs.net, localhost:7016, localhost:7074)
    /// </summary>
    private void BuildTefcaPki(TefcaPkiConfig config, bool distribute = false)
    {
        var certStore = $"{BaseDir}/certstores/{config.CertStoreName}";
        var intermediatesDir = $"{certStore}/intermediates";
        var issuedDir = $"{certStore}/issued";
        var crlDir = $"{certStore}/crl";

        var rootCrlHosted = $"{config.CrlBaseUrl}/{config.RootCrlFilename}";
        var intermediateCrlHosted = $"{config.CrlBaseUrl}/{config.IntermediateCrlFilename}";

        certStore.EnsureDirectoryExists();
        intermediatesDir.EnsureDirectoryExists();
        issuedDir.EnsureDirectoryExists();
        crlDir.EnsureDirectoryExists();

        #region TEFCA Test Root CA

        using RSA caKey = RSA.Create(4096);
        using RSA intermediateKey = RSA.Create(4096);

        var caReq = new CertificateRequest(
            "CN=TEFCA-Test-CA, OU=Root, O=Fhir Coding, L=Portland, S=Oregon, C=US",
            caKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        caReq.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(true, false, 0, true));

        caReq.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyCertSign,
                true));

        caReq.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(caReq.PublicKey, false));

        using var caCert = caReq.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(10));

        var caBytes = caCert.Export(X509ContentType.Pkcs12, "udap-test");
        File.WriteAllBytes($"{certStore}/TEFCA_Test_CA.pfx", caBytes);
        var caPem = PemEncoding.Write("CERTIFICATE", caCert.RawData);
        File.WriteAllBytes($"{certStore}/TEFCA_Test_CA.cer",
            caPem.Select(c => (byte)c).ToArray());

        #endregion

        #region TEFCA Test Intermediate CA

        var intermediateReq = new CertificateRequest(
            "CN=TEFCA-Test-Intermediate, OU=Intermediate, O=Fhir Coding, L=Portland, S=Oregon, C=US",
            intermediateKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        intermediateReq.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(true, false, 0, true));

        intermediateReq.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyCertSign,
                true));

        intermediateReq.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(intermediateReq.PublicKey, false));

        AddAuthorityKeyIdentifier(caCert, intermediateReq, _testOutputHelper);
        intermediateReq.CertificateExtensions.Add(MakeCdp(rootCrlHosted));

        var authorityInfoAccessBuilder = new AuthorityInformationAccessBuilder();
        authorityInfoAccessBuilder.AddCertificateAuthorityIssuerUri(new Uri(config.CaPublicCertUrl));
        intermediateReq.CertificateExtensions.Add(authorityInfoAccessBuilder.Build());

        using var intermediateCert = intermediateReq.Create(
            caCert,
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(5),
            new ReadOnlySpan<byte>(RandomNumberGenerator.GetBytes(16)));
        var intermediateCertWithKey = intermediateCert.CopyWithPrivateKey(intermediateKey);

        var intermediateBytes = intermediateCertWithKey.Export(X509ContentType.Pkcs12, "udap-test");
        File.WriteAllBytes($"{intermediatesDir}/TEFCA_Test_Intermediate.pfx", intermediateBytes);
        var intermediatePem = PemEncoding.Write("CERTIFICATE", intermediateCert.RawData);
        File.WriteAllBytes($"{intermediatesDir}/TEFCA_Test_Intermediate.cer",
            intermediatePem.Select(c => (byte)c).ToArray());

        #endregion

        #region Initial CRLs (empty, no revocations)

        GenerateInitialCrl(
            caCert, caKey,
            $"{crlDir}/{config.RootCrlFilename}");

        GenerateInitialCrl(
            intermediateCertWithKey, intermediateKey,
            $"{crlDir}/{config.IntermediateCrlFilename}");

        #endregion

        #region Client Certificate with all Exchange Purposes in SAN

        // Single client cert with all XP codes plus one invalid SAN for testing
        BuildTefcaClientCert(
            intermediateCert, caCert, intermediateKey,
            "all-xp",
            new List<string>
            {
                "urn:oid:2.999#T-TRTMNT",
                "urn:oid:2.999#T-TREAT",
                "urn:oid:2.999#T-PYMNT",
                "urn:oid:2.999#T-HCO",
                "urn:oid:2.999#T-HCO-CC",
                "urn:oid:2.999#T-HCO-HED",
                "urn:oid:2.999#T-HCO-QM",
                "urn:oid:2.999#T-PH",
                "urn:oid:2.999#T-PH-ECR",
                "urn:oid:2.999#T-PH-ELR",
                "urn:oid:2.999#T-IAS",
                "urn:oid:2.999#T-GOVDTRM",
                "urn:oid:2.999#INVALID"
            },
            $"{issuedDir}/fhirlabs.net.tefca.client",
            intermediateCrlHosted, config.IntermediatePublicCertUrl);

        #endregion

        #region Server Certificate (for signing UDAP metadata)

        BuildTefcaClientCert(
            intermediateCert, caCert, intermediateKey,
            "server",
            config.ServerSans,
            $"{issuedDir}/fhirlabs.net.tefca.server",
            intermediateCrlHosted, config.IntermediatePublicCertUrl);

        #endregion

        #region Distribute to example projects

        if (distribute)
        {
            var fhirLabsApi = $"{BaseDir}/../../examples/FhirLabsApi";
            var authServer = $"{BaseDir}/../../examples/Udap.Auth.Server";
            var certServer = $"{BaseDir}/../../examples/Udap.Certificates.Server/wwwroot";

            // FhirLabsApi: only the server endcert for signing UDAP metadata
            $"{fhirLabsApi}/CertStore/issued".EnsureDirectoryExists();
            File.Copy($"{issuedDir}/fhirlabs.net.tefca.server.pfx",
                $"{fhirLabsApi}/CertStore/issued/fhirlabs.net.tefca.server.pfx", true);

            // Udap.Auth.Server: only the server endcert for signing UDAP metadata
            // (anchors and intermediates go in the database via UdapDb migrations)
            $"{authServer}/CertStore/issued".EnsureDirectoryExists();
            File.Copy($"{issuedDir}/fhirlabs.net.tefca.server.pfx",
                $"{authServer}/CertStore/issued/fhirlabs.net.tefca.server.pfx", true);

            // Udap.Certificates.Server: CA anchor (AIA), intermediate cert (AIA), and CRLs (CDP)
            // for local desktop resolution of certificate chain
            $"{certServer}/certs/intermediates".EnsureDirectoryExists();
            File.Copy($"{certStore}/TEFCA_Test_CA.cer",
                $"{certServer}/certs/TEFCA_Test_CA.cer", true);
            File.Copy($"{intermediatesDir}/TEFCA_Test_Intermediate.cer",
                $"{certServer}/certs/intermediates/TEFCA_Test_Intermediate.cer", true);
            File.Copy($"{crlDir}/{config.RootCrlFilename}",
                $"{certServer}/crl/{config.RootCrlFilename}", true);
            File.Copy($"{crlDir}/{config.IntermediateCrlFilename}",
                $"{certServer}/crl/{config.IntermediateCrlFilename}", true);

            _testOutputHelper.WriteLine(
                $"[{config.CertStoreName}] Distributed TEFCA certs to FhirLabsApi, Udap.Auth.Server, and Udap.Certificates.Server");
        }

        #endregion
    }

    private X509Certificate2 BuildTefcaClientCert(
        X509Certificate2 intermediateCert,
        X509Certificate2 caCert,
        RSA intermediateKey,
        string exchangePurpose,
        List<string> subjectAltNames,
        string clientCertFilePath,
        string cdpUrl,
        string aiaUrl)
    {
        var distinguishedName =
            "CN=TEFCA-Mock, OU=TEFCA-TEST, O=Fhir Coding, L=Portland, S=Oregon, C=US";

        var intermediateCertWithKey = intermediateCert.HasPrivateKey
            ? intermediateCert
            : intermediateCert.CopyWithPrivateKey(intermediateKey);

        using RSA rsaKey = RSA.Create(2048);

        var clientReq = new CertificateRequest(
            distinguishedName,
            rsaKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        clientReq.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, true));

        clientReq.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature,
                true));

        clientReq.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(clientReq.PublicKey, false));

        AddAuthorityKeyIdentifier(intermediateCert, clientReq, _testOutputHelper);
        clientReq.CertificateExtensions.Add(MakeCdp(cdpUrl));

        var subAltNameBuilder = new SubjectAlternativeNameBuilder();
        foreach (var san in subjectAltNames)
        {
            subAltNameBuilder.AddUri(new Uri(san));
        }
        clientReq.CertificateExtensions.Add(subAltNameBuilder.Build());

        var aiaBuilder = new AuthorityInformationAccessBuilder();
        aiaBuilder.AddCertificateAuthorityIssuerUri(new Uri(aiaUrl));
        clientReq.CertificateExtensions.Add(aiaBuilder.Build());

        var clientCert = clientReq.Create(
            intermediateCertWithKey,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddYears(2),
            new ReadOnlySpan<byte>(RandomNumberGenerator.GetBytes(16)));

        var clientCertWithKey = clientCert.CopyWithPrivateKey(rsaKey);

        var certPackage = new X509Certificate2Collection();
        certPackage.Add(clientCertWithKey);
#if NET9_0_OR_GREATER
        certPackage.Add(X509CertificateLoader.LoadCertificate(intermediateCert.Export(X509ContentType.Cert)));
        certPackage.Add(X509CertificateLoader.LoadCertificate(caCert.Export(X509ContentType.Cert)));
#else
        certPackage.Add(new X509Certificate2(intermediateCert.Export(X509ContentType.Cert)));
        certPackage.Add(new X509Certificate2(caCert.Export(X509ContentType.Cert)));
#endif

        var clientBytes = certPackage.Export(X509ContentType.Pkcs12, "udap-test");
        File.WriteAllBytes($"{clientCertFilePath}.pfx", clientBytes!);
        var clientPem = PemEncoding.Write("CERTIFICATE", clientCert.RawData);
        File.WriteAllBytes($"{clientCertFilePath}.cer",
            clientPem.Select(c => (byte)c).ToArray());

        _testOutputHelper.WriteLine(
            $"Generated TEFCA {exchangePurpose} client cert: {clientCertFilePath}.pfx");

        return clientCert;
    }

    /// <summary>
    /// Generates an initial empty CRL (no revocations) for the given CA certificate.
    /// The CRL is compatible with the Udap.Pki.Cli renewal tool — it can be uploaded
    /// to GCP and renewed using the update-crl command.
    /// </summary>
    private void GenerateInitialCrl(X509Certificate2 caCert, RSA caPrivateKey, string crlFilePath)
    {
        var bouncyCaCert = DotNetUtilities.FromX509Certificate(caCert);
        var bouncyPrivateKey = DotNetUtilities.GetKeyPair(caPrivateKey).Private;

        var crlGen = new X509V2CrlGenerator();
        var now = DateTime.UtcNow;
        crlGen.SetIssuerDN(bouncyCaCert.SubjectDN);
        crlGen.SetThisUpdate(now);
        crlGen.SetNextUpdate(now.AddDays(30));

        // No revocations in initial CRL

        crlGen.AddExtension(X509Extensions.AuthorityKeyIdentifier,
            false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bouncyCaCert.GetPublicKey())));

        crlGen.AddExtension(X509Extensions.CrlNumber, false, new CrlNumber(BigInteger.One));

        var crl = crlGen.Generate(new Asn1SignatureFactory("SHA256WithRSAEncryption", bouncyPrivateKey));
        File.WriteAllBytes(crlFilePath, crl.GetEncoded());

        _testOutputHelper.WriteLine($"Generated initial CRL: {crlFilePath}");
    }

    private class TefcaPkiConfig
    {
        public required string CertStoreName { get; init; }
        public required string IntermediateCrlFilename { get; init; }
        public required string RootCrlFilename { get; init; }
        public required string CrlBaseUrl { get; init; }
        public required string CaPublicCertUrl { get; init; }
        public required string IntermediatePublicCertUrl { get; init; }
        public required List<string> ServerSans { get; init; }
    }
}
