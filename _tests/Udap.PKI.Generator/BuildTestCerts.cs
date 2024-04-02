#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Reflection;
using System.Resources;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Configuration;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Udap.Util.Extensions;
using Xunit.Abstractions;
using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;
using X509Extensions = Org.BouncyCastle.Asn1.X509.X509Extensions;

namespace Udap.PKI.Generator
{

    [Collection("Udap.PKI.Generator")]
    public class MakeCa : CertificateBase
    {
        private readonly ITestOutputHelper _testOutputHelper;


        //
        // Community:SureFhirLabs:: Certificate Store File Constants
        //
        private static string SureFhirLabsCertStore
        {
            get
            {
                var baseDir = BaseDir;

                return $"{baseDir}/certstores/surefhirlabs_community";
            }
        }

       
        private static string SurefhirlabsCrl { get; } = $"{SureFhirLabsCertStore}/crl";

        private static string SureFhirLabsIntermediatePkcsFileCrl { get; } = "surefhirlabsIntermediateCrl.crl";

        private static string sureFhirClientCrlFilename = $"{SurefhirlabsCrl}/{SureFhirLabsIntermediatePkcsFileCrl}";

        private static string SureFhirLabsRootPkcsFileCrl { get; } = "SureFhirLabsRootCrl.crl";

        private static string sureFhirIntermediateCrlFilename = $"{SurefhirlabsCrl}/{SureFhirLabsRootPkcsFileCrl}";

        private static string SureFhirLabsIntermediateCrl { get; } = $"http://crl.fhircerts.net/crl/{SureFhirLabsIntermediatePkcsFileCrl}";
        private static string SureFhirLabsRootCrl { get; } = $"http://crl.fhircerts.net/crl/{SureFhirLabsRootPkcsFileCrl}";

        private static string SureFhirLabsCaPublicCertHosted { get; } = $"http://crl.fhircerts.net/certs/SureFhirLabs_CA.cer";
        private static string SureFhirLabsIntermediatePublicCertHosted { get; } = "http://crl.fhircerts.net/certs/intermediates/SureFhirLabs_Intermediate.cer";

        private static string SurefhirlabsUdapIntermediates { get; } = $"{SureFhirLabsCertStore}/intermediates";
        private static string SurefhirlabsUdapIssued { get; } = $"{SureFhirLabsCertStore}/issued";


        private static string SureFhirLabsSslWeatherApi { get; } = $"{BaseDir}/certstores/Kestrel/WeatherApi";
        private static string SureFhirLabsSslFhirLabs { get; } = $"{BaseDir}/certstores/Kestrel/FhirLabs";
        private static string SureFhirLabsSslIdentityServer { get; } = $"{BaseDir}/certstores/Kestrel/IdentityServer";


        private static string FhirLabsCertStore { get; } = "certstores/FhirLabs";
        private static string FhirLabsUdapIntermediates { get; } = $"{FhirLabsCertStore}/intermediates";
        private static string FhirLabsUdapIssued { get; } = $"{FhirLabsCertStore}/issued";

        private string DefaultPKCS12Password { get; set; }

        public MakeCa(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;

            IConfiguration config = new ConfigurationBuilder()
                .AddUserSecrets<SecretSettings>()
                .Build();

            DefaultPKCS12Password = config["CertPassword"];
        }

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

            //
            // https://stackoverflow.com/a/48210587/6115838
            //

            #region SureFhir CA
            using (RSA parentRSAKey = RSA.Create(4096))
            using (RSA intermediateRSAKey = RSA.Create(4096))
            {
                var parentReq = new CertificateRequest(
                    "CN=SureFhir-CA, OU=Root, O=Fhir Coding, L=Portland, S=Oregon, C=US",
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
                        new OidCollection {
                            new Oid("1.3.6.1.5.5.7.3.2"), // TLS Client auth
                            new Oid("1.3.6.1.5.5.7.3.1"), // TLS Server auth
                            new Oid("1.3.6.1.5.5.7.3.8")  // Time Stamping
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
                    File.WriteAllBytes($"{SureFhirLabsCertStore}/SureFhirLabs_CA.pfx", parentBytes);
                    char[] caPem = PemEncoding.Write("CERTIFICATE", caCert.RawData);
                    File.WriteAllBytes($"{SureFhirLabsCertStore}/SureFhirLabs_CA.cer", caPem.Select(c => (byte)c).ToArray());
                    UpdateWindowsMachineStore(caCert);

                    #endregion

                    #region SureFireLabs Intermediate
                    var intermediateReq = new CertificateRequest(
                        "CN=SureFhir-Intermediate, OU=Intermediate, O=Fhir Coding, L=Portland, S=Oregon, C=US",
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
                    intermediateReq.CertificateExtensions.Add(MakeCdp(SureFhirLabsRootCrl));



                    var subAltNameBuilder = new SubjectAlternativeNameBuilder();
                    subAltNameBuilder.AddUri(new Uri("udap://fhirlabs.net")); // embedding a community uri in intermediate cert
                    var x509Extension = subAltNameBuilder.Build();
                    intermediateReq.CertificateExtensions.Add(x509Extension);

                    var authorityInfoAccessBuilder = new AuthorityInformationAccessBuilder();
                    authorityInfoAccessBuilder.AdCertificateAuthorityIssuerUri(new Uri(SureFhirLabsCaPublicCertHosted));
                    var aiaExtension = authorityInfoAccessBuilder.Build();
                    intermediateReq.CertificateExtensions.Add(aiaExtension);


                    //
                    // UDAP client certificate for simple ASP.NET WebApi project
                    // weatherapi.lab
                    //
                    using var intermediateCertWithoutKey = intermediateReq.Create(
                        caCert,
                        DateTimeOffset.UtcNow.AddDays(-1),
                        DateTimeOffset.UtcNow.AddYears(5),
                        new ReadOnlySpan<byte>(RandomNumberGenerator.GetBytes(16)));
                    var intermediateCertWithKey = intermediateCertWithoutKey.CopyWithPrivateKey(intermediateRSAKey);

                    SurefhirlabsUdapIntermediates.EnsureDirectoryExists();
                    var intermediateBytes = intermediateCertWithKey.Export(X509ContentType.Pkcs12, "udap-test");
                    File.WriteAllBytes($"{SurefhirlabsUdapIntermediates}/SureFhirLabs_Intermediate.pfx", intermediateBytes);
                    char[] intermediatePem = PemEncoding.Write("CERTIFICATE", intermediateCertWithoutKey.RawData);
                    File.WriteAllBytes($"{SurefhirlabsUdapIntermediates}/SureFhirLabs_Intermediate.cer", intermediatePem.Select(c => (byte)c).ToArray());
                    UpdateWindowsMachineStore(intermediateCertWithoutKey);

                    #endregion

                    SurefhirlabsUdapIssued.EnsureDirectoryExists();

                    #region weatherapi.lab Client (Issued) Certificates

                    BuildClientCertificate(
                        intermediateCertWithoutKey,
                        caCert,
                        intermediateRSAKey,
                        "CN=weatherapi.lab, OU=UDAP, O=Fhir Coding, L=Portland, S=Oregon, C=US",
                        new List<string> { "https://weatherapi.lab:5021/fhir" },
                        $"{SurefhirlabsUdapIssued}/WeatherApiClient",
                        SureFhirLabsIntermediateCrl,
                        SureFhirLabsIntermediatePublicCertHosted);

                    #endregion

                    #region fhirlabs.net Client (Issued) Certificates

                    BuildClientCertificate(
                        intermediateCertWithoutKey,
                        caCert,
                        intermediateRSAKey,
                        "CN=fhirlabs.net, OU=UDAP, O=Fhir Coding, L=Portland, S=Oregon, C=US",
                        new List<string> { "https://fhirlabs.net/fhir/r4", "https://fhirlabs.net:7016/fhir/r4" },
                        $"{SurefhirlabsUdapIssued}/fhirlabs.net.client",
                        SureFhirLabsIntermediateCrl,
                        SureFhirLabsIntermediatePublicCertHosted
                    );

                    #endregion

                    #region touchstone.aegis.net Client (Issued) Certificates

                    BuildClientCertificate(
                        intermediateCertWithoutKey,
                        caCert,
                        intermediateRSAKey,
                        "CN=touchstone.aegis.net, OU=UDAP, O=Fhir Coding, L=Portland, S=Oregon, C=US",
                        new List<string> { "https://touchstone.aegis.net", "https://touchstone.aegis.net:56040" },
                        $"{SurefhirlabsUdapIssued}/touchstone.aegis.net",
                        SureFhirLabsIntermediateCrl,
                        SureFhirLabsIntermediatePublicCertHosted
                    );

                    #endregion

                    #region fhirlabs.net Client (Issued) Certificates

                    // string[] numberToWord = { "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten" };
                    //
                    // for (int i = 1; i < 10; i++)
                    // {
                    //     var word = numberToWord[i - 1];
                    //
                    //     BuildClientCertificate(
                    //         intermediateCertWithoutKey,
                    //         caCert,
                    //         intermediateRSAKey,
                    //         $"CN={word}.fhirlabs.net, OU=UDAP, O=Fhir Coding, L=Portland, S=Oregon, C=US",
                    //         new List<string> { $"https://{word}.X.fhirlabs.net", $"https://{word}.Y.fhirlabs.net" },
                    //         $"{SurefhirlabsUdapIssued}/{word}.fhirlabs.net",
                    //         SureFhirLabsIntermediateCrl,
                    //         SureFhirLabsIntermediatePublicCertHosted);
                    // }

                    #endregion

                    #region fhirlabs.net ECDSA
                    //
                    // Create ECDSA certificate
                    //
                    BuildClientCertificateECDSA(
                        intermediateCertWithoutKey,
                        caCert,
                        intermediateRSAKey,
                        "CN=fhirlabs.net ECDSA, OU=UDAP, O=Fhir Coding, L=Portland, S=Oregon, C=US",
                        new List<string> { "https://fhirlabs.net/fhir/r4", "https://fhirlabs.net:7016/fhir/r4" },
                        $"{SurefhirlabsUdapIssued}/fhirlabs.net.ecdsa.client",
                        SureFhirLabsIntermediateCrl,
                        SureFhirLabsIntermediatePublicCertHosted
                    );
                    #endregion

                    #region weatherapi.lab SSL

                    using RSA rsaWeatherApiSsl = RSA.Create(2048);
                    var sslReq = new CertificateRequest(
                        "CN=weatherapi.lab, OU=SSL, O=Fhir Coding, L=Portland, S=Oregon, C=US",
                        rsaWeatherApiSsl,
                        HashAlgorithmName.SHA256,
                        RSASignaturePadding.Pkcs1);

                    sslReq.CertificateExtensions.Add(
                        new X509BasicConstraintsExtension(false, false, 0, true));

                    sslReq.CertificateExtensions.Add(
                        new X509KeyUsageExtension(
                            X509KeyUsageFlags.DigitalSignature,
                            true));

                    sslReq.CertificateExtensions.Add(
                        new X509SubjectKeyIdentifierExtension(sslReq.PublicKey, false));

                    AddAuthorityKeyIdentifier(intermediateCertWithoutKey, sslReq, _testOutputHelper);
                    sslReq.CertificateExtensions.Add(MakeCdp(SureFhirLabsIntermediateCrl));

                    subAltNameBuilder = new SubjectAlternativeNameBuilder();
                    subAltNameBuilder.AddDnsName("weatherapi.lab");
                    x509Extension = subAltNameBuilder.Build();
                    sslReq.CertificateExtensions.Add(x509Extension);

                    sslReq.CertificateExtensions.Add(
                        new X509EnhancedKeyUsageExtension(
                            new OidCollection {
                                new Oid("1.3.6.1.5.5.7.3.2"), // TLS Client auth
                                new Oid("1.3.6.1.5.5.7.3.1"), // TLS Server auth
                            },
                            true));

                    using (var clientCert = sslReq.Create(
                               intermediateCertWithKey,
                               DateTimeOffset.UtcNow.AddDays(-1),
                               DateTimeOffset.UtcNow.AddYears(2),
                               new ReadOnlySpan<byte>(RandomNumberGenerator.GetBytes(16))))
                    {
                        // Do something with these certs, like export them to PFX,
                        // or add them to an X509Store, or whatever.
                        var sslCert = clientCert.CopyWithPrivateKey(rsaWeatherApiSsl);

                        SureFhirLabsSslWeatherApi.EnsureDirectoryExists();
                        var clientBytes = sslCert.Export(X509ContentType.Pkcs12, "udap-test");

                        Console.WriteLine("*************************************");
                        Console.WriteLine($"{SureFhirLabsSslWeatherApi}/weatherapi.lab.pfx");
                        Console.WriteLine("*************************************");

                        File.WriteAllBytes($"{SureFhirLabsSslWeatherApi}/weatherapi.lab.pfx", clientBytes);
                        char[] certificatePem = PemEncoding.Write("CERTIFICATE", clientCert.RawData);
                        File.WriteAllBytes($"{SureFhirLabsSslWeatherApi}/weatherapi.lab.cer", certificatePem.Select(c => (byte)c).ToArray());
                    }
                    #endregion

                    #region fhirlabs.net SSL

                    using RSA rsaFhirLabsSsl = RSA.Create(2048);

                    var sureFhirSSLReq = new CertificateRequest(
                        "CN=fhirlabs.net, OU=SSL, O=Fhir Coding, L=Portland, S=Oregon, C=US",
                        rsaFhirLabsSsl,
                        HashAlgorithmName.SHA256,
                        RSASignaturePadding.Pkcs1);

                    sureFhirSSLReq.CertificateExtensions.Add(
                        new X509BasicConstraintsExtension(false, false, 0, true));

                    sureFhirSSLReq.CertificateExtensions.Add(
                        new X509KeyUsageExtension(
                            X509KeyUsageFlags.DigitalSignature,
                            true));

                    sureFhirSSLReq.CertificateExtensions.Add(
                        new X509SubjectKeyIdentifierExtension(sureFhirSSLReq.PublicKey, false));

                    AddAuthorityKeyIdentifier(intermediateCertWithoutKey, sureFhirSSLReq, _testOutputHelper);
                    sureFhirSSLReq.CertificateExtensions.Add(MakeCdp(SureFhirLabsIntermediateCrl));

                    subAltNameBuilder = new SubjectAlternativeNameBuilder();
                    subAltNameBuilder.AddDnsName("fhirlabs.net");
                    x509Extension = subAltNameBuilder.Build();
                    sureFhirSSLReq.CertificateExtensions.Add(x509Extension);

                    sureFhirSSLReq.CertificateExtensions.Add(
                        new X509EnhancedKeyUsageExtension(
                            new OidCollection {
                                new Oid("1.3.6.1.5.5.7.3.2"), // TLS Client auth
                                new Oid("1.3.6.1.5.5.7.3.1"), // TLS Server auth
                            },
                            true));

                    using (var clientCert = sureFhirSSLReq.Create(
                               intermediateCertWithKey,
                               DateTimeOffset.UtcNow.AddDays(-1),
                               DateTimeOffset.UtcNow.AddYears(2),
                               new ReadOnlySpan<byte>(RandomNumberGenerator.GetBytes(16))))
                    {
                        // Do something with these certs, like export them to PFX,
                        // or add them to an X509Store, or whatever.
                        var sslCert = clientCert.CopyWithPrivateKey(rsaFhirLabsSsl);

                        SureFhirLabsSslFhirLabs.EnsureDirectoryExists();
                        var clientBytes = sslCert.Export(X509ContentType.Pkcs12, "udap-test");
                        File.WriteAllBytes($"{SureFhirLabsSslFhirLabs}/fhirlabs.net.pfx", clientBytes);
                        char[] certificatePem = PemEncoding.Write("CERTIFICATE", clientCert.RawData);
                        File.WriteAllBytes($"{SureFhirLabsSslFhirLabs}/fhirlabs.net.cer", certificatePem.Select(c => (byte)c).ToArray());
                    }

                    #endregion


                    #region securedcontrols.net SSL  :: Identity Provider 

                    using RSA rsaSecuredControls = RSA.Create(2048);

                    var idProviderSureFhirSSLReq = new CertificateRequest(
                        "CN=securedcontrols.net, OU=SSL, O=Fhir Coding, L=Portland, S=Oregon, C=US",
                        rsaSecuredControls,
                        HashAlgorithmName.SHA256,
                        RSASignaturePadding.Pkcs1);

                    idProviderSureFhirSSLReq.CertificateExtensions.Add(
                        new X509BasicConstraintsExtension(false, false, 0, true));

                    idProviderSureFhirSSLReq.CertificateExtensions.Add(
                        new X509KeyUsageExtension(
                            X509KeyUsageFlags.DigitalSignature,
                            true));

                    idProviderSureFhirSSLReq.CertificateExtensions.Add(
                        new X509SubjectKeyIdentifierExtension(idProviderSureFhirSSLReq.PublicKey, false));

                    AddAuthorityKeyIdentifier(intermediateCertWithoutKey, idProviderSureFhirSSLReq, _testOutputHelper);
                    idProviderSureFhirSSLReq.CertificateExtensions.Add(MakeCdp(SureFhirLabsIntermediateCrl));

                    subAltNameBuilder = new SubjectAlternativeNameBuilder();
                    subAltNameBuilder.AddDnsName("securedcontrols.net");
                    x509Extension = subAltNameBuilder.Build();
                    idProviderSureFhirSSLReq.CertificateExtensions.Add(x509Extension);

                    idProviderSureFhirSSLReq.CertificateExtensions.Add(
                        new X509EnhancedKeyUsageExtension(
                            new OidCollection {
                                new Oid("1.3.6.1.5.5.7.3.2"), // TLS Client auth
                                new Oid("1.3.6.1.5.5.7.3.1"), // TLS Server auth
                            },
                            true));

                    using (var clientCert = idProviderSureFhirSSLReq.Create(
                               intermediateCertWithKey,
                               DateTimeOffset.UtcNow.AddDays(-1),
                               DateTimeOffset.UtcNow.AddYears(2),
                               new ReadOnlySpan<byte>(RandomNumberGenerator.GetBytes(16))))
                    {
                        // Do something with these certs, like export them to PFX,
                        // or add them to an X509Store, or whatever.
                        var sslCert = clientCert.CopyWithPrivateKey(rsaSecuredControls);

                        SureFhirLabsSslIdentityServer.EnsureDirectoryExists();
                        var clientBytes = sslCert.Export(X509ContentType.Pkcs12, "udap-test");
                        File.WriteAllBytes($"{SureFhirLabsSslIdentityServer}/securedcontrols.net.pfx", clientBytes);
                        char[] certificatePem = PemEncoding.Write("CERTIFICATE", clientCert.RawData);
                        File.WriteAllBytes($"{SureFhirLabsSslIdentityServer}/securedcontrols.net.cer", certificatePem.Select(c => (byte)c).ToArray());
                    }

                    #endregion

                    #region SureFhir Intermediate CRL

                    // Certificate Revocation
                    var bouncyCaCert = DotNetUtilities.FromX509Certificate(caCert);

                    var crlIntermediateGen = new X509V2CrlGenerator();
                    var intermediateNow = DateTime.UtcNow;
                    crlIntermediateGen.SetIssuerDN(bouncyCaCert.SubjectDN);
                    crlIntermediateGen.SetThisUpdate(intermediateNow);
                    crlIntermediateGen.SetNextUpdate(intermediateNow.AddYears(1));

                    crlIntermediateGen.AddCrlEntry(BigInteger.One, intermediateNow, CrlReason.PrivilegeWithdrawn);

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

                    crlGen.AddCrlEntry(BigInteger.One, now, CrlReason.PrivilegeWithdrawn);

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

                    #region host.docker.internal certificate

                    using RSA rsaHostDockerInternal = RSA.Create(2048);

                    var hostDockerInternal = new CertificateRequest(
                        "CN=host.docker.internal, OU=SSL, O=Fhir Coding, L=Portland, S=Oregon, C=US",
                        rsaHostDockerInternal,
                        HashAlgorithmName.SHA256,
                        RSASignaturePadding.Pkcs1);

                    hostDockerInternal.CertificateExtensions.Add(
                        new X509BasicConstraintsExtension(false, false, 0, true));

                    hostDockerInternal.CertificateExtensions.Add(
                        new X509KeyUsageExtension(
                            X509KeyUsageFlags.DigitalSignature,
                            true));

                    hostDockerInternal.CertificateExtensions.Add(
                        new X509SubjectKeyIdentifierExtension(hostDockerInternal.PublicKey, false));

                    AddAuthorityKeyIdentifier(caCert, hostDockerInternal, _testOutputHelper);
                    // hostDockerInternal.CertificateExtensions.Add(MakeCdp(SureFhirLabsRootCrl)); 

                    subAltNameBuilder = new SubjectAlternativeNameBuilder();
                    subAltNameBuilder.AddDnsName("host.docker.internal");
                    subAltNameBuilder.AddDnsName("localhost");
                    x509Extension = subAltNameBuilder.Build();
                    hostDockerInternal.CertificateExtensions.Add(x509Extension);

                    hostDockerInternal.CertificateExtensions.Add(
                        new X509EnhancedKeyUsageExtension(
                            new OidCollection {
                                new Oid("1.3.6.1.5.5.7.3.2"), // TLS Client auth
                                new Oid("1.3.6.1.5.5.7.3.1"), // TLS Server auth
                            },
                            true));

                    using (var clientCert = hostDockerInternal.Create(
                               caCert,
                               DateTimeOffset.UtcNow.AddDays(-1),
                               DateTimeOffset.UtcNow.AddYears(2),
                               new ReadOnlySpan<byte>(RandomNumberGenerator.GetBytes(16))))
                    {
                        // Do something with these certs, like export them to PFX,
                        // or add them to an X509Store, or whatever.
                        var sslCert = clientCert.CopyWithPrivateKey(rsaHostDockerInternal);

                        SureFhirLabsSslIdentityServer.EnsureDirectoryExists();
                        var clientBytes = sslCert.Export(X509ContentType.Pkcs12, "udap-test");
                        File.WriteAllBytes($"{SureFhirLabsSslIdentityServer}/host.docker.internal.pfx", clientBytes);
                        char[] certificatePem = PemEncoding.Write("CERTIFICATE", clientCert.RawData);
                        File.WriteAllBytes($"{SureFhirLabsSslIdentityServer}/host.docker.internal.cer", certificatePem.Select(c => (byte)c).ToArray());
                    }

                    #endregion
                }
            }

            //Distribute

            File.Copy($"{SureFhirLabsSslFhirLabs}/fhirlabs.net.pfx",
                $"{BaseDir}/../../examples/FhirLabsApi/fhirlabs.net.pfx",
                true);

            File.Copy($"{SurefhirlabsUdapIssued}/fhirlabs.net.client.pfx",
                $"{BaseDir}/../../examples/FhirLabsApi/CertStore/issued/fhirlabs.net.client.pfx",
                true);

            // Copy CA to FhirLabsApi so it can be added to the Docker Container trust store. 
            File.Copy($"{SureFhirLabsCertStore}/SureFhirLabs_CA.cer",
                $"{BaseDir}/../../examples/FhirLabsApi/SureFhirLabs_CA.cer",
                true);

            // Copy CA to Udap.Auth.Server so it can be added to the Docker Container trust store. 
            File.Copy($"{SureFhirLabsCertStore}/SureFhirLabs_CA.cer",
                $"{BaseDir}/../../examples/Udap.Auth.Server/SureFhirLabs_CA.cer",
                true);

            // SubAltName is localhost and host.docker.internal. Udap.Idp server can then be reached from
            // other docker images via host.docker.internal host name.
            // Example: FhirLabsApi project calling Udap.Idp via the back channel OpenIdConnect access token validation.
            File.Copy($"{SureFhirLabsSslIdentityServer}/host.docker.internal.pfx",
                $"{BaseDir}/../../examples/Udap.Auth.Server/host.docker.internal.pfx",
                true);

            File.Copy($"{SureFhirLabsSslIdentityServer}/host.docker.internal.pfx",
                $"{BaseDir}/../../examples/FhirLabsApi/host.docker.internal.pfx",
                true);

            File.Copy($"{SureFhirLabsSslIdentityServer}/host.docker.internal.pfx",
                $"{BaseDir}/../../examples/Udap.CA/host.docker.internal.pfx",
                true);

            File.Copy($"{SureFhirLabsSslIdentityServer}/host.docker.internal.pfx",
                $"{BaseDir}/../../examples/Udap.Auth.Server.Admin/host.docker.internal.pfx",
                true);
        }

        [Fact (Skip = "Enabled on desktop when needed.")]
        public void MakeNegativeTestCertsForFhirLabsReferenceImplementationServer()
        {
            using var rootCA = new X509Certificate2($"{SureFhirLabsCertStore}/SureFhirLabs_CA.pfx", "udap-test");
            using var subCA = new X509Certificate2($"{SurefhirlabsUdapIntermediates}/SureFhirLabs_Intermediate.pfx", "udap-test");

            //
            // Expired certificate
            //
            BuildClientCertificate(
                subCA,
                rootCA,
                subCA.GetRSAPrivateKey()!,
                "CN=fhirlabs.net Expired Certificate, OU=UDAP, O=Fhir Coding, L=Portland, S=Oregon, C=US",
                new List<string> { "https://fhirlabs.net/fhir/r4", "https://fhirlabs.net:7016/fhir/r4" },
                $"{SurefhirlabsUdapIssued}/fhirlabs.net.expired.client",
                SureFhirLabsIntermediateCrl,
                SureFhirLabsIntermediatePublicCertHosted,
                subCA.NotBefore, // Remember, you can not set this to before the issuing certificate
                DateTimeOffset.UtcNow.AddDays(-1)
            );

            //
            // Revoked Certificate
            // Run GenerateCrlForFailTests
            //
            BuildClientCertificate(
                subCA,
                rootCA,
                subCA.GetRSAPrivateKey()!,
                "CN=fhirlabs.net Revoked Certificate, OU=UDAP, O=Fhir Coding, L=Portland, S=Oregon, C=US",
                new List<string> { "https://fhirlabs.net/fhir/r4", "https://fhirlabs.net:7016/fhir/r4" },
                $"{SurefhirlabsUdapIssued}/fhirlabs.net.revoked.client",
                SureFhirLabsIntermediateCrl,
                SureFhirLabsIntermediatePublicCertHosted
            );

            //
            // Iss mismatch To SubjAltName
            //
            BuildClientCertificate(
                subCA,
                rootCA,
                subCA.GetRSAPrivateKey()!,
                "CN=fhirlabs.net mismatch SAN, OU=UDAP, O=Fhir Coding, L=Portland, S=Oregon, C=US",
                new List<string> { "https://san.mismatch.fhirlabs.net/fhir/r4" },
                $"{SurefhirlabsUdapIssued}/fhirlabs.net.mismatchSan.client",
                SureFhirLabsIntermediateCrl,
                SureFhirLabsIntermediatePublicCertHosted
            );

            //
            // Iss and san does not match BaseUrl.
            // This is a valid cert for fhirlabs.net.  But I can't reload the same cert twice in two communities, so I generate another.
            //
            BuildClientCertificate(
                subCA,
                rootCA,
                subCA.GetRSAPrivateKey()!,
                "CN=fhirlabs.net mismatch SAN, OU=UDAP, O=Fhir Coding, L=Portland, S=Oregon, C=US",
                new List<string> { "https://fhirlabs.net/fhir/r4", "https://fhirlabs.net:7016/fhir/r4" },
                $"{SurefhirlabsUdapIssued}/fhirlabs.net.mismatchBaseUrl.client",
                SureFhirLabsIntermediateCrl,
                SureFhirLabsIntermediatePublicCertHosted
            );


            using var rootCA_localhost = new X509Certificate2($"{LocalhostCertStore}/localhost_fhirlabs_community1/caLocalhostCert.pfx", "udap-test");
            using var subCA_localhost = new X509Certificate2($"{LocalhostCertStore}/localhost_fhirlabs_community1/intermediates/intermediateLocalhostCert.pfx", "udap-test");

            //
            // Untrusted Use Case:  the CA is not published.
            //
            BuildClientCertificate(
                subCA_localhost,
                rootCA_localhost,
                subCA_localhost.GetRSAPrivateKey()!,
                "CN=fhirlabs.net untrusted, OU=UDAP, O=Fhir Coding, L=Portland, S=Oregon, C=US",
                new List<string> { "https://fhirlabs.net/fhir/r4" },
                $"{SurefhirlabsUdapIssued}/fhirlabs.net.untrusted.client",
                "http://localhost/crl/localhost.crl"
            );
        }


        [Fact(Skip = "Enabled on desktop when needed.")]
        public void MakeIdentityProviderCertificates()
        {
            using var rootCA = new X509Certificate2($"{SureFhirLabsCertStore}/SureFhirLabs_CA.pfx", "udap-test");
            using var subCA = new X509Certificate2($"{SurefhirlabsUdapIntermediates}/SureFhirLabs_Intermediate.pfx",
                "udap-test");



            //
            // Identity Provider 1, server signing cert
            //
            BuildClientCertificate(
                subCA,
                rootCA,
                subCA.GetRSAPrivateKey()!,
                "CN=IdP1 Server, OU=UDAP, O=Fhir Coding, L=Portland, S=Oregon, C=US",
                new List<string> { "https://idp1.securedcontrols.net", "https://localhost:5055" },
                $"{SurefhirlabsUdapIssued}/idp1.securedcontrols.net.server",
                SureFhirLabsIntermediateCrl,
                SureFhirLabsIntermediatePublicCertHosted
            );

            File.Copy($"{SurefhirlabsUdapIssued}/idp1.securedcontrols.net.server.pfx",
                $"{BaseDir}/../../examples/Udap.Identity.Provider/CertStore/issued/idp1.securedcontrols.net.server.pfx",
                true);

            //
            // Identity Provider 2, server signing cert
            //
            BuildClientCertificate(
                subCA,
                rootCA,
                subCA.GetRSAPrivateKey()!,
                "CN=IdP2 Server, OU=UDAP, O=Fhir Coding, L=Portland, S=Oregon, C=US",
                new List<string> { "https://idp2.securedcontrols.net", "https://localhost:5057" },
                $"{SurefhirlabsUdapIssued}/idp2.securedcontrols.net.server",
                SureFhirLabsIntermediateCrl,
                SureFhirLabsIntermediatePublicCertHosted
            );

            File.Copy($"{SurefhirlabsUdapIssued}/idp2.securedcontrols.net.server.pfx",
                $"{BaseDir}/../../examples/Udap.Identity.Provider.2/CertStore/issued/idp2.securedcontrols.net.server.pfx",
                true);

        }

        //
        // Run this in Linux.
        //
        // Todo: enable to run in Windows.  
        // The short answer is, Windows will not allow this code rsa.ExportParameters(true).  
        // You have to follow DotNetUtilities.GetKeyPair code to see where it is.
        // That ExportParams would have needed the plaintext exportable bit set originally.
        // Windows behaves in such a way when importing the pfx it creates the CNG key so it can only be exported encrypted.
        // See this answer by bartonjs https://stackoverflow.com/users/6535399/bartonjs
        // https://stackoverflow.com/a/57330499/6115838
        // Also see this Github issue comment: https://github.com/dotnet/runtime/issues/77590#issuecomment-1325896560
        //
        [Fact (Skip = "Enabled on desktop when needed.  Actually I performed the work around in SignedSoftwareStatementBuilder<T>.BuildECDSA")]
        public void GenerateCrlForFailTests()
        {
            var subCA = new X509Certificate2($"{SurefhirlabsUdapIntermediates}/SureFhirLabs_Intermediate.pfx", "udap-test", X509KeyStorageFlags.Exportable);
            var revokeCertificate =
                new X509Certificate2($"{SurefhirlabsUdapIssued}/fhirlabs.net.revoked.client.pfx", "udap-test");

            var x509CrlParser = new X509CrlParser();
            X509Crl? x509Crl = null;

            try
            {
                //
                // If you want to keep updating the previous crl.  I don't care in this case. 
                // The pup
                //
                //x509Crl = x509CrlParser.ReadCrl(File.ReadAllBytes(sureFhirClientCrlFilename));
            }
            catch
            {
                // ignore 
            }


            // Certificate Revocation
            var bouncyIntermediateCert = DotNetUtilities.FromX509Certificate(subCA);

            var crlGen = new X509V2CrlGenerator();
            var now = DateTime.UtcNow;
            crlGen.SetIssuerDN(bouncyIntermediateCert.SubjectDN);
            crlGen.SetThisUpdate(now);
            crlGen.SetNextUpdate(now.AddYears(1));
            // crlGen.SetSignatureAlgorithm("SHA256withRSA");


            crlGen.AddCrlEntry(new BigInteger(revokeCertificate.SerialNumberBytes.ToArray()), now, CrlReason.PrivilegeWithdrawn);

            if (x509Crl != null)
            {
                crlGen.AddCrl(x509Crl);
            }

            crlGen.AddExtension(X509Extensions.AuthorityKeyIdentifier,
                false,
                new AuthorityKeyIdentifierStructure(bouncyIntermediateCert.GetPublicKey()));

            var nextSureFhirClientCrlNum = GetNextCrlNumber(sureFhirClientCrlFilename);

            crlGen.AddExtension(X509Extensions.CrlNumber, false, nextSureFhirClientCrlNum);


            // var randomGenerator = new CryptoApiRandomGenerator();
            // var random = new SecureRandom(randomGenerator);

            
            var Akp = DotNetUtilities.GetKeyPair(subCA.GetRSAPrivateKey()).Private;

            //var crl = crlGen.Generate(Akp, random);
            var crl = crlGen.Generate(new Asn1SignatureFactory("SHA256WithRSAEncryption", Akp));

            SurefhirlabsCrl.EnsureDirectoryExists();
            File.WriteAllBytes(sureFhirClientCrlFilename, crl.GetEncoded());
            

        }

       
        //
        // Community:localhost:: Certificate Store File Constants  Community used for unit tests
        //
        public static string LocalhostCertStore
        {
            get
            {
                var assembly = Assembly.GetExecutingAssembly();
                var resourcePath = String.Format(
                    $"{Regex.Replace(assembly.ManifestModule.Name, @"\.(exe|dll)$", string.Empty, RegexOptions.IgnoreCase)}" +
                    $".Resources.ProjectDirectory.txt");

                var rm = new ResourceManager("Resources", assembly);

                string[] names = assembly.GetManifestResourceNames(); // Help finding names

                using var stream = assembly.GetManifestResourceStream(resourcePath);
                using var streamReader = new StreamReader(stream);

                var baseDir = streamReader.ReadToEnd();

                return $"{baseDir.TrimEnd()}/certstores/";
            }
        }

        public static IEnumerable<object[]> LocalhostCommunities()
        {
            yield return new object[]
            {
                $"{LocalhostCertStore}localhost_fhirlabs_community1",                      //communityStorePath
                "caLocalhostCert",                                                          //anchorName
                "intermediateLocalhostCert",                                                //intermediateName
                "fhirLabsApiClientLocalhostCert",                                           //issuedName
                "CN=localhost, OU=fhirlabs.net, O=Fhir Coding, L=Portland, S=Oregon, C=US", //issuedDistinguishedName
                new List<string>
                {
                    "http://localhost/fhir/r4",
                    "https://localhost:7016/fhir/r4",
                    "https://host.docker.internal:7016/fhir/r4",
                    // For IdP Server
                    "https://localhost:5055",
                    "https://host.docker.internal:5055"
                },                                                                          //SubjAltNames
                "FhirLabsApi",                                                              //deliveryProjectPath    
                "RSA"
            };

            yield return new object[]
            {
                $"{LocalhostCertStore}localhost_fhirlabs_community2",                      //communityStorePath
                "caLocalhostCert2",                                                         //anchorName
                "intermediateLocalhostCert2",                                               //intermediateName
                "fhirLabsApiClientLocalhostCert2",                                          //issuedName
                "CN=IdProvider2, OU=fhirlabs.net, O=Fhir Coding, L=Portland, S=Oregon, C=US",//issuedDistinguishedName
                new List<string>
                {
                    "http://localhost/fhir/r4",
                    "https://localhost:7016/fhir/r4",
                    "https://host.docker.internal:7016/fhir/r4",
                    // For IdP Server
                    "https://localhost:5057",
                    "https://host.docker.internal:5057"
                },
                "FhirLabsApi",                                                              //deliveryProjectPath    
                "RSA"
            };

            yield return new object[]
            {
                $"{LocalhostCertStore}localhost_fhirlabs_community3",                      //communityStorePath
                "caLocalhostCert3",                                                         //anchorName
                "intermediateLocalhostCert3",                                               //intermediateName
                "fhirLabsApiClientLocalhostCert3",                                          //issuedName
                "CN=localhost3, OU=fhirlabs.net, O=Fhir Coding, L=Portland, S=Oregon, C=US",//issuedDistinguishedName
                new List<string> { 
                    "http://localhost/fhir/r4",
                    "https://host.docker.internal:7016/fhir/r4" },                            //SubjAltNames
                "FhirLabsApi",                                                              //deliveryProjectPath    
                "RSA"
            };

            //
            // Use case: software_statement iss does not match any subject alt names
            //
            yield return new object[]
            {
                $"{LocalhostCertStore}localhost_fhirlabs_community4",                      //communityStorePath
                "caLocalhostCert4",                                                         //anchorName
                "intermediateLocalhostCert4",                                               //intermediateName
                "fhirLabsApiClientLocalhostCert4",                                          //issuedName
                "CN=IssNoMatchIss, OU=fhirlabs.net, O=Fhir Coding, L=Portland, S=Oregon, C=US",//issuedDistinguishedName
                new List<string>
                {
                    "http://localhost/fhir/r99", 
                    "http://localhost/fhir/r999"
                },                                                                          //SubjAltNames
                "FhirLabsApi",                                                              //deliveryProjectPath    
                "RSA"
            };

            //
            // Use case: baseUrl does not match any subject alt names
            //
            yield return new object[]
            {
                $"{LocalhostCertStore}localhost_fhirlabs_community5",                      //communityStorePath
                "caLocalhostCert5",                                                         //anchorName
                "intermediateLocalhostCert5",                                               //intermediateName
                "fhirLabsApiClientLocalhostCert5",                                          //issuedName
                "CN=IssNoMatchBaseUrl, OU=fhirlabs.net, O=Fhir Coding, L=Portland, S=Oregon, C=US",//issuedDistinguishedName
                new List<string>
                {
                    "http://localhost/IssMismatchToBaseUrl/r4"
                },                                                                          //SubjAltNames
                "FhirLabsApi",                                                              //deliveryProjectPath    
                "RSA"
            };

            yield return new object[]
            {
                $"{LocalhostCertStore}localhost_fhirlabs_community6",                      //communityStorePath
                "caLocalhostCert6",                                                         //anchorName
                "intermediateLocalhostCert6",                                               //intermediateName
                "fhirLabsApiClientLocalhostCert6_ECDSA",                                    //issuedName
                "CN=ECDSA, OU=fhirlabs.net, O=Fhir Coding, L=Portland, S=Oregon, C=US",     //issuedDistinguishedName
                new List<string>
                {
                    "http://localhost/fhir/r4", 
                    "https://localhost:7016/fhir/r4",
                    "https://host.docker.internal:7016/fhir/r4"
                },                                                                          //SubjAltNames
                "FhirLabsApi",                                                              //deliveryProjectPath    
                "ECDSA"
            };

            
            yield return new object[]
            {
                $"{LocalhostCertStore}localhost_weatherapi_community1",                    //communityStorePath
                "caWeatherApiLocalhostCert",                                                //anchorName
                "intermediateWeatherApiLocalhostCert",                                      //intermediateName
                "weatherApiClientLocalhostCert1",                                           //issuedName
                "CN=localhost, OU=WeatherApi, O=Fhir Coding, L=Portland, S=Oregon, C=US",   //issuedDistinguishedName
                new List<string>
                {
                    "http://localhost/",
                    "https://localhost:5021"
                },                                                                          //SubjAltNames
                "WeatherApi",                                                               //deliveryProjectPath    
                "RSA"
            };

            yield return new object[]
            {
                $"{LocalhostCertStore}localhost_weatherapi_community2",                    //communityStorePath
                "caWeatherApiLocalhostCert2",                                               //anchorName
                "intermediateWeatherApiLocalhostCert2",                                     //intermediateName
                "weatherApiClientLocalhostCert2",                                           //issuedName
                "CN=localhost2, OU=WeatherApi, O=Fhir Coding, L=Portland, S=Oregon, C=US",  //issuedDistinguishedName
                new List<string>
                {
                    "http://localhost/",
                    "https://localhost:5021"
                },
                "WeatherApi",                                                               //deliveryProjectPath    
                "RSA"
            };
        }


        /// <summary>
        /// default community uri = http://localhost
        /// This is used for WebApplicationFactory tests.
        /// It gives us the opportunity to test multiple communities.
        ///
        /// CA                  => UDAP-Localhost-CA
        /// Intermediate              => UDAP-Localhost-Intermediate
        /// WeatherApi Client   => 
        /// FhirLabsApi Client  =>  
        /// </summary>
        [Theory]
        [MemberData(nameof(LocalhostCommunities))]
        public void MakeCaWithIntermediateUdapForLocalhostCommunity(
            string communityStorePath,
            string anchorName,
            string intermediateName,
            string issuedName,
            string issuedDistinguishedName,
            List<string> issuedSubjectAltNames,
            string deliverProjectPath,
            string cryptoAlgorithm)
        {
            var LocalhostCrl = $"{communityStorePath}/crl";
            var LocalhostCdp = "http://host.docker.internal:5033/crl";
            var LocalhostUdapIntermediates = $"{communityStorePath}/intermediates";
            var LocalhostUdapIssued = $"{communityStorePath}/issued";

            $"{communityStorePath}/crl".EnsureDirectoryExists();
            var IntermediateCrlFilePath = $"{communityStorePath}/crl/{intermediateName}.crl";
            var AnchorCrlFilePath = $"{communityStorePath}/crl/{anchorName}.crl";


            using (RSA parent = RSA.Create(4096))
            using (RSA intermediate = RSA.Create(4096))
            {
                var parentReq = new CertificateRequest(
                    $"CN={anchorName}, OU=Root, O=Fhir Coding, L=Portland, S=Oregon, C=US",
                    parent,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);

                parentReq.CertificateExtensions.Add(
                    new X509BasicConstraintsExtension(true, false, 0, true));

                parentReq.CertificateExtensions.Add(
                    new X509KeyUsageExtension(
                        X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.DigitalSignature,
                        false));

                parentReq.CertificateExtensions.Add(
                    new X509SubjectKeyIdentifierExtension(parentReq.PublicKey, false));

                using (var caCert = parentReq.CreateSelfSigned(
                           DateTimeOffset.UtcNow.AddDays(-1),
                           DateTimeOffset.UtcNow.AddYears(10)))
                {

                    var parentBytes = caCert.Export(X509ContentType.Pkcs12, "udap-test");
                    communityStorePath.EnsureDirectoryExists();
                    File.WriteAllBytes($"{communityStorePath}/{anchorName}.pfx", parentBytes);
                    char[] caPem = PemEncoding.Write("CERTIFICATE", caCert.RawData);
                    File.WriteAllBytes($"{communityStorePath}/{anchorName}.cer",
                        caPem.Select(c => (byte)c).ToArray());


                    var intermediateReq = new CertificateRequest(
                        $"CN={intermediateName}, OU=Intermediate, O=Fhir Coding, L=Portland, S=Oregon, C=US",
                        intermediate,
                        HashAlgorithmName.SHA256,
                        RSASignaturePadding.Pkcs1);

                    // Referred to as intermediate Cert or Intermediate
                    intermediateReq.CertificateExtensions.Add(
                        new X509BasicConstraintsExtension(true, false, 0, true));

                    intermediateReq.CertificateExtensions.Add(
                        new X509KeyUsageExtension(
                            X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyCertSign |
                            X509KeyUsageFlags.DigitalSignature,
                            false));

                    intermediateReq.CertificateExtensions.Add(
                        new X509SubjectKeyIdentifierExtension(intermediateReq.PublicKey, false));

                    AddAuthorityKeyIdentifier(caCert, intermediateReq, _testOutputHelper);
                    intermediateReq.CertificateExtensions.Add(
                        MakeCdp($"{LocalhostCdp}/{anchorName}.crl"));

                    var subAltNameBuilder = new SubjectAlternativeNameBuilder();
                    subAltNameBuilder.AddUri(new Uri("http://host.docker.internal"));
                    var x509Extension = subAltNameBuilder.Build();
                    intermediateReq.CertificateExtensions.Add(x509Extension);

                    using var intermediateCert = intermediateReq.Create(
                        caCert,
                        DateTimeOffset.UtcNow.AddDays(-1),
                        DateTimeOffset.UtcNow.AddYears(5),
                        new ReadOnlySpan<byte>(RandomNumberGenerator.GetBytes(16)));
                    var intermediateCertWithKey = intermediateCert.CopyWithPrivateKey(intermediate);
                    var intermediateBytes = intermediateCertWithKey.Export(X509ContentType.Pkcs12, "udap-test");
                    LocalhostUdapIntermediates.EnsureDirectoryExists();
                    File.WriteAllBytes($"{LocalhostUdapIntermediates}/{intermediateName}.pfx",
                        intermediateBytes);
                    char[] intermediatePem = PemEncoding.Write("CERTIFICATE", intermediateCert.RawData);
                    File.WriteAllBytes($"{LocalhostUdapIntermediates}/{intermediateName}.cer",
                        intermediatePem.Select(c => (byte)c).ToArray());

                    communityStorePath.EnsureDirectoryExists();
                    $"{LocalhostUdapIssued}".EnsureDirectoryExists();

                    if (cryptoAlgorithm is "ECDSA")
                    {
                        BuildClientCertificateECDSA(
                            intermediateCert,
                            caCert,
                            intermediate,
                            issuedDistinguishedName,
                            issuedSubjectAltNames,
                            $"{LocalhostUdapIssued}/{issuedName}",
                            $"{LocalhostCdp}/{intermediateName}.crl",
                            $"http://host.docker.internal:5033/certs/{intermediateName}.cer"
                        );
                    }
                    else
                    {
                        BuildClientCertificate(
                            intermediateCert,
                            caCert,
                            intermediate,
                            issuedDistinguishedName,
                            issuedSubjectAltNames,
                            $"{LocalhostUdapIssued}/{issuedName}",
                            $"{LocalhostCdp}/{intermediateName}.crl",
                            $"http://host.docker.internal:5033/certs/{intermediateName}.cer"
                        );

                        if (issuedName == "fhirLabsApiClientLocalhostCert")
                        {
                            BuildClientCertificate(
                                intermediateCert,
                                caCert,
                                intermediate,
                                "CN=idpserver", //issuedDistinguishedName
                                new List<string>
                                {
                                    "https://idpserver",
                                },
                                $"{LocalhostUdapIssued}/idpserver",
                                $"{LocalhostCdp}/{intermediateName}.crl",
                                $"http://host.docker.internal:5033/certs/{intermediateName}.cer"
                            );
                        }

                        if (issuedName == "fhirLabsApiClientLocalhostCert2")
                        {
                            BuildClientCertificate(
                                intermediateCert,
                                caCert,
                                intermediate,
                                "CN=idpserver2", //issuedDistinguishedName
                                new List<string>
                                {
                                    "https://idpserver2",
                                },
                                $"{LocalhostUdapIssued}/idpserver2",
                                $"{LocalhostCdp}/{intermediateName}.crl",
                                $"http://host.docker.internal:5033/certs/{intermediateName}.cer"
                            );
                        }
                    }


                    // CRLs


                    #region SureFhir Intermediate CRL

                    // Certificate Revocation
                    var bouncyCaCert = DotNetUtilities.FromX509Certificate(caCert);

                    var crlIntermediateGen = new X509V2CrlGenerator();
                    var intermediateNow = DateTime.UtcNow;
                    crlIntermediateGen.SetIssuerDN(bouncyCaCert.SubjectDN);
                    crlIntermediateGen.SetThisUpdate(intermediateNow);
                    crlIntermediateGen.SetNextUpdate(intermediateNow.AddYears(1));

                    crlIntermediateGen.AddCrlEntry(BigInteger.One, intermediateNow, CrlReason.PrivilegeWithdrawn);

                    crlIntermediateGen.AddExtension(X509Extensions.AuthorityKeyIdentifier,
                        false,
                        new AuthorityKeyIdentifierStructure(bouncyCaCert.GetPublicKey()));

                    var nextsureFhirIntermediateCrlNum = GetNextCrlNumber(AnchorCrlFilePath);

                    crlIntermediateGen.AddExtension(X509Extensions.CrlNumber, false, nextsureFhirIntermediateCrlNum);

                    // var intermediateRandomGenerator = new CryptoApiRandomGenerator();
                    // var intermediateRandom = new SecureRandom(intermediateRandomGenerator);

                    var intermediateAkp = DotNetUtilities.GetKeyPair(caCert.GetRSAPrivateKey()).Private;

                    // var intermediateCrl = crlIntermediateGen.Generate(new Asn1SignatureFactory("SHA256WithRSAEncryption", intermediateAkp, intermediateRandom));
                    var intermediateCrl = crlIntermediateGen.Generate(new Asn1SignatureFactory("SHA256WithRSAEncryption", intermediateAkp));

                    SurefhirlabsCrl.EnsureDirectoryExists();
                    File.WriteAllBytes(AnchorCrlFilePath, intermediateCrl.GetEncoded());

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

                    crlGen.AddCrlEntry(BigInteger.One, now, CrlReason.PrivilegeWithdrawn);

                    crlGen.AddExtension(X509Extensions.AuthorityKeyIdentifier,
                        false,
                        new AuthorityKeyIdentifierStructure(bouncyIntermediateCert.GetPublicKey()));

                    var nextSureFhirClientCrlNum = GetNextCrlNumber(IntermediateCrlFilePath);

                    crlGen.AddExtension(X509Extensions.CrlNumber, false, nextSureFhirClientCrlNum);


                    // var randomGenerator = new CryptoApiRandomGenerator();
                    // var random = new SecureRandom(randomGenerator);

                    var Akp = DotNetUtilities.GetKeyPair(intermediateCertWithKey.GetRSAPrivateKey()).Private;

                    //var crl = crlGen.Generate(Akp, random);
                    var crl = crlGen.Generate(new Asn1SignatureFactory("SHA256WithRSAEncryption", Akp));

                    SurefhirlabsCrl.EnsureDirectoryExists();
                    File.WriteAllBytes(IntermediateCrlFilePath, crl.GetEncoded());

                    #endregion

                }
            }

            //
            // Distribute
            //

            //
            // Issued -> Project
            //
            File.Copy($"{LocalhostUdapIssued}/{issuedName}.pfx",
                $"{BaseDir}/../../examples/{deliverProjectPath}/CertStore/issued/{issuedName}.pfx",
                true);


            // TODO: had to hard code deliveryProjectPath for Udap.Identity.Provider
            File.Copy($"{LocalhostUdapIssued}/{issuedName}.pfx",
                $"{BaseDir}/../../examples/Udap.Identity.Provider/CertStore/issued/{issuedName}.pfx",
                true);

            // Udap.Server.Tests :: Identity Provider 1
            if (issuedName == "fhirLabsApiClientLocalhostCert")
            {
                File.Copy($"{LocalhostUdapIssued}/idpserver.pfx",
                    $"{BaseDir}/../../_tests/UdapServer.Tests/CertStore/issued/idpserver.pfx",
                    true);


                File.Copy($"{communityStorePath}/{anchorName}.cer",
                    $"{BaseDir}/../../_tests/UdapServer.Tests/CertStore/anchors/{anchorName}.cer",
                    true);
                File.Copy($"{LocalhostUdapIntermediates}/{intermediateName}.cer",
                    $"{BaseDir}/../../_tests/UdapServer.Tests/CertStore/intermediates/{intermediateName}.cer",
                    true);
            }

            // Udap.Server.Tests :: Identity Provider 2
            if (issuedName == "fhirLabsApiClientLocalhostCert2")
            {
                File.Copy($"{LocalhostUdapIssued}/idpserver2.pfx",
                    $"{BaseDir}/../../_tests/UdapServer.Tests/CertStore/issued/idpserver2.pfx",
                    true);

                File.Copy($"{communityStorePath}/{anchorName}.cer",
                    $"{BaseDir}/../../_tests/UdapServer.Tests/CertStore/anchors/{anchorName}.cer",
                    true);
                File.Copy($"{LocalhostUdapIntermediates}/{intermediateName}.cer",
                    $"{BaseDir}/../../_tests/UdapServer.Tests/CertStore/intermediates/{intermediateName}.cer",
                    true);
            }

            // Udap.Identity.Provider.2 :: Second Identity Provider
            if (issuedName == "fhirLabsApiClientLocalhostCert2")
            {
                File.Copy($"{LocalhostUdapIssued}/{issuedName}.pfx",
                    $"{BaseDir}/../../examples/Udap.Identity.Provider.2/CertStore/issued/{issuedName}.pfx",
                    true);
            }

            //
            // CRL -> Udap.Certificates.Server project
            //
            File.Copy(IntermediateCrlFilePath,
                $"{BaseDir}/../../examples/Udap.Certificates.Server/wwwroot/crl/{intermediateName}.crl",
                true);
            File.Copy(AnchorCrlFilePath,
                $"{BaseDir}/../../examples/Udap.Certificates.Server/wwwroot/crl/{anchorName}.crl",
                true);

            //
            // AIA resolved certificates -> Udap.Certificates.Server project
            //
            File.Copy($"{LocalhostUdapIntermediates}/{intermediateName}.cer",
                $"{BaseDir}/../../examples/Udap.Certificates.Server/wwwroot/certs/{intermediateName}.cer",
                true);
            
            //
            // Distribute to UdapMetadata.Test project
            //
            File.Copy($"{communityStorePath}/{anchorName}.cer",
                $"{BaseDir}/../UdapMetadata.Tests/CertStore/anchors/{anchorName}.cer",
                true);
            File.Copy($"{LocalhostUdapIntermediates}/{intermediateName}.cer",
                $"{BaseDir}/../UdapMetadata.Tests/CertStore/intermediates/{intermediateName}.cer",
                true);


            //
            // Distribute to Udap.Auth.Server project
            //
            // File.Copy($"{communityStorePath}/{anchorName}.cer",
            //     $"{BaseDir}/../../examples/Udap.Auth.Server/CertStore/anchors/{anchorName}.cer",
            //     true);
            // File.Copy($"{LocalhostUdapIntermediates}/{intermediateName}.cer",
            //     $"{BaseDir}/../../examples/Udap.Auth.Server/CertStore/intermediates/{intermediateName}.cer",
            //     true);

            File.Copy($"{LocalhostUdapIssued}/{issuedName}.pfx",
                $"{BaseDir}/../../examples/Udap.Auth.Server/CertStore/issued/{issuedName}.pfx",
                true);
        }


        [Fact (Skip = "Enabled on desktop when needed.")]
        public void MakeGFhirLabsCerts()
        {
            using var rootCA_localhost = new X509Certificate2($"{LocalhostCertStore}/surefhirlabs_community/SureFhirLabs_CA.pfx", "udap-test");
            using var subCA_localhost = new X509Certificate2($"{LocalhostCertStore}/surefhirlabs_community/intermediates/SureFhirLabs_Intermediate.pfx", "udap-test");
            
            //
            // Build a client cert for the gFhirLabs 
            //
            // BuildClientCertificate(
            //     subCA_localhost,
            //     rootCA_localhost,
            //     subCA_localhost.GetRSAPrivateKey()!,
            //     "CN=fhirlabs.net proxy for gfhirlabs, OU=UDAP, O=Fhir Coding, L=Portland, S=Oregon, C=US",
            //     new List<string>
            //     {
            //         "https://fhirlabs.net/fhir/r4", 
            //         "https://localhost:7074/fhir/r4"
            //     },
            //     $"{LocalhostCertStore}surefhirlabs_community/issued/gfhirlabs.healthcare.client",
            //     "http://crl.fhircerts.net/certs/intermediates/SureFhirLabs_Intermediate.cer",
            //     "http://crl.fhircerts.net/crl/surefhirlabsIntermediateCrl.crl"
            // );

            //
            // Build a client cert for the ss UdapLabsFhirStore 
            //
            BuildClientCertificate(
                subCA_localhost,
                rootCA_localhost,
                subCA_localhost.GetRSAPrivateKey()!,
                "CN=proxy for sandbox, OU=UDAP, O=Fhir Coding, L=Portland, S=Oregon, C=US",
                new List<string>
                {
                    "https://localhost:7074/sandbox/fhir/"
                },
                $"{LocalhostCertStore}surefhirlabs_community/issued/sandbox.UdapLabsFhirStore.healthcare.client",
                "http://localhost:5033/crl/intermediateLocalhostCert.crl",
                "http://localhost:5033/certs/intermediateLocalhostCert.cer"
            );
        }

        private X509Certificate2 BuildClientCertificate(
            X509Certificate2 intermediateCert,
            X509Certificate2 caCert,
            RSA intermediateKey,
            string distinguishedName,
            List<string> subjectAltNames,
            string clientCertFilePath,
            string? crl,
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

            var subAltNameBuilder = new SubjectAlternativeNameBuilder();
            foreach (var subjectAltName in subjectAltNames)
            {
                subAltNameBuilder.AddUri(new Uri(subjectAltName)); //Same as iss claim
            }

            var x509Extension = subAltNameBuilder.Build();
            clientCertRequest.CertificateExtensions.Add(x509Extension);

            if (buildAIAExtensionsPath != null)
            {
                var authorityInfoAccessBuilder = new AuthorityInformationAccessBuilder();
                authorityInfoAccessBuilder.AdCertificateAuthorityIssuerUri(new Uri(buildAIAExtensionsPath));
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
            certPackage.Add(clientCertWithKey);
            certPackage.Add(new X509Certificate2(intermediateCert.Export(X509ContentType.Cert)));
            certPackage.Add(new X509Certificate2(caCert.Export(X509ContentType.Cert)));
            
            var clientBytes = certPackage.Export(X509ContentType.Pkcs12, "udap-test");
            File.WriteAllBytes($"{clientCertFilePath}.pfx", clientBytes);
            var clientPem = PemEncoding.Write("CERTIFICATE", clientCert.RawData);
            File.WriteAllBytes($"{clientCertFilePath}.cer", clientPem.Select(c => (byte)c).ToArray());
            
            return clientCert;
        }

        private X509Certificate2 BuildClientCertificateECDSA(
            X509Certificate2 intermediateCert,
            X509Certificate2 caCert,
            RSA intermediateKey,
            string distinguishedName,
            List<string> subjectAltNames,
            string clientCertFilePath,
            string? crl,
            string? buildAIAExtensionsPath,
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

            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);

            var clientCertRequest = new CertificateRequest(
                distinguishedName,
                ecdsa,
                HashAlgorithmName.SHA256);

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

            var subAltNameBuilder = new SubjectAlternativeNameBuilder();
            foreach (var subjectAltName in subjectAltNames)
            {
                subAltNameBuilder.AddUri(new Uri(subjectAltName)); //Same as iss claim
            }

            var x509Extension = subAltNameBuilder.Build();
            clientCertRequest.CertificateExtensions.Add(x509Extension);

            if (buildAIAExtensionsPath != null)
            {
                var authorityInfoAccessBuilder = new AuthorityInformationAccessBuilder();
                authorityInfoAccessBuilder.AdCertificateAuthorityIssuerUri(new Uri(buildAIAExtensionsPath));
                var aiaExtension = authorityInfoAccessBuilder.Build();
                clientCertRequest.CertificateExtensions.Add(aiaExtension);
            }

            var clientCert = clientCertRequest.Create(
                intermediateCertWithKey.SubjectName,
                X509SignatureGenerator.CreateForRSA(intermediateKey, RSASignaturePadding.Pkcs1),
                notBefore,
                notAfter,
                new ReadOnlySpan<byte>(RandomNumberGenerator.GetBytes(16)));
            // Do something with these certs, like export them to PFX,
            // or add them to an X509Store, or whatever.
            var clientCertWithKey = clientCert.CopyWithPrivateKey(ecdsa);


            var certPackage = new X509Certificate2Collection();
            certPackage.Add(clientCertWithKey);
            certPackage.Add(new X509Certificate2(intermediateCert.Export(X509ContentType.Cert)));
            certPackage.Add(new X509Certificate2(caCert.Export(X509ContentType.Cert)));

            
            var clientBytes = certPackage.Export(X509ContentType.Pkcs12, "udap-test");
            File.WriteAllBytes($"{clientCertFilePath}.pfx", clientBytes);
            var clientPem = PemEncoding.Write("CERTIFICATE", clientCert.RawData);
            File.WriteAllBytes($"{clientCertFilePath}.cer", clientPem.Select(c => (byte)c).ToArray());

            return clientCert;
        }

        
        [Fact(Skip = "Depends on ordering")]
        public void TestCrl()
        {
            var bytes = File.ReadAllBytes($"{SurefhirlabsCrl}/{SureFhirLabsIntermediatePkcsFileCrl}");
            var crl = new X509CrlParser().ReadCrl(bytes);

            foreach (X509CrlEntry crlEntry in crl.GetRevokedCertificates())
            {
                if (crlEntry.GetCertificateIssuer() != null)
                {
                    Assert.Fail("certificate issuer CRL entry extension is not null");
                }
            }
        }


        [Fact(Skip = "Ignore")]
        public void ListStoreNames()
        {
            var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            foreach (var name in store.Certificates.Where(c => c.Subject.Contains("CN=UDAP-Test-Intermediate")))
            {
                _testOutputHelper.WriteLine(name.ToString());
            }
        }

        [Fact]
        public void CompareKid()
        {

        }

    }
}