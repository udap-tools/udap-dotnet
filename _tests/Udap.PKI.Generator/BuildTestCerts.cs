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
    public class MakeCa
    {
        private readonly ITestOutputHelper _testOutputHelper;


        //
        // Community:SureFhirLabs:: Certificate Store File Constants
        //
        public static string SureFhirLabsCertStore
        {
            get
            {
                var baseDir = BaseDir;

                return $"{baseDir}/certstores/surefhirlabs_community";
            }
        }

        private static string _baseDir;

        private static string BaseDir
        {
            get
            {
                if (!String.IsNullOrEmpty(_baseDir))
                {
                    return _baseDir;
                }

                var assembly = Assembly.GetExecutingAssembly();
                var resourcePath = String.Format(
                    $"{Regex.Replace(assembly.ManifestModule.Name, @"\.(exe|dll)$", string.Empty, RegexOptions.IgnoreCase)}" +
                    $".Resources.ProjectDirectory.txt");

                var rm = new ResourceManager("Resources", assembly);

                // string[] names = assembly.GetManifestResourceNames(); // Help finding names

                using var stream = assembly.GetManifestResourceStream(resourcePath);
                using var streamReader = new StreamReader(stream);

                _baseDir = streamReader.ReadToEnd().Trim();

                return _baseDir;
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
        /// default community uri = udap://surefhir.labs
        /// </summary>
        [Fact]
        public void MakeCaWithIntermediateUdapAndSSLForDefaultCommunity()
        {
            Console.WriteLine("*************************************");
            Console.WriteLine(_baseDir);
            Console.WriteLine("*************************************");

            //
            // https://stackoverflow.com/a/48210587/6115838
            //

            #region SureFhir CA
            using (RSA parent = RSA.Create(4096))
            using (RSA intermediate = RSA.Create(4096))
            {
                var parentReq = new CertificateRequest(
                    "CN=SureFhir-CA, OU=Root, O=Fhir Coding, L=Portland, S=Oregon, C=US",
                    parent,
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
                        intermediate,
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
                    subAltNameBuilder.AddUri(new Uri("udap://surefhir.labs")); // embedding a community uri in intermediate cert
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
                    var intermediateCertWithKey = intermediateCertWithoutKey.CopyWithPrivateKey(intermediate);

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
                        intermediate,
                        "CN=weatherapi.lab, OU=UDAP, O=Fhir Coding, L=Portland, S=Oregon, C=US",
                        new List<string> { "https://weatherapi.lab:5021/fhir" },
                        $"{SurefhirlabsUdapIssued}/WeatherApiClient",
                        SureFhirLabsIntermediateCrl,
                        true);

                    #endregion

                    #region fhirlabs.net Client (Issued) Certificates

                    BuildClientCertificate(
                        intermediateCertWithoutKey,
                        caCert,
                        intermediate,
                        "CN=fhirlabs.net, OU=UDAP, O=Fhir Coding, L=Portland, S=Oregon, C=US",
                        new List<string> { "https://fhirlabs.net/fhir/r4", "https://fhirlabs.net:7016/fhir/r4" },
                        $"{SurefhirlabsUdapIssued}/fhirlabs.net.client",
                        SureFhirLabsIntermediateCrl,
                        true
                    );

                    #endregion

                    #region touchstone.aegis.net Client (Issued) Certificates

                    BuildClientCertificate(
                        intermediateCertWithoutKey,
                        caCert,
                        intermediate,
                        "CN=touchstone.aegis.net, OU=UDAP, O=Fhir Coding, L=Portland, S=Oregon, C=US",
                        new List<string> { "https://touchstone.aegis.net", "https://touchstone.aegis.net:56040" },
                        $"{SurefhirlabsUdapIssued}/touchstone.aegis.net",
                        SureFhirLabsIntermediateCrl,
                        true
                    );

                    #endregion

                    #region fhirlabs.net Client (Issued) Certificates

                    string[] numberToWord = { "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten" };

                    for (int i = 1; i < 10; i++)
                    {
                        var word = numberToWord[i - 1];

                        BuildClientCertificate(
                            intermediateCertWithoutKey,
                            caCert,
                            intermediate,
                            $"CN={word}.fhirlabs.net, OU=UDAP, O=Fhir Coding, L=Portland, S=Oregon, C=US",
                            new List<string> { $"https://{word}.X.fhirlabs.net", $"https://{word}.Y.fhirlabs.net" },
                            $"{SurefhirlabsUdapIssued}/{word}.fhirlabs.net",
                            SureFhirLabsIntermediateCrl,
                            true);
                    }

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

            File.Copy($"{SurefhirlabsUdapIssued}/fhirlabs.net.client.pfx",
                $"{BaseDir}/../../examples/clients/UdapEd/Server/fhirlabs.net.client.pfx",
                true);

            // Copy CA to FhirLabsApi so it can be added to the Docker Container trust store. 
            File.Copy($"{SureFhirLabsCertStore}/SureFhirLabs_CA.cer",
                $"{BaseDir}/../../examples/FhirLabsApi/SureFhirLabs_CA.cer",
                true);

            // SubAltName is localhost and host.docker.internal. Udap.Idp server can then be reached from
            // other docker images via host.docker.internal host name.
            // Example: FhirLabsApi project calling Udap.Idp via the back channel OpenIdConnect access token validation.
            File.Copy($"{SureFhirLabsSslIdentityServer}/host.docker.internal.pfx",
                $"{BaseDir}/../../examples/Udap.Idp/host.docker.internal.pfx",
                true);

            File.Copy($"{SureFhirLabsSslIdentityServer}/host.docker.internal.pfx",
                $"{BaseDir}/../../examples/FhirLabsApi/host.docker.internal.pfx",
                true);

            File.Copy($"{SureFhirLabsSslIdentityServer}/host.docker.internal.pfx",
                $"{BaseDir}/../../examples/Udap.CA/host.docker.internal.pfx",
                true);

            File.Copy($"{SureFhirLabsSslIdentityServer}/host.docker.internal.pfx",
                $"{BaseDir}/../../examples/Udap.Idp.Admin/host.docker.internal.pfx",
                true);

            File.Copy($"{SureFhirLabsSslIdentityServer}/host.docker.internal.pfx",
                $"{BaseDir}/../../examples/clients/UdapEd/Server/host.docker.internal.pfx",
                true);
        }

        private static CrlNumber GetNextCrlNumber(string fileName)
        {
            var nextCrlNum = new CrlNumber(BigInteger.One);

            if (File.Exists(fileName))
            {
                byte[] buf = File.ReadAllBytes(fileName);
                var crlParser = new X509CrlParser();
                var prevCrl = crlParser.ReadCrl(buf);
                var prevCrlNum = prevCrl.GetExtensionValue(X509Extensions.CrlNumber);
                var asn1Object = X509ExtensionUtilities.FromExtensionValue(prevCrlNum);
                var prevCrlNumVal = DerInteger.GetInstance(asn1Object).PositiveValue;
                nextCrlNum = new CrlNumber(prevCrlNumVal.Add(BigInteger.One));
            }

            return nextCrlNum;
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
                $"{LocalhostCertStore}/localhost_fhirlabs_community1",                      //communityStorePath
                "caLocalhostCert",                                                          //anchorName
                "intermediateLocalhostCert",                                                //intermediateName
                "fhirLabsApiClientLocalhostCert",                                           //issuedName
                "CN=localhost, OU=fhirlabs.net, O=Fhir Coding, L=Portland, S=Oregon, C=US", //issuedDistinguishedName
                new List<string> { "http://localhost/fhir/r4" },                            //SubjAltNames
                "FhirLabsApi"                                                               //deliveryProjectPath    
            };

            yield return new object[]
            {
                $"{LocalhostCertStore}/localhost_fhirlabs_community2",                      //communityStorePath
                "caLocalhostCert2",                                                         //anchorName
                "intermediateLocalhostCert2",                                               //intermediateName
                "fhirLabsApiClientLocalhostCert2",                                          //issuedName
                "CN=localhost2, OU=fhirlabs.net, O=Fhir Coding, L=Portland, S=Oregon, C=US",//issuedDistinguishedName
                new List<string> { "http://localhost/fhir/r4" },                            //SubjAltNames
                "FhirLabsApi"                                                               //deliveryProjectPath    
            };

            yield return new object[]
            {
                $"{LocalhostCertStore}/localhost_fhirlabs_community3",                      //communityStorePath
                "caLocalhostCert3",                                                         //anchorName
                "intermediateLocalhostCert3",                                               //intermediateName
                "fhirLabsApiClientLocalhostCert3",                                          //issuedName
                "CN=localhost3, OU=fhirlabs.net, O=Fhir Coding, L=Portland, S=Oregon, C=US",//issuedDistinguishedName
                new List<string> { "http://localhost/fhir/r4" },                            //SubjAltNames
                "FhirLabsApi"                                                               //deliveryProjectPath    
            };

            yield return new object[]
            {
                $"{LocalhostCertStore}/localhost_weatherapi_community1",                    //communityStorePath
                "caWeatherApiLocalhostCert",                                                //anchorName
                "intermediateWeatherApiLocalhostCert",                                      //intermediateName
                "weatherApiClientLocalhostCert1",                                           //issuedName
                "CN=localhost, OU=WeatherApi, O=Fhir Coding, L=Portland, S=Oregon, C=US",   //issuedDistinguishedName
                new List<string> { "http://localhost/" },                                   //SubjAltNames
                "WeatherApi"                                                                //deliveryProjectPath                    
            };

            yield return new object[]
            {
                $"{LocalhostCertStore}/localhost_weatherapi_community2",                    //communityStorePath
                "caWeatherApiLocalhostCert2",                                               //anchorName
                "intermediateWeatherApiLocalhostCert2",                                     //intermediateName
                "weatherApiClientLocalhostCert2",                                           //issuedName
                "CN=localhost2, OU=WeatherApi, O=Fhir Coding, L=Portland, S=Oregon, C=US",  //issuedDistinguishedName
                new List<string> { "http://localhost/" },                                   //SubjAltNames
                "WeatherApi"                                                                //deliveryProjectPath    
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
            string deliverProjectPath)
        {
            var LocalhostCrl = $"{communityStorePath}/crl";
            var LocalhostCdp = "http://localhost/crl/localhost.crl";
            var LocalhostUdapIntermediates = $"{communityStorePath}/intermediates";
            var LocalhostUdapIssued = $"{communityStorePath}/issued";
            var LocalhostPkcsFileCrl = "localhost.crl";


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
                        MakeCdp("http://certs.weatherapi.lab/crl/UDAP-Localhost-CA.crl"));

                    var subAltNameBuilder = new SubjectAlternativeNameBuilder();
                    subAltNameBuilder.AddUri(new Uri("http://localhost"));
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


                    BuildClientCertificate(
                        intermediateCert,
                        caCert,
                        intermediate,
                        issuedDistinguishedName,
                        issuedSubjectAltNames,
                        $"{LocalhostUdapIssued}/{issuedName}",
                        LocalhostCdp
                    );
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


            //
            // Distribute to UdapMetadata.Test project
            //
            File.Copy($"{communityStorePath}/{anchorName}.cer",
                $"{BaseDir}/../UdapMetadata.Tests/CertStore/anchors/{anchorName}.cer",
                true);
            File.Copy($"{LocalhostUdapIntermediates}/{intermediateName}.cer",
                $"{BaseDir}/../UdapMetadata.Tests/CertStore/intermediates/{intermediateName}.cer",
                true);
           
        }

        private void BuildClientCertificate(
            X509Certificate2 intermediateCert,
            X509Certificate2 caCert,
            RSA intermediate,
            string distinguishedName,
            List<string> subjectAltNames,
            string clientCertFilePath,
            string? crl,
            bool buildAIAExtensions = false)
        {

            var intermediateCertWithKey = intermediateCert.CopyWithPrivateKey(intermediate);

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

            if (buildAIAExtensions)
            {
                var authorityInfoAccessBuilder = new AuthorityInformationAccessBuilder();
                authorityInfoAccessBuilder.AdCertificateAuthorityIssuerUri(new Uri(SureFhirLabsIntermediatePublicCertHosted));
                var aiaExtension = authorityInfoAccessBuilder.Build();
                clientCertRequest.CertificateExtensions.Add(aiaExtension);
            }

            using var clientCert = clientCertRequest.Create(
                intermediateCertWithKey,
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddYears(2),
                new ReadOnlySpan<byte>(RandomNumberGenerator.GetBytes(16)));
            // Do something with these certs, like export them to PFX,
            // or add them to an X509Store, or whatever.
            var clientCertWithKey = clientCert.CopyWithPrivateKey(rsaKey);


            var certPackage = new X509Certificate2Collection();
            certPackage.Add(clientCertWithKey);
            certPackage.Add(intermediateCert);
            certPackage.Add(new X509Certificate2(caCert.Export(X509ContentType.Cert)));

            var clientBytes = certPackage.Export(X509ContentType.Pkcs12, "udap-test");
            File.WriteAllBytes($"{clientCertFilePath}.pfx", clientBytes);
            char[] clientPem = PemEncoding.Write("CERTIFICATE", clientCert.RawData);
            File.WriteAllBytes($"{clientCertFilePath}.cer", clientPem.Select(c => (byte)c).ToArray());
        }

        private void UpdateWindowsMachineStore(X509Certificate2 certificate)
        {
            //This could be modified to handle Linux also... Maybe later.
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadWrite);

                var oldCert = store.Certificates.SingleOrDefault(c => c.Subject == certificate.Subject);

                if (oldCert != null)
                {
                    store.Remove(oldCert);
                }

                store.Add(certificate);
                store.Close();
            }
        }

        private static X509Extension MakeCdp(string url)
        {
            //
            // urls less than 119 char solution.
            // From Bartonjs of course.
            //
            // https://stackoverflow.com/questions/60742814/add-crl-distribution-points-cdp-extension-to-x509certificate2-certificate
            //
            // From Crypt32:  .NET doesn't support CDP extension. You have to use 3rd party libraries for that. BC is ok if it works for you.
            // Otherwise write you own. :)
            //

            byte[] encodedUrl = Encoding.ASCII.GetBytes(url);

            if (encodedUrl.Length > 119)
            {
                throw new NotSupportedException();
            }

            byte[] payload = new byte[encodedUrl.Length + 10];
            int offset = 0;
            payload[offset++] = 0x30;
            payload[offset++] = (byte)(encodedUrl.Length + 8);
            payload[offset++] = 0x30;
            payload[offset++] = (byte)(encodedUrl.Length + 6);
            payload[offset++] = 0xA0;
            payload[offset++] = (byte)(encodedUrl.Length + 4);
            payload[offset++] = 0xA0;
            payload[offset++] = (byte)(encodedUrl.Length + 2);
            payload[offset++] = 0x86;
            payload[offset++] = (byte)(encodedUrl.Length);
            Buffer.BlockCopy(encodedUrl, 0, payload, offset, encodedUrl.Length);

            return new X509Extension("2.5.29.31", payload, critical: false);
        }

        private static void AddAuthorityKeyIdentifier(X509Certificate2 caCert, CertificateRequest intermediateReq, ITestOutputHelper testOutputHelper)
        {
            //
            // Found way to generate intermediate below
            //
            // https://github.com/rwatjen/AzureIoTDPSCertificates/blob/711429e1b6dee7857452233a73f15c22c2519a12/src/DPSCertificateTool/CertificateUtil.cs#L69
            // https://blog.rassie.dk/2018/04/creating-an-x-509-certificate-chain-in-c/
            //


            var issuerSubjectKey = caCert.Extensions?["2.5.29.14"].RawData;
            var segment = new ArraySegment<byte>(issuerSubjectKey, 2, issuerSubjectKey.Length - 2);
            var authorityKeyIdentifier = new byte[segment.Count + 4];
            // these bytes define the "KeyID" part of the AuthorityKeyIdentifier
            authorityKeyIdentifier[0] = 0x30;
            authorityKeyIdentifier[1] = 0x16;
            authorityKeyIdentifier[2] = 0x80;
            authorityKeyIdentifier[3] = 0x14;
            segment.CopyTo(authorityKeyIdentifier, 4);
            intermediateReq.CertificateExtensions.Add(new X509Extension("2.5.29.35", authorityKeyIdentifier, false));
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