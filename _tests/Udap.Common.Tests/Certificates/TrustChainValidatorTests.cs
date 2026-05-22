#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Udap.Common.Certificates;
using Udap.Common.Extensions;
using Udap.Common.Metadata;
using Udap.Common.Models;
using Udap.Model;
using Udap.Util.Extensions;
using Xunit.Abstractions;
using ZiggyCreatures.Caching.Fusion;
using BcX509Extensions = Org.BouncyCastle.Asn1.X509.X509Extensions;
using X509Certificate2 = System.Security.Cryptography.X509Certificates.X509Certificate2;

namespace Udap.Common.Tests.Certificates;
public class TrustChainValidatorTests
{
    private readonly ITestOutputHelper _testOutputHelper;
    private readonly IConfigurationRoot _configuration;
    private readonly FakeChainValidatorDiagnostics _diagnosticsChainValidator = new FakeChainValidatorDiagnostics();

    public TrustChainValidatorTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;

        _configuration = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json", false, true)
            .Build();
    }

    [Fact]
    public async Task GoodValidatorTest()
    {
        var file = _configuration["UdapMetadataOptionsFile"] ?? "udap.metadata.options.json";
        var json = File.ReadAllText(file);
        var udapMetadataOptions = JsonSerializer.Deserialize<UdapMetadataOptions>(json);
        var udapMetadataOptionsMock = Substitute.For<IUdapMetadataOptionsProvider>();
        udapMetadataOptionsMock.Value.Returns(udapMetadataOptions);
        
        var udapFileCertStoreManifest = new UdapFileCertStoreManifest();
        _configuration.GetSection(Constants.UdapFileCertStoreManifestSectionName).Bind(udapFileCertStoreManifest);

        var udapFileCertStoreManifestOptions = Substitute.For<IOptionsMonitor<UdapFileCertStoreManifest>>();
        udapFileCertStoreManifestOptions.CurrentValue.Returns(udapFileCertStoreManifest);

        var privateCertificateStore = new IssuedCertificateStore(udapFileCertStoreManifestOptions, Substitute.For<ILogger<IssuedCertificateStore>>());
        var metaDataBuilder = new UdapMetaDataBuilder<UdapMetadataOptions, UdapMetadata>(
            udapMetadataOptionsMock, 
            privateCertificateStore, 
            Substitute.For<ILogger<UdapMetaDataBuilder<UdapMetadataOptions, UdapMetadata>>>());
        var metadata = await metaDataBuilder.SignMetaData("https://fhirlabs.net/fhir/r4");

        // var metadata = disco.Json?.Deserialize<UdapMetadata>();
        var jwt = new JwtSecurityToken(metadata!.SignedMetadata);
        var tokenHeader = jwt.Header;
        // _testOutputHelper.WriteLine(tokenHeader.X5c);
        var x5CArray = JsonNode.Parse(tokenHeader.X5c)?.AsArray()!;
        
#if NET9_0_OR_GREATER
        var cert = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(x5CArray.First()!.ToString()));
#else
        var cert = new X509Certificate2(Convert.FromBase64String(x5CArray.First()!.ToString()));
#endif
        var tokenHandler = new JwtSecurityTokenHandler();
        
        tokenHandler.ValidateToken(metadata.SignedMetadata, new TokenValidationParameters
        {
            RequireSignedTokens = true,
            ValidateIssuer = true,
            ValidIssuers = ["https://fhirlabs.net/fhir/r4"], //With ValidateIssuer = true issuer is validated against this list.  Docs are not clear on this, thus this example.
            ValidateAudience = false, // No aud for UDAP metadata
            ValidateLifetime = true,
            IssuerSigningKey = new X509SecurityKey(cert),
            ValidAlgorithms = [tokenHeader.Alg], //must match signing algorithm
        
        }, out _);

        //
        // Certificate revocation is offline for unit tests.
        //
        var problemFlags = ChainProblemStatus.NotTimeValid |
                           ChainProblemStatus.Revoked |
                           ChainProblemStatus.NotSignatureValid |
                           ChainProblemStatus.InvalidBasicConstraints;

        Assert.True(await ValidateCertificateChain(cert, problemFlags, "udap://fhirlabs.net"));
        Assert.False(_diagnosticsChainValidator.Called);
    }

    [Fact]
    public async Task MissingCertificateForCommunityTest()
    {
        var udapMetadataOptions = new UdapMetadataOptions();
        _configuration.GetSection(Constants.UdapMetadataOptionsSectionName).Bind(udapMetadataOptions);
        var udapMetadataOptionsProviderMock = Substitute.For<IUdapMetadataOptionsProvider>();
        udapMetadataOptionsProviderMock.Value.Returns(udapMetadataOptions);

        _configuration.GetSection(Constants.UdapMetadataOptionsSectionName).Bind(udapMetadataOptions);

        var udapFileCertStoreManifest = new UdapFileCertStoreManifest();
        _configuration.GetSection(Constants.UdapFileCertStoreManifestSectionName).Bind(udapFileCertStoreManifest);

        var udapFileCertStoreManifestOptions = Substitute.For<IOptionsMonitor<UdapFileCertStoreManifest>>();
        udapFileCertStoreManifestOptions.CurrentValue.Returns(udapFileCertStoreManifest);

        var privateCertificateStore = new IssuedCertificateStore(udapFileCertStoreManifestOptions, Substitute.For<ILogger<IssuedCertificateStore>>());
        var metaDataBuilder = new UdapMetaDataBuilder<UdapMetadataOptions, UdapMetadata>(
            udapMetadataOptionsProviderMock, 
            privateCertificateStore, 
            Substitute.For<ILogger<UdapMetaDataBuilder<UdapMetadataOptions, UdapMetadata>>>());
        var metadata = await metaDataBuilder.SignMetaData("https://fhirlabs.net/fhir/r4", "http://MissingCertificate");

        Assert.Null(metadata);
    }

    [Fact]
    public async Task UnkownCommunityTest()
    {
        var udapMetadataOptionsProvider = Substitute.For<IUdapMetadataOptionsProvider>();
        udapMetadataOptionsProvider.Value.Returns(new UdapMetadataOptions());
        _configuration.GetSection(Constants.UdapMetadataOptionsSectionName).Bind(udapMetadataOptionsProvider);

        var udapFileCertStoreManifest = new UdapFileCertStoreManifest();
        _configuration.GetSection(Constants.UdapFileCertStoreManifestSectionName).Bind(udapFileCertStoreManifest);

        var udapFileCertStoreManifestOptions = Substitute.For<IOptionsMonitor<UdapFileCertStoreManifest>>();
        udapFileCertStoreManifestOptions.CurrentValue.Returns(udapFileCertStoreManifest);

        var privateCertificateStore = new IssuedCertificateStore(udapFileCertStoreManifestOptions, Substitute.For<ILogger<IssuedCertificateStore>>());
        var metaDataBuilder = new UdapMetaDataBuilder<UdapMetadataOptions, UdapMetadata>(
            udapMetadataOptionsProvider, 
            privateCertificateStore, 
            Substitute.For<ILogger<UdapMetaDataBuilder<UdapMetadataOptions, UdapMetadata>>>());
        var metadata = await metaDataBuilder.SignMetaData("https://fhirlabs.net/fhir/r4", "udap://unknown");

        Assert.Null(metadata);
    }

    [Fact]
    public async Task FindCommunityTest()
    {
        var file = _configuration["UdapMetadataOptionsFile"] ?? "udap.metadata.options.json";
        var json = File.ReadAllText(file);
        var udapMetadataOptions = JsonSerializer.Deserialize<UdapMetadataOptions>(json);
        var udapMetadataOptionsProviderMock = Substitute.For<IUdapMetadataOptionsProvider>();
        udapMetadataOptionsProviderMock.Value.Returns(udapMetadataOptions);

        var udapFileCertStoreManifest = new UdapFileCertStoreManifest();
        _configuration.GetSection(Constants.UdapFileCertStoreManifestSectionName).Bind(udapFileCertStoreManifest);

        var udapFileCertStoreManifestOptions = Substitute.For<IOptionsMonitor<UdapFileCertStoreManifest>>();
        udapFileCertStoreManifestOptions.CurrentValue.Returns(udapFileCertStoreManifest);

        var privateCertificateStore = new IssuedCertificateStore(udapFileCertStoreManifestOptions, Substitute.For<ILogger<IssuedCertificateStore>>());
        var metaDataBuilder = new UdapMetaDataBuilder<UdapMetadataOptions, UdapMetadata>(
            udapMetadataOptionsProviderMock, 
            privateCertificateStore, 
            Substitute.For<ILogger<UdapMetaDataBuilder<UdapMetadataOptions, UdapMetadata>>>());
        var communities = metaDataBuilder.GetCommunities();

        Assert.Equal(6, communities.Count);
        Assert.Contains(communities, c => c == "udap://fhirlabs.net");
        Assert.Contains(communities, c => c == "udap://expired.fhirlabs.net/");
        Assert.Contains(communities, c => c == "udap://untrusted.fhirlabs.net/");

        var communityHtml = await metaDataBuilder.GetCommunitiesAsHtml("https://baseurl");

        Assert.False(string.IsNullOrWhiteSpace(communityHtml));
        Assert.Contains("href=\"https://baseurl/.well-known/udap?community=udap://fhirlabs.net\"", communityHtml);
        Assert.Contains("href=\"https://baseurl/.well-known/udap?community=udap://untrusted.fhirlabs.net/\"", communityHtml);
    }

    [Fact]
    public async Task ValidateUntrustedCertificate()
    {
        var problemFlags = ChainProblemStatus.NotTimeValid |
                           ChainProblemStatus.Revoked |
                           ChainProblemStatus.NotSignatureValid |
                           ChainProblemStatus.InvalidBasicConstraints;

        var configuration = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json", false, true)
            .Build();

        var services = new ServiceCollection();

        // UDAP CertStore
        services.Configure<UdapFileCertStoreManifest>(configuration.GetSection(Constants.UdapFileCertStoreManifestSectionName));
        services.AddSingleton<ITrustAnchorStore>(sp =>
            new TrustAnchorFileStore(
                sp.GetRequiredService<IOptionsMonitor<UdapFileCertStoreManifest>>(),
                Substitute.For<ILogger<TrustAnchorFileStore>>()));

        var sp = services.BuildServiceProvider();
        var certStore = sp.GetRequiredService<ITrustAnchorStore>();

        var certificateStore = await certStore.Resolve();
        var anchors = certificateStore.AnchorCertificates.ToList();

        // Coverage for frameworks not hosted in example projects.  Funky but works.
        Assert.NotEmpty(certStore.AnchorCertificates.AsEnumerable().ToX509Collection()!);

        var intermediates = anchors
            .SelectMany(a => a.Intermediates!.Select(i => X509Certificate2.CreateFromPem(i.Certificate))).ToArray()
            .ToX509Collection();

        var anchorCertificates = anchors
            .Select(c => X509Certificate2.CreateFromPem(c.Certificate))
            .OrderBy(certificate => certificate.NotBefore)
            .ToArray()
            .ToX509Collection();


        var validator = new TrustChainValidator(
            problemFlags,
            false, // no revocation checking in tests
            _testOutputHelper.ToLogger<TrustChainValidator>());

        validator.Problem += _diagnosticsChainValidator.OnChainProblem;

        // Help while writing tests to see problems summarized.
        validator.Error += (_, exception) => _testOutputHelper.WriteLine("Error: " + exception.Message);
        validator.Problem += element => _testOutputHelper.WriteLine("Problem: " + element.Problems.Summarize(problemFlags));
        validator.Untrusted += certificate2 => _testOutputHelper.WriteLine("Untrusted: " + certificate2.Subject);

#if NET9_0_OR_GREATER
        var cert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.untrusted.client.pfx", "udap-test", X509KeyStorageFlags.Exportable);
#else
        var cert = new X509Certificate2("CertStore/issued/fhirlabs.net.untrusted.client.pfx", "udap-test", X509KeyStorageFlags.Exportable);
#endif

        var trusted = await validator.IsTrustedCertificateAsync(
            "client_name",
            cert,
            intermediates,
            anchorCertificates!);

        Assert.False(trusted);
    }

    public async Task<bool> ValidateCertificateChain(
            X509Certificate2 issuedCertificate2,
            ChainProblemStatus problemFlags,
            string communityName)
    {
        var configuration = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json", false, true)
        .Build();

        var services = new ServiceCollection();

        // UDAP CertStore
        services.Configure<UdapFileCertStoreManifest>(configuration.GetSection(Constants.UdapFileCertStoreManifestSectionName));
        services.AddSingleton<ITrustAnchorStore>(sp =>
            new TrustAnchorFileStore(
                sp.GetRequiredService<IOptionsMonitor<UdapFileCertStoreManifest>>(),
                Substitute.For<ILogger<TrustAnchorFileStore>>()));


        var sp = services.BuildServiceProvider();
        var certStore = sp.GetRequiredService<ITrustAnchorStore>();

        var certificateStore = await certStore.Resolve();
        var anchors = certificateStore.AnchorCertificates
            .Where(c => c.Community == communityName)
            .ToList();

        // Coverage for frameworks not hosted in example projects.  Funky but works.
        Assert.NotEmpty(certStore.AnchorCertificates.AsEnumerable().ToX509Collection()!);

        var intermediates = anchors
            .SelectMany(a => a.Intermediates!.Select(i => X509Certificate2.CreateFromPem(i.Certificate))).ToArray()
            .ToX509Collection();

        var anchorCertificates = anchors
            .Select(c => X509Certificate2.CreateFromPem(c.Certificate))
            .OrderBy(certificate => certificate.NotBefore)
            .ToArray()
            .ToX509Collection();

        var validator = new TrustChainValidator(
            problemFlags,
            false, // no revocation checking in tests
            _testOutputHelper.ToLogger<TrustChainValidator>());

        validator.Problem += _diagnosticsChainValidator.OnChainProblem;

        // Help while writing tests to see problems summarized.
        validator.Error += (_, exception) => _testOutputHelper.WriteLine("Error: " + exception.Message);
        validator.Problem += element => _testOutputHelper.WriteLine("Problem: " + element.Problems.Summarize(problemFlags));
        validator.Untrusted += certificate2 => _testOutputHelper.WriteLine("Untrusted: " + certificate2.Subject);

        return await validator.IsTrustedCertificateAsync(
            "client_name",
            issuedCertificate2,
            intermediates,
            anchorCertificates!);
    }

    [Fact]
    public async Task RevokedCertificate_FiresProblemEvent_WithRevokedStatus()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());
        const string crlUrl = "https://example.com/revoked-event-test.crl";

        var bcLeafCert = CreateLeafCert(caKeyPair, bcRootCert, leafSerialNumber, crlUrl);

        // CRL with the leaf revoked
        var crlGenerator = new X509V2CrlGenerator();
        crlGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        crlGenerator.SetThisUpdate(DateTime.UtcNow);
        crlGenerator.SetNextUpdate(DateTime.UtcNow.AddHours(24));
        crlGenerator.AddCrlEntry(leafSerialNumber, DateTime.UtcNow.AddHours(-1), CrlReason.KeyCompromise);
        var crl = crlGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));

        var handler = new MockHttpHandler();
        handler.SetResponse(crlUrl, crl.GetEncoded());
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: httpClient);

        var problemEvents = new List<ChainElementInfo>();
        var untrustedEvents = new List<X509Certificate2>();
        validator.Problem += element => problemEvents.Add(element);
        validator.Untrusted += cert => untrustedEvents.Add(cert);

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeafCert.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRootCert.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
#endif
        var anchors = new X509Certificate2Collection(rootDotNet);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        Assert.False(result);

        // Problem event should fire with Revoked status
        Assert.Single(problemEvents);
        var problem = problemEvents[0];
        Assert.Contains(problem.Problems, p => p.Status == ChainProblemStatus.Revoked);
        Assert.Contains(problem.Problems, p => p.StatusInformation.Contains("revoked"));

        // Untrusted event should fire for the leaf cert
        Assert.Single(untrustedEvents);
        Assert.Equal(leafDotNet.Thumbprint, untrustedEvents[0].Thumbprint);
    }

    [Fact]
    public async Task ExpiredCrl_FiresProblemEvent_WithRevocationStatusUnknown()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());
        const string crlUrl = "https://example.com/expired-crl-test.crl";

        var bcLeafCert = CreateLeafCert(caKeyPair, bcRootCert, leafSerialNumber, crlUrl);

        // CRL that has already expired (NextUpdate in the past)
        var crlGenerator = new X509V2CrlGenerator();
        crlGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        crlGenerator.SetThisUpdate(DateTime.UtcNow.AddHours(-48));
        crlGenerator.SetNextUpdate(DateTime.UtcNow.AddHours(-24)); // expired 24 hours ago
        var crl = crlGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));

        var handler = new MockHttpHandler();
        handler.SetResponse(crlUrl, crl.GetEncoded());
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: httpClient);

        var problemEvents = new List<ChainElementInfo>();
        var untrustedEvents = new List<X509Certificate2>();
        validator.Problem += element => problemEvents.Add(element);
        validator.Untrusted += cert => untrustedEvents.Add(cert);

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeafCert.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRootCert.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
#endif
        var anchors = new X509Certificate2Collection(rootDotNet);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        Assert.False(result);

        // Problem event should fire with RevocationStatusUnknown
        Assert.Single(problemEvents);
        var problem = problemEvents[0];
        Assert.Contains(problem.Problems, p => p.Status == ChainProblemStatus.RevocationStatusUnknown);
        Assert.Contains(problem.Problems, p => p.StatusInformation.Contains("expired"));

        // Untrusted event should fire
        Assert.Single(untrustedEvents);
    }

    [Fact]
    public async Task ValidCertificate_NoEventsFiresWhenChainIsGood()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());
        const string crlUrl = "https://example.com/valid-no-events-test.crl";

        var bcLeafCert = CreateLeafCert(caKeyPair, bcRootCert, leafSerialNumber, crlUrl);

        // CRL with no revoked certs
        var crlGenerator = new X509V2CrlGenerator();
        crlGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        crlGenerator.SetThisUpdate(DateTime.UtcNow);
        crlGenerator.SetNextUpdate(DateTime.UtcNow.AddHours(24));
        var crl = crlGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));

        var handler = new MockHttpHandler();
        handler.SetResponse(crlUrl, crl.GetEncoded());
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: httpClient);

        var problemEvents = new List<ChainElementInfo>();
        var untrustedEvents = new List<X509Certificate2>();
        var errorEvents = new List<(X509Certificate2, Exception)>();
        validator.Problem += element => problemEvents.Add(element);
        validator.Untrusted += cert => untrustedEvents.Add(cert);
        validator.Error += (cert, ex) => errorEvents.Add((cert, ex));

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeafCert.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRootCert.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
#endif
        var anchors = new X509Certificate2Collection(rootDotNet);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        Assert.True(result);
        Assert.Empty(problemEvents);
        Assert.Empty(untrustedEvents);
        Assert.Empty(errorEvents);
    }

    [Fact]
    public async Task NoCrlDistributionPoint_WithOfflineRevocationFlag_ReportsCrlNotFound()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());

        // Leaf cert WITHOUT a CRL distribution point
        var bcLeafCert = CreateLeafCertWithoutCrlDp(caKeyPair, bcRootCert, leafSerialNumber);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        // CrlNotFound is not in DefaultProblemFlags (it's a soft-fail by default).
        // Include it explicitly to test that it causes chain failure.
        var problemFlags = TrustChainValidator.DefaultProblemFlags | ChainProblemStatus.CrlNotFound;

        var validator = new TrustChainValidator(
            problemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: new HttpClient());

        var problemEvents = new List<ChainElementInfo>();
        validator.Problem += element => problemEvents.Add(element);

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeafCert.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRootCert.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
#endif
        var anchors = new X509Certificate2Collection(rootDotNet);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        Assert.False(result);
        Assert.Single(problemEvents);
        Assert.Contains(problemEvents[0].Problems, p => p.Status == ChainProblemStatus.CrlNotFound);
        Assert.Contains(problemEvents[0].Problems, p => p.StatusInformation.Contains("CRL Distribution Point"));
    }

    [Fact]
    public async Task NoCrlDistributionPoint_WithoutOfflineRevocationFlag_NoProblemAdded()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());

        var bcLeafCert = CreateLeafCertWithoutCrlDp(caKeyPair, bcRootCert, leafSerialNumber);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        // Exclude OfflineRevocation — no CrlNotFound problem should be added at all
        var problemFlags = ChainProblemStatus.NotTimeValid |
                           ChainProblemStatus.Revoked |
                           ChainProblemStatus.NotSignatureValid |
                           ChainProblemStatus.InvalidBasicConstraints;

        var validator = new TrustChainValidator(
            problemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: new HttpClient());

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeafCert.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRootCert.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
#endif
        var anchors = new X509Certificate2Collection(rootDotNet);

        var chainResult = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            null,
            anchors,
            null);

        Assert.True(chainResult.IsValid);

        // No problems at all — CrlNotFound is not added when OfflineRevocation flag is absent
        var allProblems = chainResult.ChainElements.SelectMany(e => e.Problems).ToList();
        Assert.Empty(allProblems);
    }

    [Fact]
    public async Task NoCrlDistributionPoint_DefaultFlags_SoftFail()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());

        var bcLeafCert = CreateLeafCertWithoutCrlDp(caKeyPair, bcRootCert, leafSerialNumber);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        // DefaultProblemFlags includes OfflineRevocation, so CrlNotFound IS added,
        // but CrlNotFound itself is not in DefaultProblemFlags, so chain passes (soft-fail).
        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: new HttpClient());

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeafCert.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRootCert.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
#endif
        var anchors = new X509Certificate2Collection(rootDotNet);

        var chainResult = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            null,
            anchors,
            null);

        // Chain is valid (CrlNotFound is soft-fail)
        Assert.True(chainResult.IsValid);

        // But the CrlNotFound problem IS recorded in chain elements
        var leafProblems = chainResult.ChainElements[0].Problems;
        Assert.Contains(leafProblems, p => p.Status == ChainProblemStatus.CrlNotFound);
    }

    [Fact]
    public async Task CrlDownloadFails_DefaultFlags_RevocationUnknown()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());
        const string crlUrl = "https://example.com/missing.crl";

        var bcLeafCert = CreateLeafCert(caKeyPair, bcRootCert, leafSerialNumber, crlUrl);

        // MockHttpHandler with no response registered for the CRL URL → returns 404
        var handler = new MockHttpHandler();
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: httpClient);

        var problemEvents = new List<ChainElementInfo>();
        validator.Problem += element => problemEvents.Add(element);

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeafCert.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRootCert.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
#endif
        var anchors = new X509Certificate2Collection(rootDotNet);

        var chainResult = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            null,
            anchors,
            null);

        // No CRL was successfully checked → RevocationStatusUnknown (in DefaultProblemFlags) → chain invalid
        Assert.False(chainResult.IsValid);

        var leafProblems = chainResult.ChainElements[0].Problems;
        Assert.Contains(leafProblems, p => p.Status == ChainProblemStatus.CrlFetchFailed);
        Assert.Contains(leafProblems, p => p.Status == ChainProblemStatus.RevocationStatusUnknown);

        Assert.Single(problemEvents);
    }

    [Fact]
    public async Task CrlDownloadFails_WithCrlFetchFailedFlag_FailsValidation()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());
        const string crlUrl = "https://example.com/missing-hard-fail.crl";

        var bcLeafCert = CreateLeafCert(caKeyPair, bcRootCert, leafSerialNumber, crlUrl);

        var handler = new MockHttpHandler();
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        // Include CrlFetchFailed in flags to make it a hard failure
        var problemFlags = TrustChainValidator.DefaultProblemFlags | ChainProblemStatus.CrlFetchFailed;

        var validator = new TrustChainValidator(
            problemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: httpClient);

        var problemEvents = new List<ChainElementInfo>();
        validator.Problem += element => problemEvents.Add(element);

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeafCert.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRootCert.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
#endif
        var anchors = new X509Certificate2Collection(rootDotNet);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        Assert.False(result);
        Assert.Single(problemEvents);
        Assert.Contains(problemEvents[0].Problems, p => p.Status == ChainProblemStatus.CrlFetchFailed);
    }

    [Fact]
    public async Task CrlSignedByWrongIssuer_DefaultFlags_RevocationUnknown()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());
        const string crlUrl = "https://example.com/wrong-issuer.crl";

        var bcLeafCert = CreateLeafCert(caKeyPair, bcRootCert, leafSerialNumber, crlUrl);

        // CRL signed by a DIFFERENT key (not the CA)
        var rogueKeyPairGenerator = new RsaKeyPairGenerator();
        rogueKeyPairGenerator.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var rogueKeyPair = rogueKeyPairGenerator.GenerateKeyPair();

        var crlGenerator = new X509V2CrlGenerator();
        crlGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        crlGenerator.SetThisUpdate(DateTime.UtcNow);
        crlGenerator.SetNextUpdate(DateTime.UtcNow.AddHours(24));
        var crl = crlGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", rogueKeyPair.Private));

        var handler = new MockHttpHandler();
        handler.SetResponse(crlUrl, crl.GetEncoded());
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: httpClient);

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeafCert.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRootCert.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
#endif
        var anchors = new X509Certificate2Collection(rootDotNet);

        var chainResult = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            null,
            anchors,
            null);

        // CRL signature failed → no CRL successfully checked → RevocationStatusUnknown → chain invalid
        Assert.False(chainResult.IsValid);

        var leafProblems = chainResult.ChainElements[0].Problems;
        Assert.Contains(leafProblems, p => p.Status == ChainProblemStatus.RevocationStatusUnknown);
    }

    [Fact]
    public async Task NoHttpClientOrCache_DefaultFlags_RevocationUnknown()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());
        const string crlUrl = "https://example.com/no-client.crl";

        var bcLeafCert = CreateLeafCert(caKeyPair, bcRootCert, leafSerialNumber, crlUrl);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        // No cache, no HttpClient
        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: null);

        var problemEvents = new List<ChainElementInfo>();
        validator.Problem += element => problemEvents.Add(element);

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeafCert.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRootCert.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
#endif
        var anchors = new X509Certificate2Collection(rootDotNet);

        var chainResult = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            null,
            anchors,
            null);

        // No CRL checked → RevocationStatusUnknown → chain invalid
        Assert.False(chainResult.IsValid);

        var leafProblems = chainResult.ChainElements[0].Problems;
        Assert.Contains(leafProblems, p => p.Status == ChainProblemStatus.CrlFetchFailed);
        Assert.Contains(leafProblems, p => p.Status == ChainProblemStatus.RevocationStatusUnknown);

        Assert.Single(problemEvents);
    }

    [Fact]
    public async Task RelativeDistributionPointName_IsSkipped_FallsThrough()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());
        const string crlUrl = "https://example.com/after-relative.crl";

        // Create leaf with two CDPs: first is NameRelativeToCRLIssuer (skipped), second is valid URI
        var bcLeafCert = CreateLeafCertWithMultipleCdps(caKeyPair, bcRootCert, leafSerialNumber, crlUrl);

        var crlGenerator = new X509V2CrlGenerator();
        crlGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        crlGenerator.SetThisUpdate(DateTime.UtcNow);
        crlGenerator.SetNextUpdate(DateTime.UtcNow.AddHours(24));
        var crl = crlGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));

        var handler = new MockHttpHandler();
        handler.SetResponse(crlUrl, crl.GetEncoded());
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: httpClient);

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeafCert.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRootCert.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
#endif
        var anchors = new X509Certificate2Collection(rootDotNet);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        // Relative DP was skipped, valid URI DP was used, cert is not revoked
        Assert.True(result);
        Assert.Equal(1, handler.CallCount(crlUrl));
    }

    [Fact]
    public async Task NonUriGeneralName_IsSkipped_FallsThrough()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());
        const string crlUrl = "https://example.com/after-non-uri.crl";

        // Create leaf with a CDP containing a non-URI general name followed by a valid URI
        var bcLeafCert = CreateLeafCertWithNonUriGeneralName(caKeyPair, bcRootCert, leafSerialNumber, crlUrl);

        var crlGenerator = new X509V2CrlGenerator();
        crlGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        crlGenerator.SetThisUpdate(DateTime.UtcNow);
        crlGenerator.SetNextUpdate(DateTime.UtcNow.AddHours(24));
        var crl = crlGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));

        var handler = new MockHttpHandler();
        handler.SetResponse(crlUrl, crl.GetEncoded());
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: httpClient);

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeafCert.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRootCert.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
#endif
        var anchors = new X509Certificate2Collection(rootDotNet);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        // Non-URI general name was skipped, valid URI was used
        Assert.True(result);
        Assert.Equal(1, handler.CallCount(crlUrl));
    }

    [Fact]
    public async Task EmptyUriInCdp_IsSkipped_FallsThrough()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());
        const string crlUrl = "https://example.com/after-empty-uri.crl";

        // Create leaf with a CDP containing an empty URI followed by a valid URI
        var bcLeafCert = CreateLeafCertWithEmptyUri(caKeyPair, bcRootCert, leafSerialNumber, crlUrl);

        var crlGenerator = new X509V2CrlGenerator();
        crlGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        crlGenerator.SetThisUpdate(DateTime.UtcNow);
        crlGenerator.SetNextUpdate(DateTime.UtcNow.AddHours(24));
        var crl = crlGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));

        var handler = new MockHttpHandler();
        handler.SetResponse(crlUrl, crl.GetEncoded());
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: httpClient);

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeafCert.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRootCert.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
#endif
        var anchors = new X509Certificate2Collection(rootDotNet);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        // Empty URI was skipped, valid URI was used
        Assert.True(result);
        Assert.Equal(1, handler.CallCount(crlUrl));
    }

    [Fact]
    public async Task CrlWithNoNextUpdate_IsNotTreatedAsExpired()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());
        const string crlUrl = "https://example.com/no-next-update.crl";

        var bcLeafCert = CreateLeafCert(caKeyPair, bcRootCert, leafSerialNumber, crlUrl);

        // CRL with NO NextUpdate field
        var crlGenerator = new X509V2CrlGenerator();
        crlGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        crlGenerator.SetThisUpdate(DateTime.UtcNow);
        // Deliberately not calling SetNextUpdate
        var crl = crlGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));

        var handler = new MockHttpHandler();
        handler.SetResponse(crlUrl, crl.GetEncoded());
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: httpClient);

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeafCert.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRootCert.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
#endif
        var anchors = new X509Certificate2Collection(rootDotNet);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        // CRL with no NextUpdate should not be treated as expired
        Assert.True(result);
    }

    [Fact]
    public async Task CrlVerification_SkippedWhenCertIsLastInChain()
    {
        // When certIndex + 1 >= chain.Count, the CRL signature verification
        // is skipped (no issuer available to verify against). This happens when
        // a self-signed cert with a CDP is validated as the only cert in the chain.

        var keyPairGenerator = new RsaKeyPairGenerator();
        keyPairGenerator.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var keyPair = keyPairGenerator.GenerateKeyPair();

        var serialNumber = BigInteger.ProbablePrime(120, new Random());
        const string crlUrl = "https://example.com/self-signed.crl";

        // Self-signed cert that is ALSO a trust anchor, with a CDP
        var certGenerator = new X509V3CertificateGenerator();
        certGenerator.SetSerialNumber(serialNumber);
        certGenerator.SetIssuerDN(new X509Name("CN=Self Signed"));
        certGenerator.SetSubjectDN(new X509Name("CN=Self Signed"));
        certGenerator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        certGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));
        certGenerator.SetPublicKey(keyPair.Public);
        certGenerator.AddExtension(BcX509Extensions.BasicConstraints, true, new BasicConstraints(true));
        certGenerator.AddExtension(BcX509Extensions.SubjectKeyIdentifier, false,
            X509ExtensionUtilities.CreateSubjectKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public)));

        var crlDp = new DistributionPoint(
            new DistributionPointName(
                DistributionPointName.FullName,
                new GeneralNames(new GeneralName(GeneralName.UniformResourceIdentifier, crlUrl))),
            null, null);
        certGenerator.AddExtension(BcX509Extensions.CrlDistributionPoints, false,
            new CrlDistPoint(new[] { crlDp }));

        var bcCert = certGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", keyPair.Private));

        // CRL signed by the same key (valid for self-signed), cert not revoked
        var crlGenerator = new X509V2CrlGenerator();
        crlGenerator.SetIssuerDN(new X509Name("CN=Self Signed"));
        crlGenerator.SetThisUpdate(DateTime.UtcNow);
        crlGenerator.SetNextUpdate(DateTime.UtcNow.AddHours(24));
        var crl = crlGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", keyPair.Private));

        var handler = new MockHttpHandler();
        handler.SetResponse(crlUrl, crl.GetEncoded());
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: httpClient);

#if NET9_0_OR_GREATER
        var dotNetCert = X509CertificateLoader.LoadCertificate(bcCert.GetEncoded());
#else
        var dotNetCert = new X509Certificate2(bcCert.GetEncoded());
#endif
        // Use the same cert as both the leaf and the anchor
        var anchors = new X509Certificate2Collection(dotNetCert);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            dotNetCert,
            intermediateCertificates: null,
            anchors);

        Assert.True(result);
    }

    [Fact]
    public async Task MalformedCdpExtension_CatchesException_ReportsCrlFetchFailed()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());

        // Create a leaf cert with a malformed CRL Distribution Points extension
        var leafKeyPairGenerator = new RsaKeyPairGenerator();
        leafKeyPairGenerator.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var leafKeyPair = leafKeyPairGenerator.GenerateKeyPair();

        var leafCertGenerator = new X509V3CertificateGenerator();
        leafCertGenerator.SetSerialNumber(leafSerialNumber);
        leafCertGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        leafCertGenerator.SetSubjectDN(new X509Name("CN=Test Leaf Malformed CDP"));
        leafCertGenerator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        leafCertGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));
        leafCertGenerator.SetPublicKey(leafKeyPair.Public);
        leafCertGenerator.AddExtension(BcX509Extensions.AuthorityKeyIdentifier, false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bcRootCert.GetPublicKey())));
        // Add a malformed CDP extension (raw garbage bytes wrapped in OCTET STRING)
        leafCertGenerator.AddExtension(BcX509Extensions.CrlDistributionPoints, false,
            new Org.BouncyCastle.Asn1.DerUtf8String("not-a-valid-cdp"));

        var bcLeafCert = leafCertGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        // Use CrlFetchFailed in flags so the outer catch causes failure
        var problemFlags = TrustChainValidator.DefaultProblemFlags | ChainProblemStatus.CrlFetchFailed;

        var validator = new TrustChainValidator(
            problemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: new HttpClient());

        var problemEvents = new List<ChainElementInfo>();
        validator.Problem += element => problemEvents.Add(element);

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeafCert.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRootCert.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
#endif
        var anchors = new X509Certificate2Collection(rootDotNet);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        Assert.False(result);
        Assert.Single(problemEvents);
        Assert.Contains(problemEvents[0].Problems, p => p.Status == ChainProblemStatus.CrlFetchFailed);
        Assert.Contains(problemEvents[0].Problems, p => p.StatusInformation.Contains("Error checking CRL"));
    }

    [Fact]
    public async Task CrlWithThisUpdateInFuture_RevocationUnknown()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());
        const string crlUrl = "https://example.com/future-this-update.crl";

        var bcLeafCert = CreateLeafCert(caKeyPair, bcRootCert, leafSerialNumber, crlUrl);

        // CRL with ThisUpdate in the future (clock skew or bad CRL)
        var crlGenerator = new X509V2CrlGenerator();
        crlGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        crlGenerator.SetThisUpdate(DateTime.UtcNow.AddHours(24)); // future!
        crlGenerator.SetNextUpdate(DateTime.UtcNow.AddHours(48));
        var crl = crlGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));

        var handler = new MockHttpHandler();
        handler.SetResponse(crlUrl, crl.GetEncoded());
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: httpClient);

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeafCert.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRootCert.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
#endif
        var anchors = new X509Certificate2Collection(rootDotNet);

        var chainResult = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            null,
            anchors,
            null);

        // ThisUpdate in the future → RevocationStatusUnknown → chain invalid
        Assert.False(chainResult.IsValid);
        var leafProblems = chainResult.ChainElements[0].Problems;
        Assert.Contains(leafProblems, p =>
            p.Status == ChainProblemStatus.RevocationStatusUnknown &&
            p.StatusInformation.Contains("ThisUpdate in the future"));
    }

    [Fact]
    public async Task CrlDpWithNonHttpScheme_IsSkipped_FallsThrough()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());
        const string validCrlUrl = "https://example.com/valid.crl";

        // Create leaf with two CDPs: first is ldap:// (skipped), second is https://
        var bcLeafCert = CreateLeafCertWithUnsupportedScheme(caKeyPair, bcRootCert, leafSerialNumber, validCrlUrl);

        var crlGenerator = new X509V2CrlGenerator();
        crlGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        crlGenerator.SetThisUpdate(DateTime.UtcNow);
        crlGenerator.SetNextUpdate(DateTime.UtcNow.AddHours(24));
        var crl = crlGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));

        var handler = new MockHttpHandler();
        handler.SetResponse(validCrlUrl, crl.GetEncoded());
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: httpClient);

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeafCert.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRootCert.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
#endif
        var anchors = new X509Certificate2Collection(rootDotNet);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        // ldap:// URI was skipped, https:// was used, cert is not revoked
        Assert.True(result);
        Assert.Equal(1, handler.CallCount(validCrlUrl));
    }

    [Fact]
    public async Task IsTrustedCertificateAsync_ExceptionDuringValidation_FiresErrorEvent()
    {
        // Trigger the outer catch in IsTrustedCertificateAsync by passing an
        // IEnumerable<Anchor> that throws when enumerated. The code calls
        // anchors.ToList() inside the try block after chain building succeeds,
        // causing an exception that the outer catch handles.
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());
        const string crlUrl = "https://example.com/error-event.crl";
        var bcLeafCert = CreateLeafCert(caKeyPair, bcRootCert, leafSerialNumber, crlUrl);

        var crlGenerator = new X509V2CrlGenerator();
        crlGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        crlGenerator.SetThisUpdate(DateTime.UtcNow);
        crlGenerator.SetNextUpdate(DateTime.UtcNow.AddHours(24));
        var crl = crlGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));

        var handler = new MockHttpHandler();
        handler.SetResponse(crlUrl, crl.GetEncoded());
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: httpClient);

        var errorEvents = new List<(X509Certificate2 cert, Exception ex)>();
        var untrustedEvents = new List<X509Certificate2>();
        validator.Error += (cert, ex) => errorEvents.Add((cert, ex));
        validator.Untrusted += cert => untrustedEvents.Add(cert);

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeafCert.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRootCert.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
#endif
        var anchorCerts = new X509Certificate2Collection(rootDotNet);

        // Create an IEnumerable<Anchor> that throws on enumeration.
        // When the chain reaches the anchor, it calls anchors.ToList() which
        // invokes GetEnumerator → throws → caught by outer catch → NotifyError.
        var faultyAnchors = Substitute.For<IEnumerable<Anchor>>();
        faultyAnchors.GetEnumerator().Returns(
            _ => throw new InvalidOperationException("Simulated anchor store failure"));

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchorCerts,
            anchors: faultyAnchors);

        Assert.False(result.IsValid);
        Assert.Empty(result.ChainElements); // outer catch returns empty

        // Error event fires with the leaf cert and the exception
        Assert.Single(errorEvents);
        Assert.Equal(leafDotNet.Thumbprint, errorEvents[0].cert.Thumbprint);
        Assert.IsType<InvalidOperationException>(errorEvents[0].ex);
        Assert.Contains("Simulated anchor store failure", errorEvents[0].ex.Message);

        // Untrusted event also fires (after the catch block)
        Assert.Single(untrustedEvents);
    }

    // ========================================================================
    // AIA Chasing Tests
    // ========================================================================

    [Fact]
    public async Task AiaChasing_SuccessfulDownload_CompletesChain()
    {
        // Leaf → (AIA chase) → Intermediate → Root
        // Intermediate is NOT provided; the validator must AIA-chase it.
        const string aiaUrl = "https://example.com/intermediate.cer";
        var (caKeyPair, bcRootCert, intKeyPair, bcIntCert, bcLeafCert) =
            CreateThreeLevelPkiWithAia(aiaUrl);

        var handler = new MockHttpHandler();
        handler.SetResponse(aiaUrl, bcIntCert.GetEncoded());
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            ChainProblemStatus.NotTimeValid |
            ChainProblemStatus.NotSignatureValid |
            ChainProblemStatus.InvalidBasicConstraints,
            false, // no revocation checking
            logger,
            downloadCache: null,
            httpClient: httpClient);

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeafCert.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRootCert.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
#endif
        var anchors = new X509Certificate2Collection(rootDotNet);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null, // no intermediates provided
            anchors);

        Assert.True(result);
        Assert.Equal(1, handler.CallCount(aiaUrl));
    }

    [Fact]
    public async Task AiaChasing_ViaCache_CompletesChain()
    {
        const string aiaUrl = "https://example.com/cached-intermediate.cer";
        var (caKeyPair, bcRootCert, intKeyPair, bcIntCert, bcLeafCert) =
            CreateThreeLevelPkiWithAia(aiaUrl);

        var handler = new MockHttpHandler();
        handler.SetResponse(aiaUrl, bcIntCert.GetEncoded());
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        services.AddFusionCache(CertificateDownloadCache.CacheName);
        var sp = services.BuildServiceProvider();

        var cacheProvider = sp.GetRequiredService<IFusionCacheProvider>();
        var cacheLogger = sp.GetRequiredService<ILogger<CertificateDownloadCache>>();
        var downloadCache = new CertificateDownloadCache(cacheProvider, httpClient, cacheLogger);

        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            ChainProblemStatus.NotTimeValid |
            ChainProblemStatus.NotSignatureValid |
            ChainProblemStatus.InvalidBasicConstraints,
            false,
            logger,
            downloadCache: downloadCache);

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeafCert.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRootCert.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
#endif
        var anchors = new X509Certificate2Collection(rootDotNet);

        // First call: downloads and caches
        var result1 = await validator.IsTrustedCertificateAsync(
            "test_client", leafDotNet, intermediateCertificates: null, anchors);
        Assert.True(result1);
        Assert.Equal(1, handler.CallCount(aiaUrl));

        // Second call: served from cache, no additional HTTP call
        var result2 = await validator.IsTrustedCertificateAsync(
            "test_client", leafDotNet, intermediateCertificates: null, anchors);
        Assert.True(result2);
        Assert.Equal(1, handler.CallCount(aiaUrl));
    }

    [Fact]
    public async Task AiaChasing_NoAiaExtension_ChainIncomplete()
    {
        // Leaf signed by intermediate, but no AIA and intermediate not provided → partial chain
        var (caKeyPair, bcRootCert, intKeyPair, bcIntCert, bcLeafCert) =
            CreateThreeLevelPkiWithAia(aiaUrl: null); // no AIA

        var handler = new MockHttpHandler();
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            ChainProblemStatus.NotTimeValid |
            ChainProblemStatus.NotSignatureValid |
            ChainProblemStatus.InvalidBasicConstraints,
            false,
            logger,
            downloadCache: null,
            httpClient: httpClient);

        var untrustedEvents = new List<X509Certificate2>();
        validator.Untrusted += cert => untrustedEvents.Add(cert);

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeafCert.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRootCert.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
#endif
        var anchors = new X509Certificate2Collection(rootDotNet);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        Assert.False(result);
        Assert.Single(untrustedEvents); // couldn't reach anchor
    }

    [Fact]
    public async Task AiaChasing_DownloadFails_ChainIncomplete()
    {
        const string aiaUrl = "https://example.com/missing-intermediate.cer";
        var (caKeyPair, bcRootCert, intKeyPair, bcIntCert, bcLeafCert) =
            CreateThreeLevelPkiWithAia(aiaUrl);

        // Handler does NOT have the URL registered → 404
        var handler = new MockHttpHandler();
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            ChainProblemStatus.NotTimeValid |
            ChainProblemStatus.NotSignatureValid |
            ChainProblemStatus.InvalidBasicConstraints,
            false,
            logger,
            downloadCache: null,
            httpClient: httpClient);

        var untrustedEvents = new List<X509Certificate2>();
        validator.Untrusted += cert => untrustedEvents.Add(cert);

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeafCert.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRootCert.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
#endif
        var anchors = new X509Certificate2Collection(rootDotNet);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        Assert.False(result);
        Assert.Single(untrustedEvents);
        Assert.Equal(1, handler.CallCount(aiaUrl));
    }

    [Fact]
    public async Task AiaChasing_FetchedCertNotIssuer_ChainIncomplete()
    {
        const string aiaUrl = "https://example.com/wrong-intermediate.cer";
        var (caKeyPair, bcRootCert, intKeyPair, bcIntCert, bcLeafCert) =
            CreateThreeLevelPkiWithAia(aiaUrl);

        // Serve a completely different cert that won't verify as issuer
        var (wrongKeyPair, wrongCert) = CreateCaKeyPairAndRoot(); // self-signed, wrong key

        var handler = new MockHttpHandler();
        handler.SetResponse(aiaUrl, wrongCert.GetEncoded());
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            ChainProblemStatus.NotTimeValid |
            ChainProblemStatus.NotSignatureValid |
            ChainProblemStatus.InvalidBasicConstraints,
            false,
            logger,
            downloadCache: null,
            httpClient: httpClient);

        var untrustedEvents = new List<X509Certificate2>();
        validator.Untrusted += cert => untrustedEvents.Add(cert);

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeafCert.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRootCert.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
#endif
        var anchors = new X509Certificate2Collection(rootDotNet);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        Assert.False(result);
        Assert.Single(untrustedEvents);
    }

    [Fact]
    public async Task AiaChasing_NonCaIssuersMethod_IsSkipped()
    {
        // AIA with OCSP access method (not caIssuers) should be skipped.
        // Add a second AIA entry with caIssuers that works.
        const string aiaUrl = "https://example.com/aia-non-ca-issuers.cer";
        var (caKeyPair, bcRootCert, intKeyPair, bcIntCert, bcLeafCert) =
            CreateThreeLevelPkiWithMixedAia(aiaUrl);

        var handler = new MockHttpHandler();
        handler.SetResponse(aiaUrl, bcIntCert.GetEncoded());
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            ChainProblemStatus.NotTimeValid |
            ChainProblemStatus.NotSignatureValid |
            ChainProblemStatus.InvalidBasicConstraints,
            false,
            logger,
            downloadCache: null,
            httpClient: httpClient);

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeafCert.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRootCert.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
#endif
        var anchors = new X509Certificate2Collection(rootDotNet);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        // OCSP entry was skipped, caIssuers entry was used
        Assert.True(result);
        Assert.Equal(1, handler.CallCount(aiaUrl));
    }

    [Fact]
    public async Task AiaChasing_NonUriAccessLocation_IsSkipped()
    {
        // AIA with DirectoryName (not URI) should be skipped.
        const string aiaUrl = "https://example.com/aia-after-dirname.cer";
        var (caKeyPair, bcRootCert, intKeyPair, bcIntCert, bcLeafCert) =
            CreateThreeLevelPkiWithNonUriAia(aiaUrl);

        var handler = new MockHttpHandler();
        handler.SetResponse(aiaUrl, bcIntCert.GetEncoded());
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            ChainProblemStatus.NotTimeValid |
            ChainProblemStatus.NotSignatureValid |
            ChainProblemStatus.InvalidBasicConstraints,
            false,
            logger,
            downloadCache: null,
            httpClient: httpClient);

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeafCert.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRootCert.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
#endif
        var anchors = new X509Certificate2Collection(rootDotNet);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        // DirectoryName skipped, valid URI used
        Assert.True(result);
        Assert.Equal(1, handler.CallCount(aiaUrl));
    }

    [Fact]
    public async Task AiaChasing_EmptyUrl_IsSkipped()
    {
        // AIA with empty URL should be skipped, valid URL should work.
        const string aiaUrl = "https://example.com/aia-after-empty.cer";
        var (caKeyPair, bcRootCert, intKeyPair, bcIntCert, bcLeafCert) =
            CreateThreeLevelPkiWithEmptyAiaUrl(aiaUrl);

        var handler = new MockHttpHandler();
        handler.SetResponse(aiaUrl, bcIntCert.GetEncoded());
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            ChainProblemStatus.NotTimeValid |
            ChainProblemStatus.NotSignatureValid |
            ChainProblemStatus.InvalidBasicConstraints,
            false,
            logger,
            downloadCache: null,
            httpClient: httpClient);

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeafCert.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRootCert.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
#endif
        var anchors = new X509Certificate2Collection(rootDotNet);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        Assert.True(result);
        Assert.Equal(1, handler.CallCount(aiaUrl));
    }

    [Fact]
    public async Task AiaChasing_NoCacheOrHttpClient_NotAttempted()
    {
        // With no cache and no httpClient, AIA chasing should be skipped entirely.
        const string aiaUrl = "https://example.com/unreachable.cer";
        var (caKeyPair, bcRootCert, intKeyPair, bcIntCert, bcLeafCert) =
            CreateThreeLevelPkiWithAia(aiaUrl);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            ChainProblemStatus.NotTimeValid |
            ChainProblemStatus.NotSignatureValid |
            ChainProblemStatus.InvalidBasicConstraints,
            false,
            logger,
            downloadCache: null,
            httpClient: null);

        var untrustedEvents = new List<X509Certificate2>();
        validator.Untrusted += cert => untrustedEvents.Add(cert);

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeafCert.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRootCert.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
#endif
        var anchors = new X509Certificate2Collection(rootDotNet);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        // Chain can't be completed without AIA → untrusted
        Assert.False(result);
        Assert.Single(untrustedEvents);
    }

    [Fact]
    public async Task AiaChasing_MalformedAiaExtension_HandledGracefully()
    {
        // Malformed AIA extension → outer catch → returns null → chain incomplete
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();

        var leafKeyPairGenerator = new RsaKeyPairGenerator();
        leafKeyPairGenerator.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var leafKeyPair = leafKeyPairGenerator.GenerateKeyPair();

        // Create intermediate (we need the leaf to be signed by it, not the root)
        var intKeyPairGenerator = new RsaKeyPairGenerator();
        intKeyPairGenerator.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var intKeyPair = intKeyPairGenerator.GenerateKeyPair();

        var intCertGen = new X509V3CertificateGenerator();
        intCertGen.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
        intCertGen.SetIssuerDN(new X509Name("CN=Test Root CA"));
        intCertGen.SetSubjectDN(new X509Name("CN=Test Intermediate"));
        intCertGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        intCertGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        intCertGen.SetPublicKey(intKeyPair.Public);
        intCertGen.AddExtension(BcX509Extensions.BasicConstraints, true, new BasicConstraints(true));
        intCertGen.AddExtension(BcX509Extensions.SubjectKeyIdentifier, false,
            X509ExtensionUtilities.CreateSubjectKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(intKeyPair.Public)));
        intCertGen.AddExtension(BcX509Extensions.AuthorityKeyIdentifier, false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bcRootCert.GetPublicKey())));
        var bcIntCert = intCertGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));

        // Leaf with malformed AIA extension
        var leafCertGen = new X509V3CertificateGenerator();
        leafCertGen.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
        leafCertGen.SetIssuerDN(new X509Name("CN=Test Intermediate"));
        leafCertGen.SetSubjectDN(new X509Name("CN=Test Leaf Malformed AIA"));
        leafCertGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        leafCertGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        leafCertGen.SetPublicKey(leafKeyPair.Public);
        leafCertGen.AddExtension(BcX509Extensions.AuthorityKeyIdentifier, false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bcIntCert.GetPublicKey())));
        // Malformed AIA: raw garbage instead of proper ASN.1 structure
        leafCertGen.AddExtension(BcX509Extensions.AuthorityInfoAccess, false,
            new Org.BouncyCastle.Asn1.DerUtf8String("not-valid-aia"));
        var bcLeafCert = leafCertGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", intKeyPair.Private));

        var handler = new MockHttpHandler();
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            ChainProblemStatus.NotTimeValid |
            ChainProblemStatus.NotSignatureValid |
            ChainProblemStatus.InvalidBasicConstraints,
            false,
            logger,
            downloadCache: null,
            httpClient: httpClient);

        var untrustedEvents = new List<X509Certificate2>();
        validator.Untrusted += cert => untrustedEvents.Add(cert);

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeafCert.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRootCert.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
#endif
        var anchors = new X509Certificate2Collection(rootDotNet);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        // Malformed AIA → ChaseAiaAsync returns null → chain incomplete
        Assert.False(result);
        Assert.Single(untrustedEvents);
    }

    [Fact]
    public async Task AiaChasing_MultiHop_ChasesFullChain()
    {
        // Root → Intermediate1 → Intermediate2 → Leaf
        // Leaf AIA → Int2 URL, Int2 AIA → Int1 URL
        // Neither intermediate is provided; both must be AIA-chased.
        const string int1Url = "https://example.com/intermediate1.cer";
        const string int2Url = "https://example.com/intermediate2.cer";

        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();

        // Intermediate 1 (signed by root, has AIA to root - but root is the anchor so AIA won't be needed)
        var int1KeyPairGen = new RsaKeyPairGenerator();
        int1KeyPairGen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var int1KeyPair = int1KeyPairGen.GenerateKeyPair();

        var int1CertGen = new X509V3CertificateGenerator();
        int1CertGen.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
        int1CertGen.SetIssuerDN(new X509Name("CN=Test Root CA"));
        int1CertGen.SetSubjectDN(new X509Name("CN=Intermediate1"));
        int1CertGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        int1CertGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        int1CertGen.SetPublicKey(int1KeyPair.Public);
        int1CertGen.AddExtension(BcX509Extensions.BasicConstraints, true, new BasicConstraints(true));
        int1CertGen.AddExtension(BcX509Extensions.SubjectKeyIdentifier, false,
            X509ExtensionUtilities.CreateSubjectKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(int1KeyPair.Public)));
        int1CertGen.AddExtension(BcX509Extensions.AuthorityKeyIdentifier, false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bcRootCert.GetPublicKey())));
        var bcInt1Cert = int1CertGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));

        // Intermediate 2 (signed by Int1, AIA points to Int1)
        var int2KeyPairGen = new RsaKeyPairGenerator();
        int2KeyPairGen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var int2KeyPair = int2KeyPairGen.GenerateKeyPair();

        var int2CertGen = new X509V3CertificateGenerator();
        int2CertGen.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
        int2CertGen.SetIssuerDN(new X509Name("CN=Intermediate1"));
        int2CertGen.SetSubjectDN(new X509Name("CN=Intermediate2"));
        int2CertGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        int2CertGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        int2CertGen.SetPublicKey(int2KeyPair.Public);
        int2CertGen.AddExtension(BcX509Extensions.BasicConstraints, true, new BasicConstraints(true));
        int2CertGen.AddExtension(BcX509Extensions.SubjectKeyIdentifier, false,
            X509ExtensionUtilities.CreateSubjectKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(int2KeyPair.Public)));
        int2CertGen.AddExtension(BcX509Extensions.AuthorityKeyIdentifier, false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bcInt1Cert.GetPublicKey())));
        // AIA pointing to Int1
        int2CertGen.AddExtension(BcX509Extensions.AuthorityInfoAccess, false,
            new AuthorityInformationAccess(AccessDescription.IdADCAIssuers,
                new GeneralName(GeneralName.UniformResourceIdentifier, int1Url)));
        var bcInt2Cert = int2CertGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", int1KeyPair.Private));

        // Leaf (signed by Int2, AIA points to Int2)
        var leafKeyPairGen = new RsaKeyPairGenerator();
        leafKeyPairGen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var leafKeyPair = leafKeyPairGen.GenerateKeyPair();

        var leafCertGen = new X509V3CertificateGenerator();
        leafCertGen.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
        leafCertGen.SetIssuerDN(new X509Name("CN=Intermediate2"));
        leafCertGen.SetSubjectDN(new X509Name("CN=Leaf MultiHop"));
        leafCertGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        leafCertGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        leafCertGen.SetPublicKey(leafKeyPair.Public);
        leafCertGen.AddExtension(BcX509Extensions.AuthorityKeyIdentifier, false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bcInt2Cert.GetPublicKey())));
        leafCertGen.AddExtension(BcX509Extensions.AuthorityInfoAccess, false,
            new AuthorityInformationAccess(AccessDescription.IdADCAIssuers,
                new GeneralName(GeneralName.UniformResourceIdentifier, int2Url)));
        var bcLeafCert = leafCertGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", int2KeyPair.Private));

        var handler = new MockHttpHandler();
        handler.SetResponse(int1Url, bcInt1Cert.GetEncoded());
        handler.SetResponse(int2Url, bcInt2Cert.GetEncoded());
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            ChainProblemStatus.NotTimeValid |
            ChainProblemStatus.NotSignatureValid |
            ChainProblemStatus.InvalidBasicConstraints,
            false,
            logger,
            downloadCache: null,
            httpClient: httpClient);

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeafCert.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRootCert.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
#endif
        var anchors = new X509Certificate2Collection(rootDotNet);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        Assert.True(result);
        Assert.Equal(1, handler.CallCount(int1Url));
        Assert.Equal(1, handler.CallCount(int2Url));
    }

    [Fact]
    public async Task AiaChasing_IntermediateAvailableForCrlLookup()
    {
        // When an intermediate is AIA-chased, it should be added to the intermediates
        // list so it's available as the CRL issuer for signature verification.
        const string aiaUrl = "https://example.com/aia-crl-issuer.cer";
        const string crlUrl = "https://example.com/leaf-revocation.crl";
        var (caKeyPair, bcRootCert, intKeyPair, bcIntCert, bcLeafCert) =
            CreateThreeLevelPkiWithAiaAndCrl(aiaUrl, crlUrl);

        // CRL signed by the intermediate (not revoked)
        var crlGenerator = new X509V2CrlGenerator();
        crlGenerator.SetIssuerDN(new X509Name("CN=Test Intermediate"));
        crlGenerator.SetThisUpdate(DateTime.UtcNow);
        crlGenerator.SetNextUpdate(DateTime.UtcNow.AddHours(24));
        var crl = crlGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", intKeyPair.Private));

        var handler = new MockHttpHandler();
        handler.SetResponse(aiaUrl, bcIntCert.GetEncoded());
        handler.SetResponse(crlUrl, crl.GetEncoded());
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            true, // revocation checking ON
            logger,
            downloadCache: null,
            httpClient: httpClient);

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeafCert.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRootCert.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
#endif
        var anchors = new X509Certificate2Collection(rootDotNet);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null, // intermediate must be AIA-chased
            anchors);

        // Chain completed via AIA, CRL verified against AIA-fetched intermediate
        Assert.True(result);
        Assert.Equal(1, handler.CallCount(aiaUrl));
        Assert.Equal(1, handler.CallCount(crlUrl));
    }

    [Fact]
    public async Task ExpiredCrl_WithCache_EvictsStaleEntry()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());
        const string crlUrl = "https://example.com/expired-cached.crl";

        var bcLeafCert = CreateLeafCert(caKeyPair, bcRootCert, leafSerialNumber, crlUrl);

        // Expired CRL
        var crlGenerator = new X509V2CrlGenerator();
        crlGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        crlGenerator.SetThisUpdate(DateTime.UtcNow.AddHours(-48));
        crlGenerator.SetNextUpdate(DateTime.UtcNow.AddHours(-24));
        var crl = crlGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));

        var mockHandler = new MockHttpHandler();
        mockHandler.SetResponse(crlUrl, crl.GetEncoded());
        var httpClient = new HttpClient(mockHandler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        services.AddFusionCache(CertificateDownloadCache.CacheName);
        var sp = services.BuildServiceProvider();

        var cacheProvider = sp.GetRequiredService<IFusionCacheProvider>();
        var cacheLogger = sp.GetRequiredService<ILogger<CertificateDownloadCache>>();
        var downloadCache = new CertificateDownloadCache(cacheProvider, httpClient, cacheLogger);

        var validatorLogger = sp.GetRequiredService<ILogger<TrustChainValidator>>();
        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            true,
            validatorLogger,
            downloadCache: downloadCache);

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeafCert.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRootCert.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
#endif
        var anchors = new X509Certificate2Collection(rootDotNet);

        // First call: downloads and caches the expired CRL, then evicts it
        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        Assert.False(result);

        // Second call should re-download because the stale entry was evicted
        var result2 = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        Assert.False(result2);
        // The CRL was downloaded twice (evicted after first call)
        Assert.Equal(2, mockHandler.CallCount(crlUrl));
    }

    [Fact]
    public async Task IsTrustedCertificateAsync_WithAnchors_SetsCommunityId()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());
        var bcLeafCert = CreateLeafCertWithoutCrlDp(caKeyPair, bcRootCert, leafSerialNumber);

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeafCert.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRootCert.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
#endif
        var anchorCertificates = new X509Certificate2Collection(rootDotNet);

        var expectedCommunityId = 42L;
        var anchors = new List<Anchor>
        {
            new Anchor(rootDotNet, "test-community")
            {
                CommunityId = expectedCommunityId
            }
        };

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            false,
            logger);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchorCertificates,
            anchors);

        Assert.True(result.IsValid);
        Assert.Equal(expectedCommunityId, result.CommunityId);
    }

    [Fact]
    public async Task NotifyUntrusted_EventHandlerThrows_ExceptionSwallowed()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());
        var bcLeafCert = CreateLeafCertWithoutCrlDp(caKeyPair, bcRootCert, leafSerialNumber);

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeafCert.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
#endif
        // Use a different root so the chain is untrusted → triggers NotifyUntrusted
        var (_, differentRoot) = CreateCaKeyPairAndRoot();
#if NET9_0_OR_GREATER
        var differentRootDotNet = X509CertificateLoader.LoadCertificate(differentRoot.GetEncoded());
#else
        var differentRootDotNet = new X509Certificate2(differentRoot.GetEncoded());
#endif
        var anchorCerts = new X509Certificate2Collection(differentRootDotNet);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();

        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            false,
            sp.GetRequiredService<ILogger<TrustChainValidator>>());

        // Subscribe an event handler that throws
        validator.Untrusted += _ => throw new InvalidOperationException("Handler blew up");

        // Should not throw despite the event handler throwing
        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchorCerts);

        Assert.False(result);
    }

    [Fact]
    public async Task NotifyProblem_EventHandlerThrows_ExceptionSwallowed()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());

        // Create an expired leaf cert to trigger NotifyProblem via NotTimeValid
        var leafKeyPairGenerator = new RsaKeyPairGenerator();
        leafKeyPairGenerator.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var leafKeyPair = leafKeyPairGenerator.GenerateKeyPair();

        var leafCertGenerator = new X509V3CertificateGenerator();
        leafCertGenerator.SetSerialNumber(leafSerialNumber);
        leafCertGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        leafCertGenerator.SetSubjectDN(new X509Name("CN=Test Expired Leaf"));
        leafCertGenerator.SetNotBefore(DateTime.UtcNow.AddYears(-2));
        leafCertGenerator.SetNotAfter(DateTime.UtcNow.AddYears(-1)); // expired
        leafCertGenerator.SetPublicKey(leafKeyPair.Public);
        leafCertGenerator.AddExtension(BcX509Extensions.AuthorityKeyIdentifier, false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bcRootCert.GetPublicKey())));
        var bcExpiredLeaf = leafCertGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcExpiredLeaf.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRootCert.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcExpiredLeaf.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
#endif
        var anchorCerts = new X509Certificate2Collection(rootDotNet);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();

        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            false,
            sp.GetRequiredService<ILogger<TrustChainValidator>>());

        // Subscribe an event handler that throws
        validator.Problem += _ => throw new InvalidOperationException("Handler blew up");

        // Should not throw despite the event handler throwing
        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchorCerts);

        Assert.False(result);
    }

    [Fact]
    public async Task NotifyError_EventHandlerThrows_ExceptionSwallowed()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());
        const string crlUrl = "https://example.com/error-handler-throw.crl";
        var bcLeafCert = CreateLeafCert(caKeyPair, bcRootCert, leafSerialNumber, crlUrl);

        var crlGenerator = new X509V2CrlGenerator();
        crlGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        crlGenerator.SetThisUpdate(DateTime.UtcNow);
        crlGenerator.SetNextUpdate(DateTime.UtcNow.AddHours(24));
        var crl = crlGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));

        var handler = new MockHttpHandler();
        handler.SetResponse(crlUrl, crl.GetEncoded());
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();

        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            true,
            sp.GetRequiredService<ILogger<TrustChainValidator>>(),
            downloadCache: null,
            httpClient: httpClient);

        // Subscribe an Error handler that throws — covers the catch block in NotifyError
        validator.Error += (_, _) => throw new InvalidOperationException("Error handler blew up");

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeafCert.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRootCert.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
#endif
        var anchorCerts = new X509Certificate2Collection(rootDotNet);

        // Use faulty anchors to trigger the outer catch → NotifyError
        var faultyAnchors = Substitute.For<IEnumerable<Anchor>>();
        faultyAnchors.GetEnumerator().Returns(
            _ => throw new InvalidOperationException("Simulated anchor store failure"));

        // Should not throw despite the Error event handler throwing
        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchorCerts,
            anchors: faultyAnchors);

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task BuildChainAsync_LoopDetected_BreaksChain()
    {
        // Create two certs that sign each other (loop scenario):
        // Cert A has IssuerDN = "CN=B", SubjectDN = "CN=A", signed by B's key
        // Cert B has IssuerDN = "CN=A", SubjectDN = "CN=B", signed by A's key
        // Neither is self-signed, neither is an anchor → loop detection kicks in

        var keyGenA = new RsaKeyPairGenerator();
        keyGenA.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var keyPairA = keyGenA.GenerateKeyPair();

        var keyGenB = new RsaKeyPairGenerator();
        keyGenB.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var keyPairB = keyGenB.GenerateKeyPair();

        // Cert A: Subject=A, Issuer=B, signed by B
        var certGenA = new X509V3CertificateGenerator();
        certGenA.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
        certGenA.SetSubjectDN(new X509Name("CN=Cert A"));
        certGenA.SetIssuerDN(new X509Name("CN=Cert B"));
        certGenA.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        certGenA.SetNotAfter(DateTime.UtcNow.AddYears(1));
        certGenA.SetPublicKey(keyPairA.Public);
        var bcCertA = certGenA.Generate(new Asn1SignatureFactory("SHA256WithRSA", keyPairB.Private));

        // Cert B: Subject=B, Issuer=A, signed by A
        var certGenB = new X509V3CertificateGenerator();
        certGenB.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
        certGenB.SetSubjectDN(new X509Name("CN=Cert B"));
        certGenB.SetIssuerDN(new X509Name("CN=Cert A"));
        certGenB.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        certGenB.SetNotAfter(DateTime.UtcNow.AddYears(1));
        certGenB.SetPublicKey(keyPairB.Public);
        certGenB.AddExtension(BcX509Extensions.BasicConstraints, true, new BasicConstraints(true));
        var bcCertB = certGenB.Generate(new Asn1SignatureFactory("SHA256WithRSA", keyPairA.Private));

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcCertA.GetEncoded());
        var intermediateDotNet = X509CertificateLoader.LoadCertificate(bcCertB.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcCertA.GetEncoded());
        var intermediateDotNet = new X509Certificate2(bcCertB.GetEncoded());
#endif

        // Use an unrelated anchor so the chain won't terminate at a trust anchor
        var (_, unrelatedRoot) = CreateCaKeyPairAndRoot();
#if NET9_0_OR_GREATER
        var anchorCerts = new X509Certificate2Collection(X509CertificateLoader.LoadCertificate(unrelatedRoot.GetEncoded()));
#else
        var anchorCerts = new X509Certificate2Collection(new X509Certificate2(unrelatedRoot.GetEncoded()));
#endif

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();

        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            false,
            sp.GetRequiredService<ILogger<TrustChainValidator>>());

        var untrustedEvents = new List<X509Certificate2>();
        validator.Untrusted += cert => untrustedEvents.Add(cert);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            new X509Certificate2Collection(intermediateDotNet),
            anchorCerts);

        Assert.False(result);
        Assert.NotEmpty(untrustedEvents);
    }

    [Fact]
    public async Task FindIssuer_DnMatchButSignatureFails_SkipsCandidate()
    {
        // Create a leaf signed by CA-A, but provide CA-B (same DN as CA-A but different key)
        // as the only anchor. FindIssuer should fail signature check and skip CA-B.
        var (caKeyPairA, _) = CreateCaKeyPairAndRoot();

        // Create CA-B with same DN but different key
        var keyGenB = new RsaKeyPairGenerator();
        keyGenB.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var caKeyPairB = keyGenB.GenerateKeyPair();

        var certGenB = new X509V3CertificateGenerator();
        certGenB.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
        certGenB.SetIssuerDN(new X509Name("CN=Test Root CA")); // same DN
        certGenB.SetSubjectDN(new X509Name("CN=Test Root CA")); // same DN
        certGenB.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        certGenB.SetNotAfter(DateTime.UtcNow.AddYears(1));
        certGenB.SetPublicKey(caKeyPairB.Public);
        certGenB.AddExtension(BcX509Extensions.BasicConstraints, true, new BasicConstraints(true));
        // No AKI/SKI so MatchesKeyIdentifiers returns true, forcing signature check
        var bcRootB = certGenB.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPairB.Private));

        // Leaf signed by CA-A
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());
        var leafKeyGen = new RsaKeyPairGenerator();
        leafKeyGen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var leafKeyPair = leafKeyGen.GenerateKeyPair();

        var leafCertGen = new X509V3CertificateGenerator();
        leafCertGen.SetSerialNumber(leafSerialNumber);
        leafCertGen.SetIssuerDN(new X509Name("CN=Test Root CA"));
        leafCertGen.SetSubjectDN(new X509Name("CN=Test Leaf Sig Mismatch"));
        leafCertGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        leafCertGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        leafCertGen.SetPublicKey(leafKeyPair.Public);
        var bcLeaf = leafCertGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPairA.Private));

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeaf.GetEncoded());
        var rootBDotNet = X509CertificateLoader.LoadCertificate(bcRootB.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeaf.GetEncoded());
        var rootBDotNet = new X509Certificate2(bcRootB.GetEncoded());
#endif
        var anchorCerts = new X509Certificate2Collection(rootBDotNet);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();

        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            false,
            sp.GetRequiredService<ILogger<TrustChainValidator>>());

        var untrustedEvents = new List<X509Certificate2>();
        validator.Untrusted += cert => untrustedEvents.Add(cert);

        // Should be untrusted: DN matches but signature doesn't verify
        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchorCerts);

        Assert.False(result);
        Assert.NotEmpty(untrustedEvents);
    }

    [Fact]
    public async Task MatchesKeyIdentifiers_MissingExtensions_AllowsDnMatch()
    {
        // Create a CA and leaf where neither has AKI/SKI extensions.
        // MatchesKeyIdentifiers should return true, falling through to signature check.
        var keyGen = new RsaKeyPairGenerator();
        keyGen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var caKeyPair = keyGen.GenerateKeyPair();

        // Root without SKI
        var rootGen = new X509V3CertificateGenerator();
        rootGen.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
        rootGen.SetIssuerDN(new X509Name("CN=NoSKI Root"));
        rootGen.SetSubjectDN(new X509Name("CN=NoSKI Root"));
        rootGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        rootGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        rootGen.SetPublicKey(caKeyPair.Public);
        rootGen.AddExtension(BcX509Extensions.BasicConstraints, true, new BasicConstraints(true));
        // Intentionally no SubjectKeyIdentifier
        var bcRoot = rootGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));

        // Leaf without AKI
        var leafKeyGen = new RsaKeyPairGenerator();
        leafKeyGen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var leafKeyPair = leafKeyGen.GenerateKeyPair();

        var leafGen = new X509V3CertificateGenerator();
        leafGen.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
        leafGen.SetIssuerDN(new X509Name("CN=NoSKI Root"));
        leafGen.SetSubjectDN(new X509Name("CN=NoAKI Leaf"));
        leafGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        leafGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        leafGen.SetPublicKey(leafKeyPair.Public);
        // Intentionally no AuthorityKeyIdentifier
        var bcLeaf = leafGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeaf.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRoot.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeaf.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRoot.GetEncoded());
#endif
        var anchorCerts = new X509Certificate2Collection(rootDotNet);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();

        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            false,
            sp.GetRequiredService<ILogger<TrustChainValidator>>());

        // Should be valid because MatchesKeyIdentifiers returns true (missing extensions)
        // and the signature verifies correctly
        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchorCerts);

        Assert.True(result);
    }

    [Fact]
    public async Task BuildChainAsync_SelfSignedVerificationFails_ContinuesChainBuilding()
    {
        // Create a cert where Subject DN == Issuer DN but it's NOT actually self-signed
        // (signed by a different key). This triggers the self-signed verification failure
        // catch block in BuildChainAsync, then chain building continues to look for issuer.

        var keyGenReal = new RsaKeyPairGenerator();
        keyGenReal.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var realCaKeyPair = keyGenReal.GenerateKeyPair();

        // Create the "root" that will be the actual anchor
        var rootGen = new X509V3CertificateGenerator();
        rootGen.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
        rootGen.SetIssuerDN(new X509Name("CN=Shared DN"));
        rootGen.SetSubjectDN(new X509Name("CN=Shared DN"));
        rootGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        rootGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        rootGen.SetPublicKey(realCaKeyPair.Public);
        rootGen.AddExtension(BcX509Extensions.BasicConstraints, true, new BasicConstraints(true));
        rootGen.AddExtension(BcX509Extensions.SubjectKeyIdentifier, false,
            X509ExtensionUtilities.CreateSubjectKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(realCaKeyPair.Public)));
        var bcRoot = rootGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", realCaKeyPair.Private));

        // Create an intermediate with SubjectDN == IssuerDN == "CN=Shared DN" but signed
        // by the real CA, so self-verify will fail. It also has a different key.
        var keyGenFake = new RsaKeyPairGenerator();
        keyGenFake.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var fakeKeyPair = keyGenFake.GenerateKeyPair();

        var intermediateGen = new X509V3CertificateGenerator();
        intermediateGen.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
        intermediateGen.SetIssuerDN(new X509Name("CN=Shared DN"));
        intermediateGen.SetSubjectDN(new X509Name("CN=Shared DN")); // same as issuer!
        intermediateGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        intermediateGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        intermediateGen.SetPublicKey(fakeKeyPair.Public); // different key
        intermediateGen.AddExtension(BcX509Extensions.BasicConstraints, true, new BasicConstraints(true));
        intermediateGen.AddExtension(BcX509Extensions.AuthorityKeyIdentifier, false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bcRoot.GetPublicKey())));
        intermediateGen.AddExtension(BcX509Extensions.SubjectKeyIdentifier, false,
            X509ExtensionUtilities.CreateSubjectKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(fakeKeyPair.Public)));
        var bcIntermediate = intermediateGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", realCaKeyPair.Private));

        // Create leaf signed by the intermediate
        var leafKeyGen = new RsaKeyPairGenerator();
        leafKeyGen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var leafKeyPair = leafKeyGen.GenerateKeyPair();

        var leafGen = new X509V3CertificateGenerator();
        leafGen.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
        leafGen.SetIssuerDN(new X509Name("CN=Shared DN"));
        leafGen.SetSubjectDN(new X509Name("CN=Leaf Under Fake Self-Signed"));
        leafGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        leafGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        leafGen.SetPublicKey(leafKeyPair.Public);
        leafGen.AddExtension(BcX509Extensions.AuthorityKeyIdentifier, false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bcIntermediate.GetPublicKey())));
        var bcLeaf = leafGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", fakeKeyPair.Private));

#if NET9_0_OR_GREATER
        var leafDotNet = X509CertificateLoader.LoadCertificate(bcLeaf.GetEncoded());
        var intermediateDotNet = X509CertificateLoader.LoadCertificate(bcIntermediate.GetEncoded());
        var rootDotNet = X509CertificateLoader.LoadCertificate(bcRoot.GetEncoded());
#else
        var leafDotNet = new X509Certificate2(bcLeaf.GetEncoded());
        var intermediateDotNet = new X509Certificate2(bcIntermediate.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRoot.GetEncoded());
#endif
        var anchorCerts = new X509Certificate2Collection(rootDotNet);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();

        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            false,
            sp.GetRequiredService<ILogger<TrustChainValidator>>());

        // The intermediate has Subject==Issuer but self-verify fails,
        // so BuildChainAsync should continue and find the real root anchor
        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            new X509Certificate2Collection(intermediateDotNet),
            anchorCerts);

        Assert.True(result);
    }

    #region Test Helpers

    private static (Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair caKeyPair, Org.BouncyCastle.X509.X509Certificate bcRootCert) CreateCaKeyPairAndRoot()
    {
        var caKeyPairGenerator = new RsaKeyPairGenerator();
        caKeyPairGenerator.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var caKeyPair = caKeyPairGenerator.GenerateKeyPair();

        var caCertGenerator = new X509V3CertificateGenerator();
        caCertGenerator.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
        caCertGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        caCertGenerator.SetSubjectDN(new X509Name("CN=Test Root CA"));
        caCertGenerator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        caCertGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));
        caCertGenerator.SetPublicKey(caKeyPair.Public);
        caCertGenerator.AddExtension(BcX509Extensions.BasicConstraints, true, new BasicConstraints(true));
        caCertGenerator.AddExtension(BcX509Extensions.SubjectKeyIdentifier, false,
            X509ExtensionUtilities.CreateSubjectKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(caKeyPair.Public)));

        var bcRootCert = caCertGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));
        return (caKeyPair, bcRootCert);
    }

    private static Org.BouncyCastle.X509.X509Certificate CreateLeafCert(
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair caKeyPair,
        Org.BouncyCastle.X509.X509Certificate bcRootCert,
        BigInteger serialNumber,
        string crlUrl)
    {
        var leafKeyPairGenerator = new RsaKeyPairGenerator();
        leafKeyPairGenerator.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var leafKeyPair = leafKeyPairGenerator.GenerateKeyPair();

        var leafCertGenerator = new X509V3CertificateGenerator();
        leafCertGenerator.SetSerialNumber(serialNumber);
        leafCertGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        leafCertGenerator.SetSubjectDN(new X509Name("CN=Test Leaf"));
        leafCertGenerator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        leafCertGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));
        leafCertGenerator.SetPublicKey(leafKeyPair.Public);

        var crlDp = new DistributionPoint(
            new DistributionPointName(
                DistributionPointName.FullName,
                new GeneralNames(new GeneralName(GeneralName.UniformResourceIdentifier, crlUrl))),
            null, null);
        leafCertGenerator.AddExtension(BcX509Extensions.CrlDistributionPoints, false,
            new CrlDistPoint(new[] { crlDp }));
        leafCertGenerator.AddExtension(BcX509Extensions.AuthorityKeyIdentifier, false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bcRootCert.GetPublicKey())));

        return leafCertGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));
    }

    private static Org.BouncyCastle.X509.X509Certificate CreateLeafCertWithMultipleCdps(
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair caKeyPair,
        Org.BouncyCastle.X509.X509Certificate bcRootCert,
        BigInteger serialNumber,
        string validCrlUrl)
    {
        var leafKeyPairGenerator = new RsaKeyPairGenerator();
        leafKeyPairGenerator.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var leafKeyPair = leafKeyPairGenerator.GenerateKeyPair();

        var leafCertGenerator = new X509V3CertificateGenerator();
        leafCertGenerator.SetSerialNumber(serialNumber);
        leafCertGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        leafCertGenerator.SetSubjectDN(new X509Name("CN=Test Leaf Multi CDP"));
        leafCertGenerator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        leafCertGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));
        leafCertGenerator.SetPublicKey(leafKeyPair.Public);

        // First DP: NameRelativeToCRLIssuer (not FullName → line 589 continue)
        var relativeDp = new DistributionPoint(
            new DistributionPointName(
                DistributionPointName.NameRelativeToCrlIssuer,
                new X509Name("CN=CRL Issuer")),
            null, null);

        // Second DP: valid FullName URI
        var validDp = new DistributionPoint(
            new DistributionPointName(
                DistributionPointName.FullName,
                new GeneralNames(new GeneralName(GeneralName.UniformResourceIdentifier, validCrlUrl))),
            null, null);

        leafCertGenerator.AddExtension(BcX509Extensions.CrlDistributionPoints, false,
            new CrlDistPoint(new[] { relativeDp, validDp }));
        leafCertGenerator.AddExtension(BcX509Extensions.AuthorityKeyIdentifier, false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bcRootCert.GetPublicKey())));

        return leafCertGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));
    }

    private static Org.BouncyCastle.X509.X509Certificate CreateLeafCertWithNonUriGeneralName(
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair caKeyPair,
        Org.BouncyCastle.X509.X509Certificate bcRootCert,
        BigInteger serialNumber,
        string validCrlUrl)
    {
        var leafKeyPairGenerator = new RsaKeyPairGenerator();
        leafKeyPairGenerator.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var leafKeyPair = leafKeyPairGenerator.GenerateKeyPair();

        var leafCertGenerator = new X509V3CertificateGenerator();
        leafCertGenerator.SetSerialNumber(serialNumber);
        leafCertGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        leafCertGenerator.SetSubjectDN(new X509Name("CN=Test Leaf NonURI"));
        leafCertGenerator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        leafCertGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));
        leafCertGenerator.SetPublicKey(leafKeyPair.Public);

        // Single DP with two general names: first is DirectoryName (not URI → line 597 continue),
        // second is a valid URI
        var dp = new DistributionPoint(
            new DistributionPointName(
                DistributionPointName.FullName,
                new GeneralNames(new[]
                {
                    new GeneralName(GeneralName.DirectoryName, new X509Name("CN=Not A URI")),
                    new GeneralName(GeneralName.UniformResourceIdentifier, validCrlUrl)
                })),
            null, null);

        leafCertGenerator.AddExtension(BcX509Extensions.CrlDistributionPoints, false,
            new CrlDistPoint(new[] { dp }));
        leafCertGenerator.AddExtension(BcX509Extensions.AuthorityKeyIdentifier, false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bcRootCert.GetPublicKey())));

        return leafCertGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));
    }

    private static Org.BouncyCastle.X509.X509Certificate CreateLeafCertWithEmptyUri(
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair caKeyPair,
        Org.BouncyCastle.X509.X509Certificate bcRootCert,
        BigInteger serialNumber,
        string validCrlUrl)
    {
        var leafKeyPairGenerator = new RsaKeyPairGenerator();
        leafKeyPairGenerator.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var leafKeyPair = leafKeyPairGenerator.GenerateKeyPair();

        var leafCertGenerator = new X509V3CertificateGenerator();
        leafCertGenerator.SetSerialNumber(serialNumber);
        leafCertGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        leafCertGenerator.SetSubjectDN(new X509Name("CN=Test Leaf EmptyURI"));
        leafCertGenerator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        leafCertGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));
        leafCertGenerator.SetPublicKey(leafKeyPair.Public);

        // Single DP with two URI general names: first is empty (line 603 continue), second is valid
        var dp = new DistributionPoint(
            new DistributionPointName(
                DistributionPointName.FullName,
                new GeneralNames(new[]
                {
                    new GeneralName(GeneralName.UniformResourceIdentifier, ""),
                    new GeneralName(GeneralName.UniformResourceIdentifier, validCrlUrl)
                })),
            null, null);

        leafCertGenerator.AddExtension(BcX509Extensions.CrlDistributionPoints, false,
            new CrlDistPoint(new[] { dp }));
        leafCertGenerator.AddExtension(BcX509Extensions.AuthorityKeyIdentifier, false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bcRootCert.GetPublicKey())));

        return leafCertGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));
    }

    private static Org.BouncyCastle.X509.X509Certificate CreateLeafCertWithUnsupportedScheme(
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair caKeyPair,
        Org.BouncyCastle.X509.X509Certificate bcRootCert,
        BigInteger serialNumber,
        string validCrlUrl)
    {
        var leafKeyPairGenerator = new RsaKeyPairGenerator();
        leafKeyPairGenerator.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var leafKeyPair = leafKeyPairGenerator.GenerateKeyPair();

        var leafCertGenerator = new X509V3CertificateGenerator();
        leafCertGenerator.SetSerialNumber(serialNumber);
        leafCertGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        leafCertGenerator.SetSubjectDN(new X509Name("CN=Test Leaf LDAP CDP"));
        leafCertGenerator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        leafCertGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));
        leafCertGenerator.SetPublicKey(leafKeyPair.Public);

        // Single DP with two URIs: first is ldap:// (unsupported scheme), second is valid https://
        var dp = new DistributionPoint(
            new DistributionPointName(
                DistributionPointName.FullName,
                new GeneralNames(new[]
                {
                    new GeneralName(GeneralName.UniformResourceIdentifier, "ldap://example.com/cn=CRL"),
                    new GeneralName(GeneralName.UniformResourceIdentifier, validCrlUrl)
                })),
            null, null);

        leafCertGenerator.AddExtension(BcX509Extensions.CrlDistributionPoints, false,
            new CrlDistPoint(new[] { dp }));
        leafCertGenerator.AddExtension(BcX509Extensions.AuthorityKeyIdentifier, false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bcRootCert.GetPublicKey())));

        return leafCertGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));
    }

    private static Org.BouncyCastle.X509.X509Certificate CreateLeafCertWithoutCrlDp(
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair caKeyPair,
        Org.BouncyCastle.X509.X509Certificate bcRootCert,
        BigInteger serialNumber)
    {
        var leafKeyPairGenerator = new RsaKeyPairGenerator();
        leafKeyPairGenerator.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var leafKeyPair = leafKeyPairGenerator.GenerateKeyPair();

        var leafCertGenerator = new X509V3CertificateGenerator();
        leafCertGenerator.SetSerialNumber(serialNumber);
        leafCertGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        leafCertGenerator.SetSubjectDN(new X509Name("CN=Test Leaf No CDP"));
        leafCertGenerator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        leafCertGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));
        leafCertGenerator.SetPublicKey(leafKeyPair.Public);
        leafCertGenerator.AddExtension(BcX509Extensions.AuthorityKeyIdentifier, false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bcRootCert.GetPublicKey())));

        return leafCertGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));
    }

    /// <summary>
    /// Creates a 3-level PKI: Root → Intermediate → Leaf.
    /// The leaf has an AIA extension pointing to the given URL (or none if null).
    /// No CRL distribution point on the leaf.
    /// </summary>
    private static (
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair caKeyPair,
        Org.BouncyCastle.X509.X509Certificate bcRootCert,
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair intKeyPair,
        Org.BouncyCastle.X509.X509Certificate bcIntCert,
        Org.BouncyCastle.X509.X509Certificate bcLeafCert)
        CreateThreeLevelPkiWithAia(string? aiaUrl)
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();

        var intKeyPairGen = new RsaKeyPairGenerator();
        intKeyPairGen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var intKeyPair = intKeyPairGen.GenerateKeyPair();

        var intCertGen = new X509V3CertificateGenerator();
        intCertGen.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
        intCertGen.SetIssuerDN(new X509Name("CN=Test Root CA"));
        intCertGen.SetSubjectDN(new X509Name("CN=Test Intermediate"));
        intCertGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        intCertGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        intCertGen.SetPublicKey(intKeyPair.Public);
        intCertGen.AddExtension(BcX509Extensions.BasicConstraints, true, new BasicConstraints(true));
        intCertGen.AddExtension(BcX509Extensions.SubjectKeyIdentifier, false,
            X509ExtensionUtilities.CreateSubjectKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(intKeyPair.Public)));
        intCertGen.AddExtension(BcX509Extensions.AuthorityKeyIdentifier, false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bcRootCert.GetPublicKey())));
        var bcIntCert = intCertGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));

        var leafKeyPairGen = new RsaKeyPairGenerator();
        leafKeyPairGen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var leafKeyPair = leafKeyPairGen.GenerateKeyPair();

        var leafCertGen = new X509V3CertificateGenerator();
        leafCertGen.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
        leafCertGen.SetIssuerDN(new X509Name("CN=Test Intermediate"));
        leafCertGen.SetSubjectDN(new X509Name("CN=Test Leaf AIA"));
        leafCertGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        leafCertGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        leafCertGen.SetPublicKey(leafKeyPair.Public);
        leafCertGen.AddExtension(BcX509Extensions.AuthorityKeyIdentifier, false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bcIntCert.GetPublicKey())));
        if (aiaUrl != null)
        {
            leafCertGen.AddExtension(BcX509Extensions.AuthorityInfoAccess, false,
                new AuthorityInformationAccess(AccessDescription.IdADCAIssuers,
                    new GeneralName(GeneralName.UniformResourceIdentifier, aiaUrl)));
        }
        var bcLeafCert = leafCertGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", intKeyPair.Private));

        return (caKeyPair, bcRootCert, intKeyPair, bcIntCert, bcLeafCert);
    }

    /// <summary>
    /// Creates a 3-level PKI where the leaf has AIA with both caIssuers and a CRL DP.
    /// </summary>
    private static (
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair caKeyPair,
        Org.BouncyCastle.X509.X509Certificate bcRootCert,
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair intKeyPair,
        Org.BouncyCastle.X509.X509Certificate bcIntCert,
        Org.BouncyCastle.X509.X509Certificate bcLeafCert)
        CreateThreeLevelPkiWithAiaAndCrl(string aiaUrl, string crlUrl)
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();

        var intKeyPairGen = new RsaKeyPairGenerator();
        intKeyPairGen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var intKeyPair = intKeyPairGen.GenerateKeyPair();

        var intCertGen = new X509V3CertificateGenerator();
        intCertGen.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
        intCertGen.SetIssuerDN(new X509Name("CN=Test Root CA"));
        intCertGen.SetSubjectDN(new X509Name("CN=Test Intermediate"));
        intCertGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        intCertGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        intCertGen.SetPublicKey(intKeyPair.Public);
        intCertGen.AddExtension(BcX509Extensions.BasicConstraints, true, new BasicConstraints(true));
        intCertGen.AddExtension(BcX509Extensions.SubjectKeyIdentifier, false,
            X509ExtensionUtilities.CreateSubjectKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(intKeyPair.Public)));
        intCertGen.AddExtension(BcX509Extensions.AuthorityKeyIdentifier, false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bcRootCert.GetPublicKey())));
        var bcIntCert = intCertGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));

        var leafKeyPairGen = new RsaKeyPairGenerator();
        leafKeyPairGen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var leafKeyPair = leafKeyPairGen.GenerateKeyPair();

        var leafCertGen = new X509V3CertificateGenerator();
        leafCertGen.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
        leafCertGen.SetIssuerDN(new X509Name("CN=Test Intermediate"));
        leafCertGen.SetSubjectDN(new X509Name("CN=Test Leaf AIA CRL"));
        leafCertGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        leafCertGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        leafCertGen.SetPublicKey(leafKeyPair.Public);
        leafCertGen.AddExtension(BcX509Extensions.AuthorityKeyIdentifier, false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bcIntCert.GetPublicKey())));
        leafCertGen.AddExtension(BcX509Extensions.AuthorityInfoAccess, false,
            new AuthorityInformationAccess(AccessDescription.IdADCAIssuers,
                new GeneralName(GeneralName.UniformResourceIdentifier, aiaUrl)));
        var crlDp = new DistributionPoint(
            new DistributionPointName(
                DistributionPointName.FullName,
                new GeneralNames(new GeneralName(GeneralName.UniformResourceIdentifier, crlUrl))),
            null, null);
        leafCertGen.AddExtension(BcX509Extensions.CrlDistributionPoints, false,
            new CrlDistPoint(new[] { crlDp }));
        var bcLeafCert = leafCertGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", intKeyPair.Private));

        return (caKeyPair, bcRootCert, intKeyPair, bcIntCert, bcLeafCert);
    }

    /// <summary>
    /// Creates a 3-level PKI where the leaf has an AIA with an OCSP entry first (non-caIssuers),
    /// followed by a valid caIssuers entry.
    /// </summary>
    private static (
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair caKeyPair,
        Org.BouncyCastle.X509.X509Certificate bcRootCert,
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair intKeyPair,
        Org.BouncyCastle.X509.X509Certificate bcIntCert,
        Org.BouncyCastle.X509.X509Certificate bcLeafCert)
        CreateThreeLevelPkiWithMixedAia(string validAiaUrl)
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();

        var intKeyPairGen = new RsaKeyPairGenerator();
        intKeyPairGen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var intKeyPair = intKeyPairGen.GenerateKeyPair();

        var intCertGen = new X509V3CertificateGenerator();
        intCertGen.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
        intCertGen.SetIssuerDN(new X509Name("CN=Test Root CA"));
        intCertGen.SetSubjectDN(new X509Name("CN=Test Intermediate"));
        intCertGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        intCertGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        intCertGen.SetPublicKey(intKeyPair.Public);
        intCertGen.AddExtension(BcX509Extensions.BasicConstraints, true, new BasicConstraints(true));
        intCertGen.AddExtension(BcX509Extensions.SubjectKeyIdentifier, false,
            X509ExtensionUtilities.CreateSubjectKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(intKeyPair.Public)));
        intCertGen.AddExtension(BcX509Extensions.AuthorityKeyIdentifier, false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bcRootCert.GetPublicKey())));
        var bcIntCert = intCertGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));

        var leafKeyPairGen = new RsaKeyPairGenerator();
        leafKeyPairGen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var leafKeyPair = leafKeyPairGen.GenerateKeyPair();

        var leafCertGen = new X509V3CertificateGenerator();
        leafCertGen.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
        leafCertGen.SetIssuerDN(new X509Name("CN=Test Intermediate"));
        leafCertGen.SetSubjectDN(new X509Name("CN=Test Leaf MixedAIA"));
        leafCertGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        leafCertGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        leafCertGen.SetPublicKey(leafKeyPair.Public);
        leafCertGen.AddExtension(BcX509Extensions.AuthorityKeyIdentifier, false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bcIntCert.GetPublicKey())));
        // Two AIA entries: OCSP (skipped) + caIssuers (used)
        var aiaEntries = new[]
        {
            new AccessDescription(AccessDescription.IdADOcsp,
                new GeneralName(GeneralName.UniformResourceIdentifier, "https://ocsp.example.com")),
            new AccessDescription(AccessDescription.IdADCAIssuers,
                new GeneralName(GeneralName.UniformResourceIdentifier, validAiaUrl))
        };
        leafCertGen.AddExtension(BcX509Extensions.AuthorityInfoAccess, false,
            new AuthorityInformationAccess(aiaEntries));
        var bcLeafCert = leafCertGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", intKeyPair.Private));

        return (caKeyPair, bcRootCert, intKeyPair, bcIntCert, bcLeafCert);
    }

    /// <summary>
    /// Creates a 3-level PKI where the leaf has an AIA with a DirectoryName (non-URI) first,
    /// followed by a valid URI.
    /// </summary>
    private static (
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair caKeyPair,
        Org.BouncyCastle.X509.X509Certificate bcRootCert,
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair intKeyPair,
        Org.BouncyCastle.X509.X509Certificate bcIntCert,
        Org.BouncyCastle.X509.X509Certificate bcLeafCert)
        CreateThreeLevelPkiWithNonUriAia(string validAiaUrl)
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();

        var intKeyPairGen = new RsaKeyPairGenerator();
        intKeyPairGen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var intKeyPair = intKeyPairGen.GenerateKeyPair();

        var intCertGen = new X509V3CertificateGenerator();
        intCertGen.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
        intCertGen.SetIssuerDN(new X509Name("CN=Test Root CA"));
        intCertGen.SetSubjectDN(new X509Name("CN=Test Intermediate"));
        intCertGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        intCertGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        intCertGen.SetPublicKey(intKeyPair.Public);
        intCertGen.AddExtension(BcX509Extensions.BasicConstraints, true, new BasicConstraints(true));
        intCertGen.AddExtension(BcX509Extensions.SubjectKeyIdentifier, false,
            X509ExtensionUtilities.CreateSubjectKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(intKeyPair.Public)));
        intCertGen.AddExtension(BcX509Extensions.AuthorityKeyIdentifier, false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bcRootCert.GetPublicKey())));
        var bcIntCert = intCertGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));

        var leafKeyPairGen = new RsaKeyPairGenerator();
        leafKeyPairGen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var leafKeyPair = leafKeyPairGen.GenerateKeyPair();

        var leafCertGen = new X509V3CertificateGenerator();
        leafCertGen.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
        leafCertGen.SetIssuerDN(new X509Name("CN=Test Intermediate"));
        leafCertGen.SetSubjectDN(new X509Name("CN=Test Leaf NonURI AIA"));
        leafCertGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        leafCertGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        leafCertGen.SetPublicKey(leafKeyPair.Public);
        leafCertGen.AddExtension(BcX509Extensions.AuthorityKeyIdentifier, false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bcIntCert.GetPublicKey())));
        // Two AIA entries: DirectoryName (skipped) + valid URI
        var aiaEntries = new[]
        {
            new AccessDescription(AccessDescription.IdADCAIssuers,
                new GeneralName(GeneralName.DirectoryName, new X509Name("CN=Not A URI"))),
            new AccessDescription(AccessDescription.IdADCAIssuers,
                new GeneralName(GeneralName.UniformResourceIdentifier, validAiaUrl))
        };
        leafCertGen.AddExtension(BcX509Extensions.AuthorityInfoAccess, false,
            new AuthorityInformationAccess(aiaEntries));
        var bcLeafCert = leafCertGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", intKeyPair.Private));

        return (caKeyPair, bcRootCert, intKeyPair, bcIntCert, bcLeafCert);
    }

    /// <summary>
    /// Creates a 3-level PKI where the leaf has an AIA with an empty URL first,
    /// followed by a valid URL.
    /// </summary>
    private static (
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair caKeyPair,
        Org.BouncyCastle.X509.X509Certificate bcRootCert,
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair intKeyPair,
        Org.BouncyCastle.X509.X509Certificate bcIntCert,
        Org.BouncyCastle.X509.X509Certificate bcLeafCert)
        CreateThreeLevelPkiWithEmptyAiaUrl(string validAiaUrl)
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();

        var intKeyPairGen = new RsaKeyPairGenerator();
        intKeyPairGen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var intKeyPair = intKeyPairGen.GenerateKeyPair();

        var intCertGen = new X509V3CertificateGenerator();
        intCertGen.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
        intCertGen.SetIssuerDN(new X509Name("CN=Test Root CA"));
        intCertGen.SetSubjectDN(new X509Name("CN=Test Intermediate"));
        intCertGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        intCertGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        intCertGen.SetPublicKey(intKeyPair.Public);
        intCertGen.AddExtension(BcX509Extensions.BasicConstraints, true, new BasicConstraints(true));
        intCertGen.AddExtension(BcX509Extensions.SubjectKeyIdentifier, false,
            X509ExtensionUtilities.CreateSubjectKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(intKeyPair.Public)));
        intCertGen.AddExtension(BcX509Extensions.AuthorityKeyIdentifier, false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bcRootCert.GetPublicKey())));
        var bcIntCert = intCertGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));

        var leafKeyPairGen = new RsaKeyPairGenerator();
        leafKeyPairGen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var leafKeyPair = leafKeyPairGen.GenerateKeyPair();

        var leafCertGen = new X509V3CertificateGenerator();
        leafCertGen.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
        leafCertGen.SetIssuerDN(new X509Name("CN=Test Intermediate"));
        leafCertGen.SetSubjectDN(new X509Name("CN=Test Leaf EmptyAIA"));
        leafCertGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        leafCertGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        leafCertGen.SetPublicKey(leafKeyPair.Public);
        leafCertGen.AddExtension(BcX509Extensions.AuthorityKeyIdentifier, false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bcIntCert.GetPublicKey())));
        // Two AIA entries: empty URL (skipped) + valid URL
        var aiaEntries = new[]
        {
            new AccessDescription(AccessDescription.IdADCAIssuers,
                new GeneralName(GeneralName.UniformResourceIdentifier, "")),
            new AccessDescription(AccessDescription.IdADCAIssuers,
                new GeneralName(GeneralName.UniformResourceIdentifier, validAiaUrl))
        };
        leafCertGen.AddExtension(BcX509Extensions.AuthorityInfoAccess, false,
            new AuthorityInformationAccess(aiaEntries));
        var bcLeafCert = leafCertGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", intKeyPair.Private));

        return (caKeyPair, bcRootCert, intKeyPair, bcIntCert, bcLeafCert);
    }

    private class MockHttpHandler : HttpMessageHandler
    {
        private readonly Dictionary<string, byte[]> _responses = new();
        private readonly Dictionary<string, int> _callCounts = new();

        public void SetResponse(string url, byte[] data) => _responses[url] = data;

        public int CallCount(string url) =>
            _callCounts.TryGetValue(url, out var count) ? count : 0;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var url = request.RequestUri!.ToString();
            _callCounts[url] = _callCounts.TryGetValue(url, out var count) ? count + 1 : 1;

            if (_responses.TryGetValue(url, out var data))
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(data)
                });
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }

    #endregion

    public class FakeChainValidatorDiagnostics
    {
        public bool Called;

        private readonly List<string> _actualErrorMessages = new List<string>();
        public List<string> ActualErrorMessages
        {
            get { return _actualErrorMessages; }
        }

        public void OnChainProblem(ChainElementInfo chainElement)
        {
            foreach (var problem in chainElement.Problems
                         .Where(p => (p.Status & TrustChainValidator.DefaultProblemFlags) != 0))
            {
                var msg = $"Trust ERROR ({problem.Status}){problem.StatusInformation}, {chainElement.Certificate}";
                _actualErrorMessages.Add(msg);
                Called = true;
            }
        }
    }

}
