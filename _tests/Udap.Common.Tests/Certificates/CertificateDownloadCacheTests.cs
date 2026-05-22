#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Udap.Common.Certificates;
using Xunit.Abstractions;
using ZiggyCreatures.Caching.Fusion;
using X509Certificate2 = System.Security.Cryptography.X509Certificates.X509Certificate2;

namespace Udap.Common.Tests.Certificates;

public class CertificateDownloadCacheTests
{
    private readonly ITestOutputHelper _testOutputHelper;

    public CertificateDownloadCacheTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
    }

    [Fact]
    public async Task GetIntermediateCertificateAsync_CachesOnFirstCall_ReturnsCachedOnSecond()
    {
        var (cache, handler) = CreateCacheWithHandler(out _);
        var certBytes = CreateSelfSignedCertBytes();

        handler.SetResponse("https://example.com/intermediate.cer", certBytes);

        var cert1 = await cache.GetIntermediateCertificateAsync("https://example.com/intermediate.cer");
        Assert.NotNull(cert1);
        Assert.Equal(1, handler.CallCount("https://example.com/intermediate.cer"));

        var cert2 = await cache.GetIntermediateCertificateAsync("https://example.com/intermediate.cer");
        Assert.NotNull(cert2);
        Assert.Equal(1, handler.CallCount("https://example.com/intermediate.cer")); // second call should come from cache

        Assert.Equal(cert1!.Thumbprint, cert2!.Thumbprint);
    }

    [Fact]
    public async Task GetCrlAsync_CachesOnFirstCall_ReturnsCachedOnSecond()
    {
        var (cache, handler) = CreateCacheWithHandler(out _);
        var crlBytes = CreateCrlBytes(hoursUntilNextUpdate: 24);

        handler.SetResponse("https://example.com/crl.crl", crlBytes);

        var crl1 = await cache.GetCrlAsync("https://example.com/crl.crl");
        Assert.NotNull(crl1);
        Assert.Equal(1, handler.CallCount("https://example.com/crl.crl"));

        var crl2 = await cache.GetCrlAsync("https://example.com/crl.crl");
        Assert.NotNull(crl2);
        Assert.Equal(1, handler.CallCount("https://example.com/crl.crl")); // second call should come from cache
    }

    [Fact]
    public async Task RemoveIntermediateAsync_RemovesSingleEntry()
    {
        var (cache, handler) = CreateCacheWithHandler(out _);
        var certBytes = CreateSelfSignedCertBytes();

        handler.SetResponse("https://example.com/a.cer", certBytes);

        await cache.GetIntermediateCertificateAsync("https://example.com/a.cer");
        Assert.Equal(1, handler.CallCount("https://example.com/a.cer"));

        await cache.RemoveIntermediateAsync("https://example.com/a.cer");

        // Next fetch of removed URL should trigger a new download
        await cache.GetIntermediateCertificateAsync("https://example.com/a.cer");
        Assert.Equal(2, handler.CallCount("https://example.com/a.cer"));
    }

    [Fact]
    public async Task RemoveCrlAsync_RemovesSingleEntry()
    {
        var (cache, handler) = CreateCacheWithHandler(out _);
        var crlBytes = CreateCrlBytes(hoursUntilNextUpdate: 24);

        handler.SetResponse("https://example.com/a.crl", crlBytes);

        await cache.GetCrlAsync("https://example.com/a.crl");
        Assert.Equal(1, handler.CallCount("https://example.com/a.crl"));

        await cache.RemoveCrlAsync("https://example.com/a.crl");

        // Next fetch of removed URL should trigger a new download
        await cache.GetCrlAsync("https://example.com/a.crl");
        Assert.Equal(2, handler.CallCount("https://example.com/a.crl"));
    }

    [Fact]
    public async Task GetIntermediateCertificateAsync_DownloadFailure_ReturnsNull()
    {
        var (cache, handler) = CreateCacheWithHandler(out _);
        handler.SetError("https://example.com/missing.cer", HttpStatusCode.NotFound);

        var result = await cache.GetIntermediateCertificateAsync("https://example.com/missing.cer");

        Assert.Null(result);
    }

    [Fact]
    public async Task GetCrlAsync_DownloadFailure_ReturnsNull()
    {
        var (cache, handler) = CreateCacheWithHandler(out _);
        handler.SetError("https://example.com/missing.crl", HttpStatusCode.NotFound);

        var result = await cache.GetCrlAsync("https://example.com/missing.crl");

        Assert.Null(result);
    }

    [Fact]
    public void DI_Resolves_ICertificateDownloadCache()
    {
        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        services.AddFusionCache(CertificateDownloadCache.CacheName);
        services.AddSingleton(new HttpClient());
        services.AddSingleton<ICertificateDownloadCache, CertificateDownloadCache>();

        var sp = services.BuildServiceProvider();
        var cache = sp.GetRequiredService<ICertificateDownloadCache>();

        Assert.NotNull(cache);
        Assert.IsType<CertificateDownloadCache>(cache);
    }

    [Fact]
    public void DI_Resolves_TrustChainValidator_With_Cache()
    {
        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        services.AddFusionCache(CertificateDownloadCache.CacheName);
        services.AddSingleton(new HttpClient());
        services.AddSingleton<ICertificateDownloadCache, CertificateDownloadCache>();
        services.AddSingleton<TrustChainValidator>();

        var sp = services.BuildServiceProvider();
        var validator = sp.GetRequiredService<TrustChainValidator>();

        Assert.NotNull(validator);
    }

    [Fact]
    public void DI_Resolves_TrustChainValidator_Without_Cache()
    {
        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        services.AddSingleton<TrustChainValidator>();

        var sp = services.BuildServiceProvider();
        var validator = sp.GetRequiredService<TrustChainValidator>();

        Assert.NotNull(validator);
    }

    [Fact]
    public async Task TrustChainValidator_Downloads_Crl_Without_Cache()
    {
        // Create a CA key pair and self-signed root
        var caKeyPairGenerator = new RsaKeyPairGenerator();
        caKeyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        var caKeyPair = caKeyPairGenerator.GenerateKeyPair();

        var caCertGenerator = new X509V3CertificateGenerator();
        caCertGenerator.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
        caCertGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        caCertGenerator.SetSubjectDN(new X509Name("CN=Test Root CA"));
        caCertGenerator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        caCertGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));
        caCertGenerator.SetPublicKey(caKeyPair.Public);
        caCertGenerator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
        caCertGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
            X509ExtensionUtilities.CreateSubjectKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(caKeyPair.Public)));

        var caSigner = new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private);
        var bcRootCert = caCertGenerator.Generate(caSigner);

        // Create a leaf certificate with a CRL distribution point
        var leafKeyPairGenerator = new RsaKeyPairGenerator();
        leafKeyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        var leafKeyPair = leafKeyPairGenerator.GenerateKeyPair();

        const string crlUrl = "https://example.com/test.crl";

        var leafCertGenerator = new X509V3CertificateGenerator();
        leafCertGenerator.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
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
        leafCertGenerator.AddExtension(X509Extensions.CrlDistributionPoints, false,
            new CrlDistPoint(new[] { crlDp }));
        leafCertGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bcRootCert.GetPublicKey())));

        var leafSigner = new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private);
        var bcLeafCert = leafCertGenerator.Generate(leafSigner);

        // Create a CRL signed by the CA (leaf is NOT revoked)
        var crlGenerator = new X509V2CrlGenerator();
        crlGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        crlGenerator.SetThisUpdate(DateTime.UtcNow);
        crlGenerator.SetNextUpdate(DateTime.UtcNow.AddHours(24));
        var crlSigner = new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private);
        var crl = crlGenerator.Generate(crlSigner);

        // Set up a mock HTTP handler to serve the CRL
        var handler = new MockHttpHandler();
        handler.SetResponse(crlUrl, crl.GetEncoded());
        var httpClient = new HttpClient(handler);

        // Create validator WITHOUT a cache, but WITH an HttpClient
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

        // CRL was downloaded and leaf is not revoked, so chain should be valid
        Assert.True(result);
        Assert.Equal(1, handler.CallCount(crlUrl));
    }

    [Fact]
    public async Task TrustChainValidator_Rejects_Revoked_Certificate()
    {
        // Create a CA key pair and self-signed root
        var caKeyPairGenerator = new RsaKeyPairGenerator();
        caKeyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        var caKeyPair = caKeyPairGenerator.GenerateKeyPair();

        var caCertGenerator = new X509V3CertificateGenerator();
        caCertGenerator.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
        caCertGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        caCertGenerator.SetSubjectDN(new X509Name("CN=Test Root CA"));
        caCertGenerator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        caCertGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));
        caCertGenerator.SetPublicKey(caKeyPair.Public);
        caCertGenerator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
        caCertGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
            X509ExtensionUtilities.CreateSubjectKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(caKeyPair.Public)));

        var caSigner = new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private);
        var bcRootCert = caCertGenerator.Generate(caSigner);

        // Create a leaf certificate with a CRL distribution point
        var leafKeyPairGenerator = new RsaKeyPairGenerator();
        leafKeyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        var leafKeyPair = leafKeyPairGenerator.GenerateKeyPair();

        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());
        const string crlUrl = "https://example.com/test.crl";

        var leafCertGenerator = new X509V3CertificateGenerator();
        leafCertGenerator.SetSerialNumber(leafSerialNumber);
        leafCertGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        leafCertGenerator.SetSubjectDN(new X509Name("CN=Test Revoked Leaf"));
        leafCertGenerator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        leafCertGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));
        leafCertGenerator.SetPublicKey(leafKeyPair.Public);

        var crlDp = new DistributionPoint(
            new DistributionPointName(
                DistributionPointName.FullName,
                new GeneralNames(new GeneralName(GeneralName.UniformResourceIdentifier, crlUrl))),
            null, null);
        leafCertGenerator.AddExtension(X509Extensions.CrlDistributionPoints, false,
            new CrlDistPoint(new[] { crlDp }));
        leafCertGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bcRootCert.GetPublicKey())));

        var leafSigner = new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private);
        var bcLeafCert = leafCertGenerator.Generate(leafSigner);

        // Create a CRL signed by the CA with the leaf certificate REVOKED
        var crlGenerator = new X509V2CrlGenerator();
        crlGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        crlGenerator.SetThisUpdate(DateTime.UtcNow);
        crlGenerator.SetNextUpdate(DateTime.UtcNow.AddHours(24));
        crlGenerator.AddCrlEntry(leafSerialNumber, DateTime.UtcNow.AddHours(-1), CrlReason.KeyCompromise);
        var crlSigner = new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private);
        var crl = crlGenerator.Generate(crlSigner);

        // Set up a mock HTTP handler to serve the CRL
        var handler = new MockHttpHandler();
        handler.SetResponse(crlUrl, crl.GetEncoded());
        var httpClient = new HttpClient(handler);

        // Create validator with revocation checking enabled
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

        // CRL was downloaded and leaf IS revoked, so chain should be invalid
        Assert.False(result);
        Assert.Equal(1, handler.CallCount(crlUrl));
    }

    [Fact]
    public async Task TrustChainValidator_Rejects_Revoked_Certificate_With_Cache()
    {
        // Create a CA key pair and self-signed root
        var caKeyPairGenerator = new RsaKeyPairGenerator();
        caKeyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        var caKeyPair = caKeyPairGenerator.GenerateKeyPair();

        var caCertGenerator = new X509V3CertificateGenerator();
        caCertGenerator.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
        caCertGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        caCertGenerator.SetSubjectDN(new X509Name("CN=Test Root CA"));
        caCertGenerator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        caCertGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));
        caCertGenerator.SetPublicKey(caKeyPair.Public);
        caCertGenerator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
        caCertGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
            X509ExtensionUtilities.CreateSubjectKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(caKeyPair.Public)));

        var caSigner = new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private);
        var bcRootCert = caCertGenerator.Generate(caSigner);

        // Create a leaf certificate with a CRL distribution point
        var leafKeyPairGenerator = new RsaKeyPairGenerator();
        leafKeyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        var leafKeyPair = leafKeyPairGenerator.GenerateKeyPair();

        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());
        const string crlUrl = "https://example.com/test-cached.crl";

        var leafCertGenerator = new X509V3CertificateGenerator();
        leafCertGenerator.SetSerialNumber(leafSerialNumber);
        leafCertGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        leafCertGenerator.SetSubjectDN(new X509Name("CN=Test Revoked Leaf Cached"));
        leafCertGenerator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        leafCertGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));
        leafCertGenerator.SetPublicKey(leafKeyPair.Public);

        var crlDp = new DistributionPoint(
            new DistributionPointName(
                DistributionPointName.FullName,
                new GeneralNames(new GeneralName(GeneralName.UniformResourceIdentifier, crlUrl))),
            null, null);
        leafCertGenerator.AddExtension(X509Extensions.CrlDistributionPoints, false,
            new CrlDistPoint(new[] { crlDp }));
        leafCertGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bcRootCert.GetPublicKey())));

        var leafSigner = new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private);
        var bcLeafCert = leafCertGenerator.Generate(leafSigner);

        // Create a CRL signed by the CA with the leaf certificate REVOKED
        var crlGenerator = new X509V2CrlGenerator();
        crlGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        crlGenerator.SetThisUpdate(DateTime.UtcNow);
        crlGenerator.SetNextUpdate(DateTime.UtcNow.AddHours(24));
        crlGenerator.AddCrlEntry(leafSerialNumber, DateTime.UtcNow.AddHours(-1), CrlReason.KeyCompromise);
        var crlSigner = new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private);
        var crl = crlGenerator.Generate(crlSigner);

        // Set up mock HTTP + FusionCache
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

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        // CRL was downloaded via cache and leaf IS revoked, so chain should be invalid
        Assert.False(result);
        Assert.Equal(1, mockHandler.CallCount(crlUrl));

        // Second call should use cached CRL (no additional download)
        var result2 = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        Assert.False(result2);
        Assert.Equal(1, mockHandler.CallCount(crlUrl)); // still only 1 download
    }

    [Fact]
    public async Task MultipleCacheEntries_RemoveOneStillServesOther()
    {
        var (cache, handler) = CreateCacheWithHandler(out _);
        var certBytes = CreateSelfSignedCertBytes();
        var crlBytes = CreateCrlBytes(hoursUntilNextUpdate: 24);

        handler.SetResponse("https://ca1.example.com/intermediate.cer", certBytes);
        handler.SetResponse("https://ca2.example.com/intermediate.cer", certBytes);
        handler.SetResponse("https://ca1.example.com/crl.crl", crlBytes);
        handler.SetResponse("https://ca2.example.com/crl.crl", crlBytes);

        await cache.GetIntermediateCertificateAsync("https://ca1.example.com/intermediate.cer");
        await cache.GetIntermediateCertificateAsync("https://ca2.example.com/intermediate.cer");
        await cache.GetCrlAsync("https://ca1.example.com/crl.crl");
        await cache.GetCrlAsync("https://ca2.example.com/crl.crl");

        // Remove one of each
        await cache.RemoveIntermediateAsync("https://ca1.example.com/intermediate.cer");
        await cache.RemoveCrlAsync("https://ca2.example.com/crl.crl");

        // Removed entries should re-download
        await cache.GetIntermediateCertificateAsync("https://ca1.example.com/intermediate.cer");
        Assert.Equal(2, handler.CallCount("https://ca1.example.com/intermediate.cer"));
        await cache.GetCrlAsync("https://ca2.example.com/crl.crl");
        Assert.Equal(2, handler.CallCount("https://ca2.example.com/crl.crl"));

        // Non-removed entries should still be cached
        await cache.GetIntermediateCertificateAsync("https://ca2.example.com/intermediate.cer");
        Assert.Equal(1, handler.CallCount("https://ca2.example.com/intermediate.cer"));
        await cache.GetCrlAsync("https://ca1.example.com/crl.crl");
        Assert.Equal(1, handler.CallCount("https://ca1.example.com/crl.crl"));
    }

    #region Helpers

    private (CertificateDownloadCache cache, MockHttpHandler handler) CreateCacheWithHandler(
        out ServiceProvider sp)
    {
        var handler = new MockHttpHandler();
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        services.AddFusionCache(CertificateDownloadCache.CacheName);

        sp = services.BuildServiceProvider();
        var cacheProvider = sp.GetRequiredService<IFusionCacheProvider>();
        var logger = sp.GetRequiredService<ILogger<CertificateDownloadCache>>();

        var cache = new CertificateDownloadCache(cacheProvider, httpClient, logger);
        return (cache, handler);
    }

    private static byte[] CreateSelfSignedCertBytes()
    {
        var keyPairGenerator = new RsaKeyPairGenerator();
        keyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        var keyPair = keyPairGenerator.GenerateKeyPair();

        var certGenerator = new X509V3CertificateGenerator();
        certGenerator.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
        certGenerator.SetIssuerDN(new X509Name("CN=Test Intermediate CA"));
        certGenerator.SetSubjectDN(new X509Name("CN=Test Intermediate CA"));
        certGenerator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        certGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));
        certGenerator.SetPublicKey(keyPair.Public);

        certGenerator.AddExtension(
            X509Extensions.BasicConstraints,
            true,
            new BasicConstraints(true));

        var signer = new Asn1SignatureFactory("SHA256WithRSA", keyPair.Private);
        var bcCert = certGenerator.Generate(signer);

        return bcCert.GetEncoded();
    }

    private static byte[] CreateCrlBytes(int hoursUntilNextUpdate = 24)
    {
        var keyPairGenerator = new RsaKeyPairGenerator();
        keyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        var keyPair = keyPairGenerator.GenerateKeyPair();

        var crlGenerator = new X509V2CrlGenerator();
        crlGenerator.SetIssuerDN(new X509Name("CN=Test CA"));
        crlGenerator.SetThisUpdate(DateTime.UtcNow);
        crlGenerator.SetNextUpdate(DateTime.UtcNow.AddHours(hoursUntilNextUpdate));

        var signer = new Asn1SignatureFactory("SHA256WithRSA", keyPair.Private);
        var crl = crlGenerator.Generate(signer);

        return crl.GetEncoded();
    }

    private class MockHttpHandler : HttpMessageHandler
    {
        private readonly Dictionary<string, byte[]> _responses = new();
        private readonly Dictionary<string, HttpStatusCode> _errors = new();
        private readonly Dictionary<string, int> _callCounts = new();

        public void SetResponse(string url, byte[] data)
        {
            _responses[url] = data;
        }

        public void SetError(string url, HttpStatusCode statusCode)
        {
            _errors[url] = statusCode;
        }

        public int CallCount(string url) =>
            _callCounts.TryGetValue(url, out var count) ? count : 0;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var url = request.RequestUri!.ToString();
            _callCounts[url] = _callCounts.TryGetValue(url, out var count) ? count + 1 : 1;

            if (_errors.TryGetValue(url, out var statusCode))
            {
                return Task.FromResult(new HttpResponseMessage(statusCode));
            }

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
}
