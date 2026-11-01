#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Udap.Common.Certificates;
using Xunit.Abstractions;
using ZiggyCreatures.Caching.Fusion;

namespace Udap.Common.Tests.Certificates;

/// <summary>
/// AIA and CRL URLs come from certificates, which whoever asks to be trusted can write.
/// These tests pin what validation is willing to download on behalf of an untrusted certificate.
/// </summary>
public class UntrustedCertificateDownloadTests
{
    private readonly ITestOutputHelper _testOutputHelper;

    public UntrustedCertificateDownloadTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
    }

    /// <summary>
    /// A chain that never reaches a configured anchor is rejected without downloading any CRL,
    /// and AIA chasing stops after a few downloads however far the certificates point.
    /// </summary>
    [Fact]
    public async Task UntrustedChain_Downloads_No_Crl_And_A_Bounded_Number_Of_Aia_Certificates()
    {
        var handler = new RecordingHttpHandler();

        // Untrusted root -> CA 1 -> CA 2 -> CA 3 -> CA 4 -> leaf. Every certificate below the root names its
        // issuer's URL (AIA) and a CRL distribution point; none of them chains to the configured anchor.
        var issuer = CreateCa("CN=Untrusted Root", issuer: null, aiaUrl: null, crlUrl: null);
        var issuerUrl = "http://pki.internal.test/root.cer";
        handler.Responses[issuerUrl] = issuer.RawData;

        for (var i = 1; i <= 4; i++)
        {
            var ca = CreateCa($"CN=Untrusted CA {i}", issuer, issuerUrl, $"http://pki.internal.test/ca{i}.crl");
            issuerUrl = $"http://pki.internal.test/ca{i}.cer";
            handler.Responses[issuerUrl] = ca.RawData;
            issuer = ca;
        }

        var leaf = CreateLeaf("CN=Untrusted Leaf", issuer, issuerUrl, "http://pki.internal.test/leaf.crl");
        var unrelatedAnchor = CreateCa("CN=Configured Anchor", issuer: null, aiaUrl: null, crlUrl: null);

        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            true,
            BuildServices().GetRequiredService<ILogger<TrustChainValidator>>(),
            null,
            new HttpClient(handler));

        var trusted = await validator.IsTrustedCertificateAsync(
            "test",
            leaf,
            null,
            new X509Certificate2Collection(unrelatedAnchor));

        Assert.False(trusted);
        Assert.DoesNotContain(handler.Requests, url => url.EndsWith(".crl"));
        Assert.InRange(handler.Requests.Count(url => url.EndsWith(".cer")), 1, 3);
    }

    /// <summary>
    /// A download stops once it passes the size limit instead of buffering whatever the server sends.
    /// </summary>
    [Fact]
    public async Task Download_Stops_Reading_At_The_Size_Limit()
    {
        const string url = "http://pki.internal.test/huge.cer";
        var content = new EndlessContent();
        var handler = new RecordingHttpHandler { Content = _ => content };

        var services = BuildServices();
        var downloadCache = new CertificateDownloadCache(
            services.GetRequiredService<IFusionCacheProvider>(),
            new HttpClient(handler),
            services.GetRequiredService<ILogger<CertificateDownloadCache>>());

        var certificate = await downloadCache.GetIntermediateCertificateAsync(url);

        Assert.Null(certificate);
        Assert.InRange(content.BytesRead, 1, 2 * 1024 * 1024);
    }

    /// <summary>Only http and https AIA and CRL URLs are downloaded.</summary>
    [Theory]
    [InlineData("file:///etc/passwd")]
    [InlineData("ftp://pki.internal.test/ca.cer")]
    [InlineData("ldap://pki.internal.test/cn=ca")]
    public async Task Download_Refuses_Non_Http_Urls(string url)
    {
        var handler = new RecordingHttpHandler();
        var services = BuildServices();
        var downloadCache = new CertificateDownloadCache(
            services.GetRequiredService<IFusionCacheProvider>(),
            new HttpClient(handler),
            services.GetRequiredService<ILogger<CertificateDownloadCache>>());

        Assert.Null(await downloadCache.GetIntermediateCertificateAsync(url));
        Assert.Null(await downloadCache.GetCrlAsync(url));
        Assert.Empty(handler.Requests);
    }

    private ServiceProvider BuildServices()
    {
        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        services.AddFusionCache(CertificateDownloadCache.CacheName);
        return services.BuildServiceProvider();
    }

    private static X509Certificate2 CreateCa(string subject, X509Certificate2? issuer, string? aiaUrl, string? crlUrl)
    {
        using var key = RSA.Create(2048);
        var request = BuildRequest(subject, key, isCa: true, aiaUrl, crlUrl);

        if (issuer == null)
        {
            return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        }

        using var cert = request.Create(issuer, issuer.NotBefore, issuer.NotAfter.AddDays(-1), RandomNumberGenerator.GetBytes(8));
        return cert.CopyWithPrivateKey(key);
    }

    private static X509Certificate2 CreateLeaf(string subject, X509Certificate2 issuer, string aiaUrl, string crlUrl)
    {
        using var key = RSA.Create(2048);
        var request = BuildRequest(subject, key, isCa: false, aiaUrl, crlUrl);
        return request.Create(issuer, issuer.NotBefore, issuer.NotAfter.AddDays(-1), RandomNumberGenerator.GetBytes(8));
    }

    private static CertificateRequest BuildRequest(string subject, RSA key, bool isCa, string? aiaUrl, string? crlUrl)
    {
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(isCa, false, 0, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        if (aiaUrl != null)
        {
            request.CertificateExtensions.Add(new X509AuthorityInformationAccessExtension(null, [aiaUrl]));
        }

        if (crlUrl != null)
        {
            request.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension([crlUrl]));
        }

        return request;
    }

    private sealed class RecordingHttpHandler : HttpMessageHandler
    {
        public Dictionary<string, byte[]> Responses { get; } = new();
        public List<string> Requests { get; } = [];
        public Func<string, HttpContent>? Content { get; init; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var url = request.RequestUri!.ToString();
            lock (Requests)
            {
                Requests.Add(url);
            }

            if (Content != null)
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = Content(url) });
            }

            return Task.FromResult(Responses.TryGetValue(url, out var data)
                ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(data) }
                : new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }

    /// <summary>A response body with no Content-Length that never ends, counting what is read.</summary>
    private sealed class EndlessContent : HttpContent
    {
        private readonly EndlessStream _stream = new();

        public long BytesRead => _stream.BytesRead;

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
            throw new NotSupportedException();

        protected override Task<Stream> CreateContentReadStreamAsync() => Task.FromResult<Stream>(_stream);

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }

        private sealed class EndlessStream : Stream
        {
            public long BytesRead { get; private set; }

            public override int Read(byte[] buffer, int offset, int count)
            {
                Array.Fill(buffer, (byte)0x30, offset, count);
                BytesRead += count;
                return count;
            }

            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => throw new NotSupportedException();
            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
            public override void Flush() { }
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        }
    }
}
