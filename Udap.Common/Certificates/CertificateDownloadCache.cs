#region (c) 2022-2025 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.X509;
using ZiggyCreatures.Caching.Fusion;

namespace Udap.Common.Certificates;

/// <summary>
/// FusionCache-backed cache for AIA-fetched intermediate certificates and CRLs.
/// Consumers can configure the named cache (<see cref="CacheName"/>) with any backend:
/// in-memory (default), Redis, or hybrid.
/// </summary>
public class CertificateDownloadCache : ICertificateDownloadCache
{
    /// <summary>
    /// Named cache identifier. Register with <c>services.AddFusionCache("UdapCertificates")</c>.
    /// </summary>
    public const string CacheName = "UdapCertificates";

    private const string IntermediatePrefix = "intermediate:";
    private const string CrlPrefix = "crl:";

    private readonly IFusionCache _cache;
    private readonly HttpClient _httpClient;
    private readonly ILogger<CertificateDownloadCache> _logger;
    private readonly TimeSpan _defaultCrlTtl;

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateDownloadCache"/>.
    /// </summary>
    /// <param name="cacheProvider">The FusionCache provider to retrieve the named certificate cache.</param>
    /// <param name="httpClient">The HTTP client used to download CRL and AIA resources.</param>
    /// <param name="logger">The logger instance.</param>
    /// <param name="defaultCrlTtl">The default time-to-live for cached CRL entries. Defaults to 1 hour.</param>
    public CertificateDownloadCache(
        IFusionCacheProvider cacheProvider,
        HttpClient httpClient,
        ILogger<CertificateDownloadCache> logger,
        TimeSpan? defaultCrlTtl = null)
    {
        _cache = cacheProvider.GetCache(CacheName);
        _httpClient = httpClient;
        _logger = logger;
        _defaultCrlTtl = defaultCrlTtl ?? TimeSpan.FromHours(12);
    }

    /// <inheritdoc />
    public async Task<X509Certificate2?> GetIntermediateCertificateAsync(string url, CancellationToken cancellationToken = default)
    {
        var cacheKey = $"{IntermediatePrefix}{url}";

        var result = await _cache.TryGetAsync<byte[]>(cacheKey, token: cancellationToken);
        if (result.HasValue)
        {
#if NET9_0_OR_GREATER
            return X509CertificateLoader.LoadCertificate(result.Value);
#else
            return new X509Certificate2(result.Value);
#endif
        }

        try
        {
            _logger.LogDebug("Downloading intermediate certificate from {Url}", url);
            var data = await _httpClient.GetByteArrayAsync(url, cancellationToken);
#if NET9_0_OR_GREATER
            var cert = X509CertificateLoader.LoadCertificate(data);
#else
            var cert = new X509Certificate2(data);
#endif

            var timeToExpiry = cert.NotAfter.ToUniversalTime() - DateTime.UtcNow;
            var options = new FusionCacheEntryOptions();
            if (timeToExpiry > TimeSpan.Zero)
            {
                options.Duration = timeToExpiry;
            }

            await _cache.SetAsync(cacheKey, data, options, cancellationToken);

            return cert;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to download intermediate certificate from {Url}", url);
            return null;
        }
    }

    /// <inheritdoc />
    public async Task<X509Crl?> GetCrlAsync(string url, CancellationToken cancellationToken = default)
    {
        var cacheKey = $"{CrlPrefix}{url}";

        var result = await _cache.TryGetAsync<byte[]>(cacheKey, token: cancellationToken);
        if (result.HasValue)
        {
            return new X509CrlParser().ReadCrl(result.Value);
        }

        try
        {
            _logger.LogDebug("Downloading CRL from {Url}", url);
            var data = await _httpClient.GetByteArrayAsync(url, cancellationToken);

            var crl = new X509CrlParser().ReadCrl(data);
            var expiry = crl.NextUpdate ?? DateTime.UtcNow.Add(_defaultCrlTtl);
            var timeToExpiry = expiry.ToUniversalTime() - DateTime.UtcNow;

            var options = new FusionCacheEntryOptions();
            if (timeToExpiry > TimeSpan.Zero)
            {
                options.Duration = timeToExpiry;
            }

            await _cache.SetAsync(cacheKey, data, options, cancellationToken);

            return crl;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to download CRL from {Url}", url);
            return null;
        }
    }

    /// <inheritdoc />
    public async Task RemoveIntermediateAsync(string url, CancellationToken cancellationToken = default)
    {
        await _cache.RemoveAsync($"{IntermediatePrefix}{url}", token: cancellationToken);
        _logger.LogDebug("Removed cached intermediate certificate for {Url}", url);
    }

    /// <inheritdoc />
    public async Task RemoveCrlAsync(string url, CancellationToken cancellationToken = default)
    {
        await _cache.RemoveAsync($"{CrlPrefix}{url}", token: cancellationToken);
        _logger.LogDebug("Removed cached CRL for {Url}", url);
    }
}
