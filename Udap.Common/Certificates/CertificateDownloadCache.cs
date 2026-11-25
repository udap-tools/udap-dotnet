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

    /// <summary>
    /// Name of the <see cref="HttpClient"/> registered for AIA and CRL downloads.
    /// </summary>
    public const string HttpClientName = "UdapCertificateDownloads";

    /// <summary>
    /// Longest time a downloaded certificate or CRL stays cached, whatever its NotAfter or
    /// NextUpdate says. Downloads happen before the chain is trusted, so the server that
    /// answered does not get to choose how long its answer is kept.
    /// </summary>
    public static readonly TimeSpan MaxCacheDuration = TimeSpan.FromHours(24);

    /// <summary>
    /// Memory budget, in bytes, of the default in-memory certificate cache. Each entry is sized
    /// by its downloaded length, so the cache cannot grow without bound.
    /// </summary>
    public const long DefaultMemoryCacheSizeLimit = 64L * 1024 * 1024;

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
            var data = await CertificateDownloader.GetBytesAsync(_httpClient, url, CertificateDownloader.MaxCertificateBytes, cancellationToken);
#if NET9_0_OR_GREATER
            var cert = X509CertificateLoader.LoadCertificate(data);
#else
            var cert = new X509Certificate2(data);
#endif

            var timeToExpiry = cert.NotAfter.ToUniversalTime() - DateTime.UtcNow;

            await _cache.SetAsync(cacheKey, data, EntryOptions(timeToExpiry, data.Length), cancellationToken);

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
            var data = await CertificateDownloader.GetBytesAsync(_httpClient, url, CertificateDownloader.MaxCrlBytes, cancellationToken);

            var crl = new X509CrlParser().ReadCrl(data);
            var expiry = crl.NextUpdate ?? DateTime.UtcNow.Add(_defaultCrlTtl);
            var timeToExpiry = expiry.ToUniversalTime() - DateTime.UtcNow;

            await _cache.SetAsync(cacheKey, data, EntryOptions(timeToExpiry, data.Length), cancellationToken);

            return crl;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to download CRL from {Url}", url);
            return null;
        }
    }

    private static FusionCacheEntryOptions EntryOptions(TimeSpan timeToExpiry, long size)
    {
        var options = new FusionCacheEntryOptions { Size = size };

        if (timeToExpiry > TimeSpan.Zero)
        {
            options.Duration = timeToExpiry < MaxCacheDuration ? timeToExpiry : MaxCacheDuration;
        }

        return options;
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
