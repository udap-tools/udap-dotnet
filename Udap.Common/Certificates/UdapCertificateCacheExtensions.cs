#region (c) 2022-2025 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Udap.Common.Certificates;
using ZiggyCreatures.Caching.Fusion;

// ReSharper disable once CheckNamespace
#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130 // Namespace does not match folder structure

/// <summary>
/// Extension methods for registering the UDAP certificate download cache with dependency injection.
/// </summary>
public static class UdapCertificateCacheExtensions
{
    /// <summary>
    /// Register the named FusionCache for UDAP certificate caching with custom options.
    /// Call this <strong>before</strong> <c>AddUdapServer()</c> to control cache behavior
    /// (TTL, fail-safe, distributed cache backend, etc.).
    /// <para>
    /// If not called, <c>AddUdapServer()</c> will register a default named cache automatically.
    /// </para>
    /// <para>
    /// For standalone use (without <c>AddUdapServer()</c>), also register the HttpClient and
    /// <see cref="ICertificateDownloadCache"/>:
    /// <code>
    /// services.AddHttpClient(CertificateDownloadCache.HttpClientName)
    ///     .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AllowAutoRedirect = false });
    /// services.AddSingleton&lt;ICertificateDownloadCache&gt;(sp => new CertificateDownloadCache(
    ///     sp.GetRequiredService&lt;IFusionCacheProvider&gt;(),
    ///     sp.GetRequiredService&lt;IHttpClientFactory&gt;().CreateClient(CertificateDownloadCache.HttpClientName),
    ///     sp.GetRequiredService&lt;ILogger&lt;CertificateDownloadCache&gt;&gt;()));
    /// </code>
    /// </para>
    /// </summary>
    /// <returns>An <see cref="IFusionCacheBuilder"/> for further configuration (e.g., WithDefaultEntryOptions, WithDistributedCache).</returns>
    public static IFusionCacheBuilder AddUdapCertificateCache(this IServiceCollection services)
    {
        services.AddSingleton<UdapCertificateCacheMarker>();
        return services.AddFusionCache(CertificateDownloadCache.CacheName);
    }
}

/// <summary>
/// Marker to prevent duplicate FusionCache registration for the UDAP certificate cache.
/// </summary>
public class UdapCertificateCacheMarker;
