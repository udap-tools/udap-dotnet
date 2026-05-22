#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Udap.Common.Certificates;

namespace Udap.Client;

/// <summary>
/// Extension methods for registering UDAP client services with dependency injection.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="IUdapClient"/> and its dependencies with the service collection.
    /// Returns an <see cref="IHttpClientBuilder"/> so callers can chain message handler
    /// configuration (e.g., <c>.AddHttpMessageHandler&lt;HeaderAugmentationHandler&gt;()</c>).
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>An <see cref="IHttpClientBuilder"/> for further configuration.</returns>
    public static IHttpClientBuilder AddUdapClient(this IServiceCollection services)
    {
        services.TryAddScoped<TrustChainValidator>();
        services.TryAddScoped<UdapClientDiscoveryValidator>();

        return services.AddHttpClient<IUdapClient, UdapClient>();
    }
}
