#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer.Models;
using Duende.IdentityServer.Stores;
using Microsoft.Extensions.DependencyInjection;
using Udap.Common.Models;
using Udap.Server.Storage.Stores;
using Udap.Server.Stores.InMemory;

namespace Udap.Server.Configuration.DependencyInjection;
public static class UdapInMemory
{
    /// <summary>
    /// Adds the in memory API scopes.
    /// </summary>
    /// <param name="builder">IServiceCollection</param>
    /// <param name="apiScopes">The API scopes.</param>
    /// <returns></returns>
    public static IUdapServiceBuilder AddUdapInMemoryApiScopes(this IUdapServiceBuilder builder, IEnumerable<ApiScope> apiScopes)
    {
        builder.Services.AddSingleton(apiScopes);
        builder.Services.AddTransient<IResourceStore, UdapInMemoryResourceStore>();

        return builder;
    }

    public static IUdapServiceBuilder AddInMemoryUdapCertificates(
        this IUdapServiceBuilder builder,
        IEnumerable<Community> communities)
    {
        builder.Services.AddSingleton(communities);
        builder.Services.AddSingleton<ICollection<TieredClient>>(new List<TieredClient>());

        builder.Services.AddScoped<IUdapClientRegistrationStore>(sp => 
            new InMemoryUdapClientRegistrationStore(
                sp.GetRequiredService<List<Duende.IdentityServer.Models.Client>>(),
                sp.GetRequiredService<ICollection<TieredClient>>(),
                sp.GetRequiredService<IEnumerable<Community>>()));

        return builder;
    }
}
