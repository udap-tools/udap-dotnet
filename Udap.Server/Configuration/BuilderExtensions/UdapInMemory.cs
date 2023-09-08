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
using Udap.Server.Stores.InMemory;

namespace Udap.Server.Configuration.BuilderExtensions;
public static class UdapInMemory
{
    /// <summary>
    /// Adds the in memory API scopes.
    /// </summary>
    /// <param name="builder">The builder.</param>
    /// <param name="apiScopes">The API scopes.</param>
    /// <returns></returns>
    public static IIdentityServerBuilder AddUdapInMemoryApiScopes(this IIdentityServerBuilder builder, IEnumerable<ApiScope> apiScopes)
    {
        builder.Services.AddSingleton(apiScopes);
        builder.AddResourceStore<UdapInMemoryResourceStore>();

        return builder;
    }

}
