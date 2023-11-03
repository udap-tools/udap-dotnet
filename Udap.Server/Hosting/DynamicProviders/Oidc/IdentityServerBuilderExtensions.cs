#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer.Models;
using Microsoft.Extensions.DependencyInjection;
using Udap.Server.Hosting.DynamicProviders.Store;

namespace Udap.Server.Hosting.DynamicProviders.Oidc;
public static class IdentityServerBuilderExtensions
{


    public static IIdentityServerBuilder AddInMemorIdentityProviders(
        this IIdentityServerBuilder builder, IEnumerable<IdentityProvider> identityProviders)
    {
        builder.Services.AddSingleton(identityProviders);
        builder.AddIdentityProviderStore<UdapInMemoryIdentityProviderStore>();

        return builder;
    }

}
