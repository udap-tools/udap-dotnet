#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer.Models;
using Udap.Common.Models;
using Udap.Server.Storage.Stores;
using Udap.Server.Stores.InMemory;


//
// See reason for Microsoft.Extensions.DependencyInjection namespace
// here: https://learn.microsoft.com/en-us/dotnet/core/extensions/dependency-injection-usage
//
namespace Microsoft.Extensions.DependencyInjection;

public static class InMemory
{
    public static IIdentityServerBuilder AddInMemoryUdapCertificates(
        this IIdentityServerBuilder builder,
        IEnumerable<Community> communities)
    {
        builder.Services.AddSingleton(communities);

        builder.Services.AddScoped<IUdapClientRegistrationStore>(sp => 
            new InMemoryUdapClientRegistrationStore(
                sp.GetRequiredService<List<Client>>(),
                sp.GetRequiredService<IEnumerable<Community>>()));

        return builder;
    }
}
