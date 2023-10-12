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
using Udap.Common;

namespace Udap.Server.Hosting.DynamicProviders.Store;
internal class UdapInMemoryIdentityProviderStore : IIdentityProviderStore
{
    private readonly IEnumerable<IdentityProvider> _providers;

    public UdapInMemoryIdentityProviderStore(IEnumerable<IdentityProvider> providers)
    {
        _providers = providers;
    }

    public Task<IEnumerable<IdentityProviderName>> GetAllSchemeNamesAsync()
    {
        using var activity = Tracing.StoreActivitySource.StartActivity("InMemoryOidcProviderStore.GetAllSchemeNames");

        var items = _providers.Select(x => new IdentityProviderName
        {
            Enabled = x.Enabled,
            DisplayName = x.DisplayName,
            Scheme = x.Scheme
        });

        return Task.FromResult(items);
    }

    public Task<IdentityProvider> GetBySchemeAsync(string scheme)
    {
        using var activity = Tracing.StoreActivitySource.StartActivity("InMemoryOidcProviderStore.GetByScheme");

        var item = _providers.FirstOrDefault(x => x.Scheme == scheme);
        return Task.FromResult<IdentityProvider>(item);
    }
}