#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Stores;
using Udap.Common;
using Udap.Server.Validation;
using Udap.Util.Extensions;

namespace Udap.Server.Stores.InMemory;

public class UdapInMemoryResourceStore : IResourceStore
{
    private readonly IEnumerable<IdentityResource> _identityResources;
    private readonly IEnumerable<ApiResource> _apiResources;
    private readonly IEnumerable<ApiScope> _apiScopes;

    /// <summary>
    /// Initializes a new instance of the <see cref="InMemoryResourcesStore" /> class.
    /// </summary>
    public UdapInMemoryResourceStore(
        IEnumerable<IdentityResource>? identityResources = null,
        IEnumerable<ApiResource>? apiResources = null,
        IEnumerable<ApiScope>? apiScopes = null)
    {
        if (identityResources?.HasDuplicates(m => m.Name) == true)
        {
            throw new ArgumentException("Identity resources must not contain duplicate names");
        }

        if (apiResources?.HasDuplicates(m => m.Name) == true)
        {
            throw new ArgumentException("Api resources must not contain duplicate names");
        }

        if (apiScopes?.HasDuplicates(m => m.Name) == true)
        {
            throw new ArgumentException("Scopes must not contain duplicate names");
        }

        _identityResources = identityResources ?? Enumerable.Empty<IdentityResource>();
        _apiResources = apiResources ?? Enumerable.Empty<ApiResource>();
        _apiScopes = apiScopes ?? Enumerable.Empty<ApiScope>();
    }

    /// <inheritdoc/>
    public Task<Resources> GetAllResourcesAsync()
    {
        using var activity = Tracing.StoreActivitySource.StartActivity("UdapInMemoryResourceStore.GetAllResources");

        var result = new Resources(_identityResources, _apiResources, _apiScopes);
        return Task.FromResult(result);
    }

    /// <inheritdoc/>
    public Task<IEnumerable<ApiResource>> FindApiResourcesByNameAsync(IEnumerable<string> apiResourceNames)
    {
        using var activity = Tracing.StoreActivitySource.StartActivity("UdapInMemoryResourceStore.FindApiResourcesByName");
        var apiResourceNamesList = apiResourceNames as List<string> ?? apiResourceNames.ToList();
        activity?.SetTag(Tracing.Properties.ApiResourceNames, apiResourceNamesList.ToSpaceSeparatedString());

        if (apiResourceNames == null) throw new ArgumentNullException(nameof(apiResourceNames));
        
        var query = from a in _apiResources
                    where apiResourceNamesList.Contains(a.Name)
                    select a;


        return Task.FromResult(query);
    }

    /// <inheritdoc/>
    public Task<IEnumerable<IdentityResource>> FindIdentityResourcesByScopeNameAsync(IEnumerable<string> scopeNames)
    {
        using var activity = Tracing.StoreActivitySource.StartActivity("UdapInMemoryResourceStore.FindIdentityResourcesByScopeName");
        var scopeNamesList = scopeNames as List<string> ?? scopeNames.ToList();
        activity?.SetTag(Tracing.Properties.ScopeNames, scopeNamesList.ToSpaceSeparatedString());

        if (scopeNames == null) throw new ArgumentNullException(nameof(scopeNames));

        var identity = from i in _identityResources
                       where scopeNamesList.Contains(i.Name)
                       select i;

        return Task.FromResult(identity);
    }

    /// <inheritdoc/>
    public Task<IEnumerable<ApiResource>> FindApiResourcesByScopeNameAsync(IEnumerable<string> scopeNames)
    {
        using var activity = Tracing.StoreActivitySource.StartActivity("UdapInMemoryResourceStore.FindApiResourcesByScopeName");
        var scopeNamesList = scopeNames as List<string> ?? scopeNames.ToList();
        activity?.SetTag(Tracing.Properties.ScopeNames, scopeNamesList.ToSpaceSeparatedString());

        if (scopeNames == null) throw new ArgumentNullException(nameof(scopeNames));

        var query = from a in _apiResources
                    where a.Scopes.Any(x => scopeNamesList.Contains(x))
                    select a;

        return Task.FromResult(query);
    }

    /// <inheritdoc/>
    public Task<IEnumerable<ApiScope>> FindApiScopesByNameAsync(IEnumerable<string> scopeNames)
    {
        using var activity = Tracing.StoreActivitySource.StartActivity("UdapInMemoryResourceStore.FindApiScopesByName");
        var scopeNamesList = scopeNames as List<string> ?? scopeNames.ToList();
        activity?.SetTag(Tracing.Properties.ScopeNames, scopeNamesList.ToSpaceSeparatedString());

        if (scopeNames == null) throw new ArgumentNullException(nameof(scopeNames));
        
        var query =
            from x in _apiScopes
            where scopeNamesList.Contains(x.Name)
            select x;
        
        return Task.FromResult(query);
    }
}
