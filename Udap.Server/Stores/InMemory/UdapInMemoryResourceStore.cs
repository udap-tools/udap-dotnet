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
using System;
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
        if (identityResources?.GroupBy(m => m.Name).Any(g => g.Count() > 1) == true)
        {
            throw new ArgumentException("Identity resources must not contain duplicate names");
        }

        if (apiResources?.GroupBy(m => m.Name).Any(g => g.Count() > 1) == true)
        {
            throw new ArgumentException("Api resources must not contain duplicate names");
        }

        if (apiScopes?.GroupBy(m => m.Name).Any(g => g.Count() > 1) == true)
        {
            throw new ArgumentException("Scopes must not contain duplicate names");
        }

        _identityResources = identityResources ?? Enumerable.Empty<IdentityResource>();
        _apiResources = apiResources ?? Enumerable.Empty<ApiResource>();
        _apiScopes = apiScopes ?? Enumerable.Empty<ApiScope>();
    }

    /// <inheritdoc/>
    public Task<Resources> GetAllResourcesAsync(CancellationToken ct)
    {
        using var activity = Tracing.StoreActivitySource.StartActivity();

        var result = new Resources(_identityResources, _apiResources, _apiScopes);
        return Task.FromResult(result);
    }

    /// <inheritdoc/>
    public Task<IReadOnlyCollection<ApiResource>> FindApiResourcesByNameAsync(IEnumerable<string> apiResourceNames, CancellationToken ct)
    {
        using var activity = Tracing.StoreActivitySource.StartActivity();
        var apiResourceNamesList = apiResourceNames as List<string> ?? apiResourceNames.ToList();
        activity?.SetTag(Tracing.Properties.ApiResourceNames, apiResourceNamesList.ToSpaceSeparatedString());

        ArgumentNullException.ThrowIfNull(apiResourceNames);

        IReadOnlyCollection<ApiResource> query = (from a in _apiResources
                    where apiResourceNamesList.Contains(a.Name)
                    select a).ToList();


        return Task.FromResult(query);
    }

    /// <inheritdoc/>
    public Task<IReadOnlyCollection<IdentityResource>> FindIdentityResourcesByScopeNameAsync(IEnumerable<string> scopeNames, CancellationToken ct)
    {
        using var activity = Tracing.StoreActivitySource.StartActivity();
        var scopeNamesList = scopeNames as List<string> ?? scopeNames.ToList();
        activity?.SetTag(Tracing.Properties.ScopeNames, scopeNamesList.ToSpaceSeparatedString());

        ArgumentNullException.ThrowIfNull(scopeNames);

        IReadOnlyCollection<IdentityResource> identity = (from i in _identityResources
                       where scopeNamesList.Contains(i.Name)
                       select i).ToList();

        return Task.FromResult(identity);
    }

    /// <inheritdoc/>
    public Task<IReadOnlyCollection<ApiResource>> FindApiResourcesByScopeNameAsync(IEnumerable<string> scopeNames, CancellationToken ct)
    {
        using var activity = Tracing.StoreActivitySource.StartActivity();
        var scopeNamesList = scopeNames as List<string> ?? scopeNames.ToList();
        activity?.SetTag(Tracing.Properties.ScopeNames, scopeNamesList.ToSpaceSeparatedString());

        ArgumentNullException.ThrowIfNull(scopeNames);

        IReadOnlyCollection<ApiResource> query = (from a in _apiResources
                    where a.Scopes.Any(x => scopeNamesList.Contains(x))
                    select a).ToList();

        return Task.FromResult(query);
    }

    /// <inheritdoc/>
    public Task<IReadOnlyCollection<ApiScope>> FindApiScopesByNameAsync(IEnumerable<string> scopeNames, CancellationToken ct)
    {
        using var activity = Tracing.StoreActivitySource.StartActivity();
        var scopeNamesList = scopeNames as List<string> ?? scopeNames.ToList();
        activity?.SetTag(Tracing.Properties.ScopeNames, scopeNamesList.ToSpaceSeparatedString());

        ArgumentNullException.ThrowIfNull(scopeNames);

        IReadOnlyCollection<ApiScope> query =
            (from x in _apiScopes
            where scopeNamesList.Contains(x.Name)
            select x).ToList();

        return Task.FromResult(query);
    }
}
