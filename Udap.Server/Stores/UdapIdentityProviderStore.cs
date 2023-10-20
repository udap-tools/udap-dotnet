#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer.EntityFramework.Interfaces;
using Duende.IdentityServer.EntityFramework.Mappers;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Udap.Common;
using Udap.Server.Models;

namespace Udap.Server.Stores;
public class UdapIdentityProviderStore : IIdentityProviderStore
{
    /// <summary>
    /// The DbContext.
    /// </summary>
    protected readonly IConfigurationDbContext Context;

    /// <summary>
    /// The CancellationToken provider.
    /// </summary>
    protected readonly ICancellationTokenProvider CancellationTokenProvider;

    /// <summary>
    /// The logger.
    /// </summary>
    protected readonly ILogger<UdapIdentityProviderStore> Logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="UdapIdentityProviderStore"/> class.
    /// </summary>
    /// <param name="context">The context.</param>
    /// <param name="logger">The logger.</param>
    /// <param name="cancellationTokenProvider"></param>
    /// <exception cref="ArgumentNullException">context</exception>
    public UdapIdentityProviderStore(IConfigurationDbContext context, ILogger<UdapIdentityProviderStore> logger, ICancellationTokenProvider cancellationTokenProvider)
    {
        Context = context ?? throw new ArgumentNullException(nameof(context));
        Logger = logger;
        CancellationTokenProvider = cancellationTokenProvider;
    }

    /// <inheritdoc/>
    public async Task<IEnumerable<IdentityProviderName>> GetAllSchemeNamesAsync()
    {
        using var activity = Tracing.StoreActivitySource.StartActivity($"{nameof(UdapIdentityProviderStore)}.GetAllSchemeNames");

        var query = Context.IdentityProviders.Select(x => new IdentityProviderName
        {
            Enabled = x.Enabled,
            Scheme = x.Scheme,
            DisplayName = x.DisplayName
        });

        return await query.ToArrayAsync(CancellationTokenProvider.CancellationToken);
    }

    /// <inheritdoc/>
    public async Task<IdentityProvider?> GetBySchemeAsync(string scheme)
    {
        using var activity = Tracing.StoreActivitySource.StartActivity($"{nameof(UdapIdentityProviderStore)}.GetByScheme");
        activity?.SetTag(Tracing.Properties.Scheme, scheme);

        var idp = (await Context.IdentityProviders.AsNoTracking().Where(x => x.Scheme == scheme)
                .ToArrayAsync(CancellationTokenProvider.CancellationToken))
            .SingleOrDefault(x => x.Scheme == scheme);
        if (idp == null) return null;

        var result = MapIdp(idp);
        
        if (result == null)
        {
            Logger.LogWarning("Identity provider record found in database, but mapping failed for scheme {scheme} and protocol type {protocol}", idp.Scheme, idp.Type);
        }

        return result;
    }

    // public async Task<bool> UpsertProviderAsync(UdapIdentityProvider provider)
    // {
    //     using var activity = Tracing.StoreActivitySource.StartActivity("UdapIdentityProviderStore.UpsertProvider");
    //     activity?.SetTag(Tracing.Properties.Scheme, provider.Authority);
    //
    //     var idp = (await Context.IdentityProviders.AsNoTracking().Where(x => x. == scheme)
    //             .ToArrayAsync(CancellationTokenProvider.CancellationToken))
    //         .SingleOrDefault(x => x.Scheme == scheme);
    //
    // }

    /// <summary>
    /// Maps from the identity provider entity to identity provider model.
    /// </summary>
    /// <param name="idp"></param>
    /// <returns></returns>
    protected virtual IdentityProvider? MapIdp(Duende.IdentityServer.EntityFramework.Entities.IdentityProvider idp)
    {
        if (idp.Type == "oidc" || idp.Type == "udap_oidc")
        {
            return new UdapIdentityProvider(idp.ToModel());
        }

        return null;
    }
}
