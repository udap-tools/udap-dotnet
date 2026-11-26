#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Udap.Common.Certificates;
using Udap.Common.Models;
using Udap.Server.Storage.DbContexts;
using Udap.Server.Storage.Mappers;
using Udap.Server.Storage.Stores;

namespace Udap.Server.Stores;

/// <summary>
/// Trust anchors for validating upstream identity providers during Tiered OAuth, read from the
/// UDAP database each time they are resolved. Only enabled anchors in enabled communities are
/// returned, each with its community name, so disabling or removing an anchor takes effect
/// without a restart and the community filter in discovery validation applies.
/// </summary>
internal sealed class UdapDbTrustAnchorStore : ITrustAnchorStore
{
    private readonly IServiceScopeFactory _scopeFactory;

    public UdapDbTrustAnchorStore(IServiceScopeFactory scopeFactory)
    {
        _scopeFactory = scopeFactory;
    }

    /// <summary>
    /// The anchors from the most recent <see cref="Resolve"/>. Callers should use the store
    /// returned by <see cref="Resolve"/> instead, which is a snapshot of its own.
    /// </summary>
    public ICollection<Anchor> AnchorCertificates { get; set; } = new List<Anchor>();

    public async Task<ITrustAnchorStore> Resolve()
    {
        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetService<IUdapDbContext>();

        if (db == null)
        {
            return new TrustAnchorStore(new List<Anchor>());
        }

        var entities = await db.Anchors
            .Include(a => a.Community)
            .Include(a => a.Intermediates)
            .Where(a => a.Enabled && a.Community != null && a.Community.Enabled)
            .AsNoTracking()
            .ToListAsync();

        var anchors = entities.Select(a => a.ToModel()).ToList();
        AnchorCertificates = anchors;

        return new TrustAnchorStore(anchors);
    }
}
