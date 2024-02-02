#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer.EntityFramework.Mappers;
using Microsoft.EntityFrameworkCore;
using Udap.Common.Models;
using Udap.Server.DbContexts;
using Udap.Server.Mappers;
using Udap.Server.Storage.Stores;

namespace Udap.Server.Stores;

/// <inheritdoc />
public class UdapClientConfigurationStore : IUdapClientConfigurationStore
{
    private IUdapDbContext _dbContext;
    
    public UdapClientConfigurationStore(IUdapDbContext dbContext)
    {
        _dbContext = dbContext;
    }
    
    public async Task<Duende.IdentityServer.Models.Client?> GetClient(Duende.IdentityServer.Models.Client client, CancellationToken token = default)
    {
        var entity = await _dbContext.Clients
            .SingleOrDefaultAsync(c => c.ClientId == client.ClientId, token);
    
        return entity?.ToModel();
    }
    
    public async Task<IEnumerable<Anchor>> GetAnchors(CancellationToken token = default)
    {
        var anchors = await _dbContext.Anchors.ToListAsync(token);

        return anchors.Select(a => a.ToModel());
    }
}