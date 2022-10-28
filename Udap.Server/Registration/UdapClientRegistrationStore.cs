#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Duende.IdentityServer.EntityFramework.Mappers;
using Microsoft.EntityFrameworkCore;
using Udap.Common.Models;
using Udap.Server.DbContexts;
using Udap.Server.Mappers;

namespace Udap.Server.Registration
{
    /// <inheritdoc /> TODO: missing admin interface for adding Anchors to store.
    public class UdapClientRegistrationStore : IUdapClientRegistrationStore
    {
        private IUdapDbAdminContext _dbContext;

        public UdapClientRegistrationStore(IUdapDbAdminContext dbContext)
        {
            _dbContext = dbContext;
        }

        public async Task<Duende.IdentityServer.Models.Client?> GetClient(Duende.IdentityServer.Models.Client client, CancellationToken token = default)
        {
            var entity = await _dbContext.Clients
                .SingleOrDefaultAsync(c => c.ClientId == client.ClientId, token);

            return entity.ToModel();
        }

        public async Task<int> AddClient(Duende.IdentityServer.Models.Client client, CancellationToken token = default)
        {
            _dbContext.Clients.Add(client.ToEntity());
            return await _dbContext.SaveChangesAsync(token);
        }

        public async Task<IEnumerable<Anchor>> GetAnchors(string? community, CancellationToken token = default)
        {
            List<Entitiies.Anchor> anchors;

            if (community == null)
            {
                anchors = await _dbContext.Communities
                    .Where(c => c.Default)
                    .Include(a => a.Anchors)
                    .SelectMany(c => c.Anchors)
                    .ToListAsync(token);
            }
            else
            {
                anchors = await _dbContext.Communities
                    .Where(c => c.Name == community)
                    .Include(c => c.Anchors)
                    .SelectMany(c => c.Anchors)
                    .ToListAsync(token);
            }

            return anchors.Select(a => a.ToModel());
        }

        public async Task<IEnumerable<Anchor>> GetRoots(string? community, CancellationToken token = default)
        {
            List<Entitiies.Anchor> anchors;

            if (community == null)
            {
                anchors = await _dbContext.Communities
                    .Where(c => c.Default)
                    .Include(a => a.Anchors)
                    .SelectMany(c => c.Anchors)
                    .ToListAsync(token);
            }
            else
            {
                anchors = await _dbContext.Communities
                    .Where(c => c.Name == community)
                    .Include(c => c.Anchors)
                    .SelectMany(c => c.Anchors)
                    .ToListAsync(token);
            }

            return anchors.Select(a => a.ToModel());
        }


        public async Task<X509Certificate2Collection> GetRootCertificates(string? community, CancellationToken token = default)
        {
            var roots = await GetRoots(community, token).ConfigureAwait(false);

            return new X509Certificate2Collection(roots.Select(a => X509Certificate2.CreateFromPem(a.Certificate)).ToArray());
        }


        public async Task<X509Certificate2Collection> GetAnchorsCertificates(string? community, CancellationToken token = default)
        {
            var anchors = await GetAnchors(community, token).ConfigureAwait(false);
            
            return new X509Certificate2Collection(anchors.Select(a => X509Certificate2.CreateFromPem(a.Certificate)).ToArray());
        }
    }
}
