#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using System.Text;
using Duende.IdentityServer.EntityFramework.Mappers;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Udap.Common.Models;
using Udap.Server.DbContexts;
using Udap.Server.Mappers;

namespace Udap.Server.Registration
{
    /// <inheritdoc /> 
    public class UdapClientRegistrationStore : IUdapClientRegistrationStore
    {
        private readonly IUdapDbAdminContext _dbContext;
        private ILogger<UdapClientRegistrationStore> _logger;

        public UdapClientRegistrationStore(IUdapDbAdminContext dbContext, ILogger<UdapClientRegistrationStore> logger)
        {
            _dbContext = dbContext;
            _logger = logger;
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
            List<Entities.Anchor> anchors;

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

        public async Task<X509Certificate2Collection?> GetRootCertificates(CancellationToken token = default)
        {
            var roots = await _dbContext.RootCertificates.ToListAsync(token).ConfigureAwait(false);
            
            _logger.LogInformation($"Found {roots?.Count() ?? 0} root certificates");

            if (roots != null)
            {
                return new X509Certificate2Collection(roots
                    .Select(a => X509Certificate2.CreateFromPem(a.X509Certificate)).ToArray());

            }
            else
            {
                return null;
            }
        }


        public async Task<X509Certificate2Collection> GetAnchorsCertificates(string? community, CancellationToken token = default)
        {
            var anchors = await GetAnchors(community, token).ConfigureAwait(false);

            _logger.LogInformation($"Found {anchors?.Count() ?? 0} anchors for community, {community}");
            _logger.LogDebug(ShowSummary(anchors));

            return new X509Certificate2Collection(anchors.Select(a => X509Certificate2.CreateFromPem(a.Certificate)).ToArray());
        }

        private string ShowSummary(IEnumerable<Anchor> anchors)
        {
            var sb = new StringBuilder();
            sb.Append("Resolved Anchors: | ");

            foreach (var anchor in anchors)
            {
                sb.Append($"{anchor.Name} |");
            }

            return sb.ToString();
        }
    }
}
