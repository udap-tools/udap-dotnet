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
using Duende.IdentityServer.EntityFramework.Entities;
using Duende.IdentityServer.EntityFramework.Mappers;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Udap.Common;
using Udap.Common.Models;
using Udap.Server.DbContexts;
using Udap.Server.Mappers;
using Udap.Server.Storage.Stores;

namespace Udap.Server.Stores
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

        public async Task<bool> UpsertClient(Duende.IdentityServer.Models.Client client, CancellationToken token = default)
        {
            using var activity = Tracing.StoreActivitySource.StartActivity("UdapClientRegistrationStore.AddClient");
            activity?.SetTag(Tracing.Properties.ClientId, client.ClientId);

            var iss = client.ClientSecrets
                .SingleOrDefault(cs => cs.Type == UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME)
                ?.Value;

            var existingClient = _dbContext.Clients.SingleOrDefault(c =>
                c.AllowedGrantTypes.Any(grant => client.AllowedGrantTypes.Contains(grant.GrantType)) &&
                c.ClientSecrets.Any(cs =>
                cs.Type == UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME &&
                cs.Value == iss));

            if (existingClient != null)
            {
                existingClient.AllowedScopes = client.AllowedScopes
                    .Select(s => new ClientScope(){ClientId = existingClient.Id, Scope = s})
                    .ToList();

                await _dbContext.SaveChangesAsync(token);
                return true;
            }
            else
            {
                _dbContext.Clients.Add(client.ToEntity());
                await _dbContext.SaveChangesAsync(token);
                return false;
            }
        }

        public async Task<IEnumerable<Anchor>> GetAnchors(string? community, CancellationToken token = default)
        {
            using var activity = Tracing.StoreActivitySource.StartActivity("UdapClientRegistrationStore.GetAnchors");
            activity?.SetTag(Tracing.Properties.Community, community);

            List<Entities.Anchor> anchors;

            if (community == null)
            {
                anchors = await _dbContext.Communities
                    .Where(c => c.Enabled)
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

        public async Task<IEnumerable<X509Certificate2>>? GetCommunityCertificates(long communityId, CancellationToken token = default)
        {
            using var activity = Tracing.StoreActivitySource.StartActivity("UdapClientRegistrationStore.GetCommunityCertificates");
            activity?.SetTag(Tracing.Properties.Community, communityId);

            var encodedCerts = await _dbContext.Anchors
                .Where(c => c.CommunityId == communityId)
                .Include(c => c.IntermediateCertificates)
                .SelectMany(c => c.IntermediateCertificates.Select(i => 
                    i.X509Certificate).ToList().Append(c.X509Certificate))
                .ToListAsync(token);

            return encodedCerts.Select(e => 
                new X509Certificate2(Convert.FromBase64String(e)));
        }

        public async Task<X509Certificate2Collection?> GetIntermediateCertificates(CancellationToken token = default)
        {
            using var activity = Tracing.StoreActivitySource.StartActivity("UdapClientRegistrationStore.GetRootCertificates");

            var roots = await _dbContext.IntermediateCertificates.ToListAsync(token).ConfigureAwait(false);
            
            _logger.LogInformation($"Found {roots?.Count() ?? 0} root certificates");

            if (roots != null)
            {
                return new X509Certificate2Collection(roots
                    .Select(a => X509Certificate2.CreateFromPem(a.X509Certificate)).ToArray());

            }

            return null;
        }


        public async Task<X509Certificate2Collection> GetAnchorsCertificates(string? community, CancellationToken token = default)
        {
            using var activity = Tracing.StoreActivitySource.StartActivity("UdapClientRegistrationStore.GetAnchorsCertificates");
            activity?.SetTag(Tracing.Properties.Community, community);

            var anchors = (await GetAnchors(community, token).ConfigureAwait(false)).ToList();

            _logger.LogInformation($"Found {anchors.Count} anchors for community, {community}");
            _logger.LogDebug(ShowSummary(anchors));

            if (!anchors.Any())
            {
                return new X509Certificate2Collection();
            }

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
