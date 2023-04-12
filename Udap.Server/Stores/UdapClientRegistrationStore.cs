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

            var existingClient = _dbContext.Clients
                .Include(c => c.AllowedScopes)
                .Include(c => c.RedirectUris)
                .SingleOrDefault(c =>
                c.AllowedGrantTypes.Any(grant => client.AllowedGrantTypes.Contains(grant.GrantType)) &&
                c.ClientSecrets.Any(cs =>
                cs.Type == UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME &&
                cs.Value == iss));

            if (existingClient != null)
            {
                client.ClientId = existingClient.ClientId;
                existingClient.AllowedScopes = client.AllowedScopes
                    .Select(s => new ClientScope(){ClientId = existingClient.Id, Scope = s})
                    .ToList();
                existingClient.RedirectUris = client.ToEntity().RedirectUris;
                await _dbContext.SaveChangesAsync(token);
                return true;
            }

            _dbContext.Clients.Add(client.ToEntity());
            await _dbContext.SaveChangesAsync(token);
            return false;
        }

        public async Task<int> CancelRegistration(Duende.IdentityServer.Models.Client client, CancellationToken token = default)
        {
            //TODO: combine into one query
            var iss = client.ClientSecrets
                .SingleOrDefault(cs => cs.Type == UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME)
                ?.Value;

            var clientsFound = _dbContext.Clients
                .Where(c =>
                    c.ClientSecrets.Any(cs =>
                        cs.Type == UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME &&
                        cs.Value == iss))
                .Select(c => c)
                .ToList();

            if (clientsFound.Any())
            {
                foreach (var clientFound in clientsFound)
                {
                    _dbContext.Clients.Remove(clientFound);
                }

                await _dbContext.SaveChangesAsync(token);
                return clientsFound.Count;
            }

            return 0;
        }

        public async Task<IEnumerable<Anchor>> GetAnchors(string? community, CancellationToken token = default)
        {
            using var activity = Tracing.StoreActivitySource.StartActivity("UdapClientRegistrationStore.GetAnchors");
            activity?.SetTag(Tracing.Properties.Community, community);

            List<Entities.Anchor> anchors;

            if (community == null)
            {
                anchors = await _dbContext.Anchors
                    .Include(a => a.Community)
                    .Include(a => a.IntermediateCertificates)
                    .Where(a => a.Community.Enabled && a.Enabled)
                    .Select(a => a)
                    .ToListAsync(token);
            }
            else
            {
                anchors = await _dbContext.Anchors
                    .Include(a => a.Community)
                    .Include(a => a.IntermediateCertificates)
                    .Where(a => a.Community.Enabled && a.Community.Name == community && a.Enabled)
                    .Select(a => a)
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
                .ToListAsync(token);

            var certs = encodedCerts.Select(anchor =>
                X509Certificate2.CreateFromPem(anchor.X509Certificate));

            foreach (var intCert in encodedCerts.SelectMany(anchor => anchor.IntermediateCertificates))
            {
                certs.Append(X509Certificate2.CreateFromPem(intCert.X509Certificate));
            }
           
            return certs;
        }

        //TODO.  This is still coded with the old concept of getting root certificates.
        public async Task<X509Certificate2Collection?> GetIntermediateCertificates(CancellationToken token = default)
        {
            using var activity = Tracing.StoreActivitySource.StartActivity("UdapClientRegistrationStore.GetRootCertificates");

            var roots = await _dbContext.IntermediateCertificates.ToListAsync(token).ConfigureAwait(false);
            
            _logger.LogInformation($"Found {roots?.Count() ?? 0} anchor certificates");

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
