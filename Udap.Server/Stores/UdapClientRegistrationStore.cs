#region (c) 2024 Joseph Shook. All rights reserved.
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
using Duende.IdentityServer.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Udap.Common;
using Udap.Common.Models;
using Udap.Server.DbContexts;
using Udap.Server.Extensions;
using Udap.Server.Mappers;
using Udap.Server.Storage.Stores;
using Secret = Duende.IdentityServer.Models.Secret;

namespace Udap.Server.Stores
{
    /// <inheritdoc /> 
    public class UdapClientRegistrationStore : IUdapClientRegistrationStore
    {
        private readonly IUdapDbAdminContext _dbContext;
        private readonly ILogger<UdapClientRegistrationStore> _logger;

        public UdapClientRegistrationStore(IUdapDbAdminContext dbContext, ILogger<UdapClientRegistrationStore> logger)
        {
            _dbContext = dbContext;
            _logger = logger;
        }

        public async Task<Duende.IdentityServer.Models.Client?> GetClient(Duende.IdentityServer.Models.Client client, CancellationToken token = default)
        {
            var entity = await _dbContext.Clients
                .SingleOrDefaultAsync(c => c.ClientId == client.ClientId, token);

            return entity?.ToModel();
        }

        
        public async Task<bool> UpsertClient(Duende.IdentityServer.Models.Client client, CancellationToken token = default)
        {
            using var activity = Tracing.StoreActivitySource.StartActivity();
            activity?.SetTag(Tracing.Properties.ClientId, client.ClientId);

            var iss = client.ClientSecrets
                .SingleOrDefault(cs => cs.Type == UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME)
                ?.Value;

            var community = client.ClientSecrets
                .SingleOrDefault(cs => cs.Type == UdapServerConstants.SecretTypes.UDAP_COMMUNITY)
                ?.Value;

            var existingClient = await _dbContext.Clients
                .Include(c => c.AllowedScopes)
                .Include(c => c.RedirectUris)
                .Include(c => c.AllowedGrantTypes)
                .SingleOrDefaultAsync(c =>
                // ISS
                c.ClientSecrets.Any(cs =>
                cs.Type == UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME &&
                cs.Value == iss) &&
                // Community
                c.ClientSecrets.Any(cs =>
                cs.Type == UdapServerConstants.SecretTypes.UDAP_COMMUNITY &&
                cs.Value == community), cancellationToken: token);

            if (existingClient != null)
            {
                client.ClientId = existingClient.ClientId;
                existingClient.AllowedScopes = client.AllowedScopes
                    .Select(s => new ClientScope(){ClientId = existingClient.Id, Scope = s})
                    .ToList();
                existingClient.RedirectUris = client.ToEntity().RedirectUris;
                existingClient.AllowedGrantTypes = client.ToEntity().AllowedGrantTypes;
                existingClient.AllowOfflineAccess = client.AllowOfflineAccess;
                existingClient.RequirePkce = client.RequirePkce;
                existingClient.LogoUri = client.LogoUri;

                await _dbContext.SaveChangesAsync(token);
                _logger.LogInformation("Updated client: {Id}", existingClient.Id);
                return true;
            }

            _dbContext.Clients.Add(client.ToEntity());
            await _dbContext.SaveChangesAsync(token);
            _logger.LogInformation("Created client");
            return false;
        }

        public async Task<bool> UpsertTieredClient(TieredClient client, CancellationToken token = default)
        {
            using var activity = Tracing.StoreActivitySource.StartActivity();
            activity?.SetTag(Tracing.Properties.ClientId, client.ClientId);
            activity?.SetTag(Tracing.Properties.ClientId, client.IdPBaseUrl);


            var existingClient = await _dbContext.TieredClients
                .SingleOrDefaultAsync(t => 
                    t.IdPBaseUrl == client.IdPBaseUrl  &&
                    t.CommunityId == client.CommunityId, 
                    cancellationToken: token);
            
            if (existingClient != null)
            {
                client.ClientId = existingClient.ClientId;
                if (client.RedirectUri != null)
                {
                    existingClient.RedirectUri = client.RedirectUri;
                }

                await _dbContext.SaveChangesAsync(token);
                _logger.LogInformation("Updated client: {Id}", existingClient.Id);
                return true;
            }

            _dbContext.TieredClients.Add(client.ToEntity());

            await _dbContext.SaveChangesAsync(token);
            _logger.LogInformation("Created client");
            return false;
        }

        public async Task<TieredClient?> FindTieredClientById(string clientId, CancellationToken token = default)
        {
            var entity = await _dbContext.TieredClients
                .SingleOrDefaultAsync(t => t.ClientId == clientId, token);

            return entity.ToModel();
        }

        public async Task<int> CancelRegistration(Duende.IdentityServer.Models.Client client, CancellationToken token = default)
        {
            //TODO: combine into one query
            var iss = client.ClientSecrets
                .SingleOrDefault(cs => cs.Type == UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME)
                ?.Value;

            var community = client.ClientSecrets
                .SingleOrDefault(cs => cs.Type == UdapServerConstants.SecretTypes.UDAP_COMMUNITY)
                ?.Value;

            var clientsFound = _dbContext.Clients
                // ISS
                .Where(c =>
                    c.ClientSecrets.Any(cs =>
                        cs.Type == UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME &&
                        cs.Value == iss) &&
                // Community
                    c.ClientSecrets.Any(cs =>
                        cs.Type == UdapServerConstants.SecretTypes.UDAP_COMMUNITY &&
                        cs.Value == community))
                .Select(c => c)
                .ToList();

            if (clientsFound.Count != 0)
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
            using var activity = Tracing.StoreActivitySource.StartActivity();
            activity?.SetTag(Tracing.Properties.Community, community);

            List<Entities.Anchor> anchors;

            if (community == null)
            {
                anchors = await _dbContext.Anchors
                    .Include(a => a.Community)
                    .Include(a => a.Intermediates)
                    .Where(a => a.Community != null && a.Community.Enabled && a.Enabled)
                    .Select(a => a)
                    .ToListAsync(token);
            }
            else
            {
                anchors = await _dbContext.Anchors
                    .Include(a => a.Community)
                    .Include(a => a.Intermediates)
                    .Where(a => a.Community != null && a.Community.Enabled && a.Community.Name == community && a.Enabled)
                    .Select(a => a)
                    .ToListAsync(token);
            }

            return anchors.Select(a => a.ToModel());
        }

        public async Task<IEnumerable<X509Certificate2>?> GetCommunityCertificates(long communityId, CancellationToken token = default)
        {
            using var activity = Tracing.StoreActivitySource.StartActivity();
            activity?.SetTag(Tracing.Properties.Community, communityId);

            var encodedCerts = await _dbContext.Anchors
                .Where(c => c.CommunityId == communityId)
                .Include(c => c.Intermediates)
                .ToListAsync(token);

            var certificates = encodedCerts.Select(anchor =>
                X509Certificate2.CreateFromPem(anchor.X509Certificate))
                .ToList();

            foreach (var intCert in encodedCerts.SelectMany(anchor => anchor.Intermediates))
            {
                _ = certificates.Append(X509Certificate2.CreateFromPem(intCert.X509Certificate));
            }
           
            return certificates;
        }

        public async Task<X509Certificate2Collection?> GetIntermediateCertificates(CancellationToken token = default)
        {
            using var activity = Tracing.StoreActivitySource.StartActivity();

            var intermediates = await _dbContext.IntermediateCertificates.ToListAsync(token).ConfigureAwait(false);

            _logger.LogInformation("Found {IntermediateCount} intermediate certificates", intermediates.Count);

            return new X509Certificate2Collection(intermediates
                    .Select(a => X509Certificate2.CreateFromPem(a.X509Certificate)).ToArray());
        }


        public async Task<X509Certificate2Collection?> GetAnchorsCertificates(string? community, CancellationToken token = default)
        {
            using var activity = Tracing.StoreActivitySource.StartActivity();
            activity?.SetTag(Tracing.Properties.Community, community);

            var anchors = (await GetAnchors(community, token).ConfigureAwait(false)).ToList();

            _logger.LogInformation("Found {AnchorCount} anchors for community {Community}", anchors.Count, community);
            _logger.LogDebug("Anchor summary: {Summary}", ShowSummary(anchors));

            if (anchors.Count == 0)
            {
                return new X509Certificate2Collection();
            }

            return new X509Certificate2Collection(anchors.Select(a => X509Certificate2.CreateFromPem(a.Certificate)).ToArray());
        }

        public async Task<int?> GetCommunityId(string community, CancellationToken token = default)
        {
            using var activity = Tracing.StoreActivitySource.StartActivity();
            activity?.SetTag(Tracing.Properties.Community, community);

            if (string.IsNullOrEmpty(community))
            {
                return await _dbContext.Communities.Where(c => c.Default)
                    .Select(c => c.Id)
                    .FirstAsync(token);
            }

            return await _dbContext.Communities.Where(c => c.Name == community)
                .Select(c => c.Id)
                .SingleOrDefaultAsync(token);
        }

        public async Task<ICollection<Secret>?> RolloverClientSecrets(ParsedSecret secret, CancellationToken token = default)
        {
            var rolled = false;
            using var activity = Tracing.StoreActivitySource.StartActivity();
            activity?.SetTag(Tracing.Properties.ClientId, secret.Id);

            var entity = await _dbContext.Clients
                .Include(c => c.ClientSecrets)
                .SingleOrDefaultAsync(c => c.ClientId == secret.Id, cancellationToken: token);

            if (entity != null)
            {
                var endCertificate = secret.GetUdapEndCert();

                if(endCertificate != null && endCertificate.NotBefore < DateTime.Now.ToUniversalTime()
                                          && endCertificate.NotAfter > DateTime.Now.ToUniversalTime())
                {
                    foreach (var clientSecret in entity.ClientSecrets.Where(cs =>
                                              cs.Type == UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME ||
                                              cs.Type == UdapServerConstants.SecretTypes.UDAP_COMMUNITY))
                    {
                        clientSecret.Expiration = endCertificate.NotAfter.ToUniversalTime();
                        rolled = true;
                    }
                }

                await _dbContext.SaveChangesAsync(token);
            }

            activity?.SetTag("Rolled", rolled);
            return entity.ToModel().ClientSecrets;
        }

        private static string ShowSummary(IEnumerable<Anchor> anchors)
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
