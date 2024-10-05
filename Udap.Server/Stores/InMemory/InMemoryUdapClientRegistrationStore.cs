#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Duende.IdentityServer.Models;
using Udap.Common;
using Udap.Common.Models;
using Udap.Server.Extensions;
using Udap.Server.Storage.Stores;

namespace Udap.Server.Stores.InMemory;

public class InMemoryUdapClientRegistrationStore : IUdapClientRegistrationStore
{
    private readonly List<Duende.IdentityServer.Models.Client> _clients;
    private readonly ICollection<TieredClient> _tieredClients;
    private readonly IEnumerable<Community> _communities;
    private readonly IEnumerable<Intermediate> _intermediateCertificates;

    /// <summary>
    /// Initializes a new instance of the <see cref="InMemoryUdapClientRegistrationStore"/> class.
    /// </summary>
    /// <param name="clients"></param>
    /// <param name="tieredClients"></param>
    /// <param name="communities"></param>
    public InMemoryUdapClientRegistrationStore(
        List<Duende.IdentityServer.Models.Client> clients,
        ICollection<TieredClient> tieredClients,
        IEnumerable<Community> communities)
    {
        _clients = clients;
        _communities = communities;
        _tieredClients = tieredClients;
        _intermediateCertificates = _communities
            .Where(c => c.Enabled && c.Anchors != null)
            .SelectMany(c =>
            {
                if (c.Anchors != null)
                {
                    return c.Anchors
                        .SelectMany(a =>
                        {
                            if (a.Intermediates != null)
                            {
                                return a.Intermediates;
                            }
                            return new List<Intermediate>();
                        });
                }
                return new List<Intermediate>();
            })
            .ToList();
    }


    public Task<Duende.IdentityServer.Models.Client?> GetClient(Duende.IdentityServer.Models.Client client, CancellationToken token = default)
    {
        throw new NotImplementedException();
    }


    public Task<bool> UpsertClient(Duende.IdentityServer.Models.Client client, CancellationToken token = default)
    {
        using var activity = Tracing.StoreActivitySource.StartActivity();
        activity?.SetTag(Tracing.Properties.ClientId, client.ClientId);

        var iss = client.ClientSecrets.SingleOrDefault(i =>
            i.Type == UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME)
            ?.Value;

        var community = client.ClientSecrets
            .SingleOrDefault(cs => cs.Type == UdapServerConstants.SecretTypes.UDAP_COMMUNITY)
            ?.Value;

        var existingClient = _clients.SingleOrDefault(c => 
            // ISS
            c.ClientSecrets.Any(cs =>
                cs.Type == UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME && 
                cs.Value == iss) &&
            // Community
            c.ClientSecrets.Any(cs =>
                cs.Type == UdapServerConstants.SecretTypes.UDAP_COMMUNITY &&
                cs.Value == community));

        if (existingClient != null)
        {
            client.ClientId = existingClient.ClientId;
            existingClient.AllowedScopes = client.AllowedScopes;
            existingClient.RedirectUris = client.RedirectUris;
            existingClient.AllowedGrantTypes = client.AllowedGrantTypes;
            existingClient.AllowOfflineAccess = client.AllowOfflineAccess;
            //TODO update Certifications
            //TODO update others?
            return Task.FromResult(true);
        }
        else
        {
            _clients.Add(client);
            return Task.FromResult(false);
        }
    }

    public Task<bool> UpsertTieredClient(TieredClient client, CancellationToken token = default)
    {
        using var activity = Tracing.StoreActivitySource.StartActivity();
        activity?.SetTag(Tracing.Properties.ClientId, client.ClientId);
        activity?.SetTag(Tracing.Properties.ClientId, client.IdPBaseUrl);


        var existingClient = _tieredClients
            .SingleOrDefault(t =>
                    t.IdPBaseUrl == client.IdPBaseUrl &&
                    t.CommunityId == client.CommunityId);

        if (existingClient != null)
        {
            client.ClientId = existingClient.ClientId;
            existingClient.RedirectUri = client.RedirectUri;
            return Task.FromResult(true);
        }

        _tieredClients.Add(client);
        return Task.FromResult(false);
    }

    public Task<TieredClient?> FindTieredClientById(string clientId, CancellationToken token = default)
    {
        return Task.FromResult(_tieredClients.SingleOrDefault(t => t.ClientId == clientId));
    }

    public Task<int> CancelRegistration(Duende.IdentityServer.Models.Client client, CancellationToken token = default)
    {

        var iss = client.ClientSecrets
            .SingleOrDefault(cs => cs.Type == UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME)
            ?.Value;

        var community = client.ClientSecrets
            .SingleOrDefault(cs => cs.Type == UdapServerConstants.SecretTypes.UDAP_COMMUNITY)
            ?.Value;

        var clientsFound = _clients.Where(c => 
            // ISS
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
                _clients.Remove(clientFound);
            }

            return Task.FromResult(clientsFound.Count);
        }

        return Task.FromResult(0);
    }

    public Task<IEnumerable<Anchor>> GetAnchors(string? community, CancellationToken token = default)
    {
        using var activity = Tracing.StoreActivitySource.StartActivity();
        activity?.SetTag(Tracing.Properties.Community, community);

        List<Anchor> anchors;

        if (community == null)
        {
            anchors = _communities
                .Where(c => c.Enabled && c.Anchors != null)
                .SelectMany(c => c.Anchors!)
                .ToList();
        }
        else
        {
            anchors = _communities
                .Where(c => c.Name == community && c.Anchors != null)
                .SelectMany(c => c.Anchors!)
                .ToList();
        }

        return Task.FromResult(anchors.AsEnumerable());
    }

    public Task<IEnumerable<X509Certificate2>?> GetCommunityCertificates(long communityId, CancellationToken token = default)
    {
        using var activity = Tracing.StoreActivitySource.StartActivity();
        activity?.SetTag(Tracing.Properties.CommunityId, communityId);

        var anchors = _communities
            .Where(c => c.Id == communityId && c.Anchors != null)
            .SelectMany(c => c.Anchors!)
            .ToList();

        if (anchors.Count == 0)
        {
            return Task.FromResult<IEnumerable<X509Certificate2>?>(null);
        }
        
        var encodedCerts = new List<X509Certificate2>();
        
        foreach (var anchor in anchors)
        {
            encodedCerts.Add(X509Certificate2.CreateFromPem(anchor.Certificate));
            if (anchor.Intermediates != null)
            {
                encodedCerts.AddRange(anchor.Intermediates.Select(i => 
                    X509Certificate2.CreateFromPem(i.Certificate)));
            }
        }

        return Task.FromResult(encodedCerts.AsEnumerable())!;
    }

    public Task<X509Certificate2Collection?> GetIntermediateCertificates(CancellationToken token = default)
    {
        using var activity = Tracing.StoreActivitySource.StartActivity();

        var intermediates = _intermediateCertificates.ToList();
        var certificates = new X509Certificate2Collection(intermediates
                    .Select(a => X509Certificate2.CreateFromPem(a.Certificate)).ToArray());

        return Task.FromResult<X509Certificate2Collection?>(certificates);
    }

    public Task<X509Certificate2Collection?> GetAnchorsCertificates(string? community, CancellationToken token = default)
    {
        using var activity = Tracing.StoreActivitySource.StartActivity();
        activity?.SetTag(Tracing.Properties.Community, community);

        var anchors = GetAnchors(community, token).Result.ToList();

        if (anchors.Count == 0)
        {
            return Task.FromResult<X509Certificate2Collection?>(null);
        }

        var certificates = new X509Certificate2Collection(
            anchors.Select(a =>
                X509Certificate2.CreateFromPem(a.Certificate))
                .ToArray());

        return Task.FromResult<X509Certificate2Collection?>(certificates);
    }

    public Task<int?> GetCommunityId(string community, CancellationToken token = default)
    {
        int? id;
        if (string.IsNullOrEmpty(community))
        {
            id = _communities.Where(c => c.Default)
                .Select(c => c.Id)
            .First();

            return Task.FromResult(id);
        }

        id = _communities.Where(c => c.Name == community)
            .Select(c => c.Id)
            .SingleOrDefault();

        return Task.FromResult(id);
    }

    public Task<ICollection<Secret>?> RolloverClientSecrets(ParsedSecret secret, CancellationToken token = default)
    {
        var rolled = false;
        using var activity = Tracing.StoreActivitySource.StartActivity();
        activity?.SetTag(Tracing.Properties.ClientId, secret.Id);

        var client = _clients.SingleOrDefault(c => c.ClientId == secret.Id);

        if (client != null)
        {
            var endCertificate = secret.GetUdapEndCert();

            if (endCertificate != null && endCertificate.NotBefore < DateTime.Now.ToUniversalTime()
                                       && endCertificate.NotAfter > DateTime.Now.ToUniversalTime())
            {
                foreach (var clientSecret in client.ClientSecrets.Where(cs =>
                             cs.Type == UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME ||
                             cs.Type == UdapServerConstants.SecretTypes.UDAP_COMMUNITY))
                {
                    clientSecret.Expiration = endCertificate.NotAfter.ToUniversalTime();
                    rolled = true;
                }
            }
        }

        activity?.SetTag("Rolled", rolled);
        return Task.FromResult(client?.ClientSecrets);
    }
}
