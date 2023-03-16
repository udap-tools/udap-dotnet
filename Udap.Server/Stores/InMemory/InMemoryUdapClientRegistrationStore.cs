﻿#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Udap.Common;
using Udap.Common.Models;
using Udap.Server.Storage.Stores;

namespace Udap.Server.Stores.InMemory;

public class InMemoryUdapClientRegistrationStore : IUdapClientRegistrationStore
{
    private readonly ICollection<Duende.IdentityServer.Models.Client> _clients;
    private readonly IEnumerable<Community> _communities;
    private readonly IEnumerable<IntermediateCertificate> _intermediateCertificates;

    /// <summary>
    /// Initializes a new instance of the <see cref="InMemoryUdapClientRegistrationStore"/> class.
    /// </summary>
    /// <param name="clients"></param>
    /// <param name="communities"></param>
    /// <param name="intermediateCertificates"></param>
    public InMemoryUdapClientRegistrationStore(
        List<Duende.IdentityServer.Models.Client> clients,
        IEnumerable<Community> communities,
        IEnumerable<IntermediateCertificate> intermediateCertificates)
    {
        _clients = clients;
        _communities = communities;
        _intermediateCertificates = intermediateCertificates;
    }


    public Task<Duende.IdentityServer.Models.Client?> GetClient(Duende.IdentityServer.Models.Client client, CancellationToken token = default)
    {
        throw new NotImplementedException();
    }

    public Task<int> AddClient(Duende.IdentityServer.Models.Client client, CancellationToken token = default)
    {
        using var activity = Tracing.StoreActivitySource.StartActivity("InMemoryUdapClientRegistrationStore.AddClient");
        activity?.SetTag(Tracing.Properties.ClientId, client.ClientId);

        _clients.Add(client);

        return Task.FromResult(_clients.Count + 1);
    }

    public Task<IEnumerable<Anchor>> GetAnchors(string? community, CancellationToken token = default)
    {
        using var activity = Tracing.StoreActivitySource.StartActivity("InMemoryUdapClientRegistrationStore.GetAnchors");
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

    public Task<IEnumerable<X509Certificate2>>? GetCommunityCertificates(long communityId, CancellationToken token = default)
    {
        using var activity = Tracing.StoreActivitySource.StartActivity("UdapClientRegistrationStore.GetCommunityCertificates");
        activity?.SetTag(Tracing.Properties.CommunityId, communityId);

        var anchors = _communities
            .Where(c => c.Id == communityId && c.Anchors != null)
            .SelectMany(c => c.Anchors!)
            .ToList();

        if (!anchors.Any())
        {
            return null;
        }
        
        var encodedCerts = new List<X509Certificate2>();
        
        foreach (var anchor in anchors)
        {
            encodedCerts.Add(X509Certificate2.CreateFromPem(anchor.Certificate));
            if (anchor.IntermediateCertificates != null)
            {
                encodedCerts.AddRange(anchor.IntermediateCertificates.Select(i => X509Certificate2.CreateFromPem(i.Certificate)));
            }
        }

        return Task.FromResult(encodedCerts.AsEnumerable())!;
    }

    public Task<X509Certificate2Collection?> GetIntermediateCertificates(CancellationToken token = default)
    {
        using var activity = Tracing.StoreActivitySource.StartActivity("InMemoryUdapClientRegistrationStore.GetRootCertificates");

        var roots = _intermediateCertificates.ToList();
        var certificates = new X509Certificate2Collection(roots
                    .Select(a => X509Certificate2.CreateFromPem(a.Certificate)).ToArray());

        return Task.FromResult<X509Certificate2Collection?>(certificates);
    }

    public Task<X509Certificate2Collection?> GetAnchorsCertificates(string? community, CancellationToken token = default)
    {
        using var activity = Tracing.StoreActivitySource.StartActivity("InMemoryUdapClientRegistrationStore.GetAnchorsCertificates");
        activity?.SetTag(Tracing.Properties.Community, community);

        var anchors = GetAnchors(community, token).Result.ToList();

        if (!anchors.Any())
        {
            return Task.FromResult<X509Certificate2Collection?>(null);
        }

        var certificates = new X509Certificate2Collection(
            anchors.Select(a =>
                X509Certificate2.CreateFromPem(a.Certificate))
                .ToArray());

        return Task.FromResult<X509Certificate2Collection?>(certificates);
    }
}
