using System.Security.Cryptography.X509Certificates;
using Udap.Common.Models;

namespace Udap.Server.Storage.Stores;

/// <summary>
/// UDAP store used for storage during registration
/// </summary>
public interface IUdapClientRegistrationStore
{
    Task<Duende.IdentityServer.Models.Client?> GetClient(Duende.IdentityServer.Models.Client client, CancellationToken token = default);

    Task<int> AddClient(Duende.IdentityServer.Models.Client client, CancellationToken token = default);

    Task<IEnumerable<Anchor>> GetAnchors(string? community, CancellationToken token = default);

    Task<X509Certificate2Collection?> GetRootCertificates(CancellationToken token = default);

    Task<X509Certificate2Collection?> GetAnchorsCertificates(string? community, CancellationToken token = default);
}