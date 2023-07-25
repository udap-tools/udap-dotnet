using System.Security.Cryptography.X509Certificates;
using Duende.IdentityServer.Models;
using Udap.Common.Models;

namespace Udap.Server.Storage.Stores;

/// <summary>
/// UDAP store used for storage during registration
/// </summary>
public interface IUdapClientRegistrationStore
{
    Task<Duende.IdentityServer.Models.Client?> GetClient(Duende.IdentityServer.Models.Client client, CancellationToken token = default);

    /// <summary>
    /// The UDAP store will key clients by joining specific named <see cref="Secret"/>s.
    /// Specifically the <see cref="UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME"/>
    /// where the X509 Subject Alt Name matches the secret value and the <see cref="UdapServerConstants.SecretTypes.UDAP_COMMUNITY"/>
    /// matches the registered community.
    /// </summary>
    /// <param name="client"></param>
    /// <param name="token"></param>
    /// <returns>Returns true if client is updated, false if created</returns>
    Task<bool> UpsertClient(Duende.IdentityServer.Models.Client client, CancellationToken token = default);

    /// <summary>
    /// Cancel registration by passing an empty grant_types claim.  The cancel registration will cancel the
    /// community specific registration based on the signed_software statement. 
    /// </summary>
    /// <param name="client"></param>
    /// <param name="token"></param>
    /// <returns>The number of clients deleted</returns>
    Task<int> CancelRegistration(Duende.IdentityServer.Models.Client client, CancellationToken token = default);

    Task<IEnumerable<Anchor>> GetAnchors(string? community, CancellationToken token = default);

    Task<IEnumerable<X509Certificate2>>? GetCommunityCertificates(long communityId, CancellationToken token = default);

    Task<X509Certificate2Collection?> GetIntermediateCertificates(CancellationToken token = default);

    Task<X509Certificate2Collection> GetAnchorsCertificates(string? community, CancellationToken token = default);
    Task<string?> GetCommunityId(string community, CancellationToken token = default);
}