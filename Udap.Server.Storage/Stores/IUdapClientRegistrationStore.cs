#region (c) 2025 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Udap.Common.Models;

namespace Udap.Server.Storage.Stores;

/// <summary>
/// UDAP store used for storage during registration
/// </summary>
public interface IUdapClientRegistrationStore
{
    Task<Duende.IdentityServer.Models.Client?> GetClient(Duende.IdentityServer.Models.Client client, CancellationToken token = default);

    /// <summary>
    /// The UDAP store will key clients by joining specific named <see cref="Duende.IdentityServer.Models.Secret"/>s.
    /// Specifically the <see cref="UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME"/>
    /// where the X509 Subject Alt Name matches the secret value and the <see cref="UdapServerConstants.SecretTypes.UDAP_COMMUNITY"/>
    /// matches the registered community.
    /// </summary>
    /// <param name="client"></param>
    /// <param name="token"></param>
    /// <returns>Returns true if client is updated, false if created</returns>
    Task<bool> UpsertClient(Duende.IdentityServer.Models.Client client, CancellationToken token = default);

    Task<bool> UpsertTieredClient(TieredClient client, CancellationToken token = default);

    Task<TieredClient?> FindTieredClientById(string clientId, CancellationToken token = default);

    /// <summary>
    /// Finds a registered Tiered (federated) client by the IdP's base URL — the key
    /// <see cref="UpsertTieredClient"/> stores records under. Use this from the Tiered OAuth
    /// challenge, where the lookup value is the IdP base URL, not the issued client_id.
    /// Returns null when no matching record exists.
    /// </summary>
    Task<TieredClient?> FindTieredClientByIdPBaseUrl(string idpBaseUrl, CancellationToken token = default);

    /// <summary>
    /// Finds the Tiered client registered at <paramref name="idpBaseUrl"/> for <paramref name="communityId"/>, the key
    /// <see cref="UpsertTieredClient"/> stores records under. Returns null when there is none.
    /// The default implementation filters <see cref="FindTieredClientByIdPBaseUrl"/>; stores should override it with
    /// a query on both values.
    /// </summary>
    async Task<TieredClient?> FindTieredClient(string idpBaseUrl, int communityId, CancellationToken token = default)
    {
        var client = await FindTieredClientByIdPBaseUrl(idpBaseUrl, token);
        return client != null && client.CommunityId == communityId ? client : null;
    }

    /// <summary>
    /// Finds the Tiered client with <paramref name="clientId"/> registered at <paramref name="idpBaseUrl"/>. Two IdPs
    /// can issue the same client_id, so a callback looks its registration up by both. Returns null when there is none.
    /// The default implementation filters <see cref="FindTieredClientById"/>; stores should override it with a query
    /// on both values.
    /// </summary>
    async Task<TieredClient?> FindTieredClientById(string clientId, string idpBaseUrl, CancellationToken token = default)
    {
        var client = await FindTieredClientById(clientId, token);
        return client != null && string.Equals(client.IdPBaseUrl, idpBaseUrl, StringComparison.Ordinal) ? client : null;
    }
    /// <summary>
    /// Cancel registration by passing an empty grant_types claim.  The cancel registration will cancel the
    /// community specific registration based on the signed_software statement. 
    /// </summary>
    /// <param name="client"></param>
    /// <param name="token"></param>
    /// <returns>The number of clients deleted</returns>
    Task<int> CancelRegistration(Duende.IdentityServer.Models.Client client, CancellationToken token = default);

    Task<IEnumerable<Anchor>> GetAnchors(string? community, CancellationToken token = default);

    Task<IEnumerable<X509Certificate2>?> GetCommunityCertificates(long communityId, CancellationToken token = default);

    Task<X509Certificate2Collection?> GetIntermediateCertificates(CancellationToken token = default);

    Task<X509Certificate2Collection?> GetAnchorsCertificates(string? community, CancellationToken token = default);
    Task<int?> GetCommunityId(string community, CancellationToken token = default);

    /// <summary>
    /// Reverse lookup: resolves a community name (URI) from a community ID.
    /// </summary>
    Task<string?> GetCommunityName(string communityId, CancellationToken token = default);

    Task<ICollection<Duende.IdentityServer.Models.Secret>?> RolloverClientSecrets(ParsedSecret secret, CancellationToken token = default);
}