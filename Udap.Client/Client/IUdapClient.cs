#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.IdentityModel.Tokens;
using Udap.Client.Client.Messages;
using Udap.Common.Certificates;
using Udap.Model;
using Udap.Model.Access;
using Udap.Model.Registration;

namespace Udap.Client.Client;

public interface IUdapClient : IUdapClientEvents
{
    //TODO Cancellation Token add...
    Task<UdapDiscoveryDocumentResponse> ValidateResource(
        string baseUrl,
        string? community = null,
        DiscoveryPolicy? discoveryPolicy = null);

    Task<UdapDiscoveryDocumentResponse> ValidateResource(
        string baseUrl,
        ITrustAnchorStore? trustAnchorStore,
        string? community = null,
        DiscoveryPolicy? discoveryPolicy = null);

    UdapMetadata? UdapDynamicClientRegistrationDocument { get; set; }
    UdapMetadata? UdapServerMetaData { get; set; }

        
    /// <summary>
    /// Register a TieredClient in the Authorization Server.
    /// Currently it is not SAN and Community aware.  It picks the first SAN.
    /// </summary>
    /// <param name="redirectUrl"></param>
    /// <param name="certificates"></param>
    /// <param name="scopes"></param>
    /// <param name="token"></param>
    /// <returns></returns>
    Task<UdapDynamicClientRegistrationDocument> RegisterTieredClient(string redirectUrl,
        IEnumerable<X509Certificate2> certificates,
        string scopes,
        CancellationToken token = default);

    Task<OAuthTokenResponse> ExchangeCodeForAuthTokenResponse(UdapAuthorizationCodeTokenRequest tokenRequest, CancellationToken token = default);
        
    Task<IEnumerable<SecurityKey>?> ResolveJwtKeys(DiscoveryDocumentRequest? request = null, CancellationToken cancellationToken = default);

    Task<DiscoveryDocumentResponse?> ResolveOpenIdConfig(DiscoveryDocumentRequest? request = null, CancellationToken cancellationToken = default);
}