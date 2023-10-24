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
        DiscoveryPolicy? discoveryPolicy = null,
        CancellationToken token = default);

    Task<UdapDiscoveryDocumentResponse> ValidateResource(
        string baseUrl,
        ITrustAnchorStore? trustAnchorStore,
        string? community = null,
        DiscoveryPolicy? discoveryPolicy = null,
        CancellationToken token = default);

    UdapMetadata? UdapDynamicClientRegistrationDocument { get; set; }
    UdapMetadata? UdapServerMetaData { get; set; }


    /// <summary>
    /// Register a TieredClient in the Authorization Server.
    /// Currently it is not SAN aware.  It picks the first SAN.
    /// To pick a different community the client can add a community query parameter to the .
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

    /// <summary>
    /// Register a UdapClient in the Authorization Server with authorization_code flow.
    /// </summary>
    /// <param name="certificates"></param>
    /// <param name="scopes"></param>
    /// <param name="logo"></param>
    /// <param name="redirectUrl"></param>
    /// <param name="issuer">If issuer is supplied it will match try to match to a valid URI based subject alternative name from the X509Certificate</param>
    /// <param name="token"></param>
    /// <returns></returns>
    Task<UdapDynamicClientRegistrationDocument> RegisterAuthCodeClient(
        IEnumerable<X509Certificate2> certificates,
        string scopes,
        string logo,
        ICollection<string> redirectUrl,
        string? issuer = null, 
        CancellationToken token = default);

    /// <summary>
    /// Register a UdapClient in the Authorization Server with authorization_code flow.
    /// </summary>
    /// <param name="certificate"></param>
    /// <param name="scopes"></param>
    /// <param name="logo">optional</param>
    /// <param name="redirectUrl"></param>
    /// <param name="issuer">If issuer is supplied it will match try to match to a valid URI based subject alternative name from the X509Certificate</param>
    /// <param name="token"></param>
    /// <returns></returns>
    Task<UdapDynamicClientRegistrationDocument> RegisterAuthCodeClient(
        X509Certificate2 certificate,
        string scopes,
        string logo,
        ICollection<string> redirectUrl,
        string? issuer = null,
        CancellationToken token = default);

    /// <summary>
    /// Register a UdapClient in the Authorization Server with client_credentials flow.
    /// </summary>
    /// <param name="certificates"></param>
    /// <param name="scopes"></param>
    /// <param name="logo"></param>
    /// <param name="issuer">If issuer is supplied it will match try to match to a valid URI based subject alternative name from the X509Certificate</param>
    /// <param name="token"></param>
    /// <returns></returns>
    Task<UdapDynamicClientRegistrationDocument> RegisterClientCredentialsClient(
        IEnumerable<X509Certificate2> certificates,
        string scopes,
        string? issuer = null,
        string? logo = null,
        CancellationToken token = default);

    /// <summary>
    /// Register a UdapClient in the Authorization Server with client_credentials flow.
    /// </summary>
    /// <param name="certificate"></param>
    /// <param name="scopes"></param>
    /// <param name="logo">optional</param>
    /// <param name="issuer">If issuer is supplied it will match try to match to a valid URI based subject alternative name from the X509Certificate</param>
    /// <param name="token"></param>
    /// <returns></returns>
    Task<UdapDynamicClientRegistrationDocument> RegisterClientCredentialsClient(
        X509Certificate2 certificate,
        string scopes,
        string? issuer = null,
        string? logo = null,
        CancellationToken token = default);

    Task<TokenResponse> ExchangeCodeForTokenResponse(UdapAuthorizationCodeTokenRequest tokenRequest, CancellationToken token = default);

    Task<OAuthTokenResponse> ExchangeCodeForAuthTokenResponse(UdapAuthorizationCodeTokenRequest tokenRequest, CancellationToken token = default);
        
    Task<IEnumerable<SecurityKey>?> ResolveJwtKeys(DiscoveryDocumentRequest? request = null, CancellationToken cancellationToken = default);

    Task<DiscoveryDocumentResponse?> ResolveOpenIdConfig(DiscoveryDocumentRequest? request = null, CancellationToken cancellationToken = default);
}