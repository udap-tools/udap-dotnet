#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Duende.IdentityModel.Client;
using Microsoft.IdentityModel.Tokens;
using Udap.Client.Messages;
using Udap.Common.Authentication;
using Udap.Common.Certificates;
using Udap.Model;
using Udap.Model.Access;
using Udap.Model.Registration;

namespace Udap.Client;

public interface IUdapClient : IUdapClientEvents
{
    /// <summary>
    /// Query the UDAP well-known endpoint and validate the metadata.
    /// The metadata will contain a signed JWT.  The signed JWT will be validated.  The <see cref="DiscoveryPolicy"/> can
    /// be supplied to override the default policy but, it would not be typical.
    /// </summary>
    /// <param name="baseUrl"></param>
    /// <param name="community"></param>
    /// <param name="discoveryPolicy"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<UdapDiscoveryDocumentResponse> ValidateResource(
        string baseUrl,
        string? community = null,
        DiscoveryPolicy? discoveryPolicy = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Query the UDAP well-known endpoint, validate the metadata, and verify the trust chain
    /// using the supplied <see cref="ITrustAnchorStore"/> instead of the store registered in DI.
    /// </summary>
    /// <param name="baseUrl">The FHIR server base URL whose UDAP metadata will be fetched.</param>
    /// <param name="trustAnchorStore">An explicit trust anchor store to use for chain validation.</param>
    /// <param name="community">An optional UDAP community identifier to include in the metadata request.</param>
    /// <param name="discoveryPolicy">An optional policy to override default discovery endpoint validation.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>A <see cref="UdapDiscoveryDocumentResponse"/> containing the validated metadata or error details.</returns>
    Task<UdapDiscoveryDocumentResponse> ValidateResource(
        string baseUrl,
        ITrustAnchorStore? trustAnchorStore,
        string? community = null,
        DiscoveryPolicy? discoveryPolicy = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// The validated UDAP server metadata. Populated after a successful call to <see cref="ValidateResource"/>.
    /// </summary>
    UdapMetadata? UdapServerMetadata { get; set; }


    /// <summary>
    /// Register a TieredClient in the Authorization Server.
    /// Currently, it is not SAN aware.  It picks the first SAN.
    /// To pick a different community the client can add a community query parameter to the .
    /// </summary>
    /// <param name="redirectUrl"></param>
    /// <param name="certificates"></param>
    /// <param name="scopes"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<UdapDynamicClientRegistrationDocument> RegisterTieredClient(string redirectUrl,
        IEnumerable<X509Certificate2> certificates,
        string scopes,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Register a UdapClient in the Authorization Server with authorization_code flow.
    /// </summary>
    /// <param name="certificates"></param>
    /// <param name="scopes"></param>
    /// <param name="logo"></param>
    /// <param name="redirectUrl"></param>
    /// <param name="issuer">If issuer is supplied it will match try to match to a valid URI based subject alternative name from the X509Certificate</param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<UdapDynamicClientRegistrationDocument> RegisterAuthCodeClient(
        IEnumerable<X509Certificate2> certificates,
        string scopes,
        string logo,
        ICollection<string> redirectUrl,
        string? issuer = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Register a UdapClient in the Authorization Server with authorization_code flow.
    /// </summary>
    /// <param name="certificate"></param>
    /// <param name="scopes"></param>
    /// <param name="logo">optional</param>
    /// <param name="redirectUrl"></param>
    /// <param name="issuer">If issuer is supplied it will match try to match to a valid URI based subject alternative name from the X509Certificate</param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<UdapDynamicClientRegistrationDocument> RegisterAuthCodeClient(
        X509Certificate2 certificate,
        string scopes,
        string logo,
        ICollection<string> redirectUrl,
        string? issuer = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Register a UdapClient in the Authorization Server with client_credentials flow.
    /// </summary>
    /// <param name="certificates"></param>
    /// <param name="scopes"></param>
    /// <param name="logo"></param>
    /// <param name="issuer">If issuer is supplied it will match try to match to a valid URI based subject alternative name from the X509Certificate</param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<UdapDynamicClientRegistrationDocument> RegisterClientCredentialsClient(
        IEnumerable<X509Certificate2> certificates,
        string scopes,
        string? issuer = null,
        string? logo = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Register a UdapClient in the Authorization Server with client_credentials flow.
    /// </summary>
    /// <param name="certificate"></param>
    /// <param name="scopes"></param>
    /// <param name="logo">optional</param>
    /// <param name="issuer">If issuer is supplied it will match try to match to a valid URI based subject alternative name from the X509Certificate</param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<UdapDynamicClientRegistrationDocument> RegisterClientCredentialsClient(
        X509Certificate2 certificate,
        string scopes,
        string? issuer = null,
        string? logo = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Sends an authorization request using the specified parameters.
    /// </summary>
    /// <param name="request">The authorization request parameters.</param>
    /// <returns>The HTTP response from the authorization endpoint.</returns>
    Task<HttpResponseMessage> Authorize(AuthorizeRequest request);

    /// <summary>
    /// Sends an authorization request with individual parameters.
    /// </summary>
    [Obsolete("Use the Authorize(AuthorizeRequest) overload instead.")]
    Task<HttpResponseMessage> Authorize(
        string authorizationUrl,
        string clientId,
        string? responseType = null,
        string? scope = null,
        string? redirectUri = null,
        string? state = null,
        string? nonce = null,
        string? loginHint = null,
        string? acrValues = null,
        string? prompt = null,
        string? responseMode = null,
        string? codeChallenge = null,
        string? codeChallengeMethod = null,
        string? display = null,
        int? maxAge = null,
        string? uiLocales = null,
        string? idTokenHint = null,
        string? requestUri = null,
        object? extra = null);


    /// <summary>
    /// Generated PKCS and use in the authorization code flow.
    /// <a href="https://datatracker.ietf.org/doc/html/rfc7636"/>
    /// <a href="https://build.fhir.org/ig/HL7/fhir-udap-security-ig/b2b.html#obtaining-an-authorization-code"/> 
    /// <a href="https://build.fhir.org/ig/HL7/fhir-udap-security-ig/consumer.html#obtaining-an-authorization-code"/>
    /// </summary>
    Pkce GeneratePkce();

    /// <summary>
    /// Exchanges an authorization code for a token response using a UDAP-signed client assertion.
    /// </summary>
    /// <param name="tokenRequest">The authorization code token request containing the code, redirect URI, and client assertion.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>A <see cref="TokenResponse"/> from the authorization server's token endpoint.</returns>
    Task<TokenResponse> ExchangeCodeForTokenResponse(UdapAuthorizationCodeTokenRequest tokenRequest, CancellationToken cancellationToken = default);

    /// <summary>
    /// Exchanges an authorization code for an <see cref="OAuthTokenResponse"/>, suitable for ASP.NET Core authentication handlers.
    /// </summary>
    /// <param name="tokenRequest">The authorization code token request containing the code, redirect URI, and client assertion.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>An <see cref="OAuthTokenResponse"/> parsed from the token endpoint response.</returns>
    Task<OAuthTokenResponse> ExchangeCodeForAuthTokenResponse(UdapAuthorizationCodeTokenRequest tokenRequest, CancellationToken cancellationToken = default);
        
    /// <summary>
    /// Resolves the JSON Web Key Set from the authorization server's OIDC discovery document.
    /// </summary>
    /// <param name="request">An optional discovery document request; when null, uses the previously discovered token endpoint authority.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The signing keys published by the authorization server, or null if resolution fails.</returns>
    Task<IEnumerable<SecurityKey>?> ResolveJwtKeys(DiscoveryDocumentRequest? request = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Resolves the OpenID Connect discovery document from the authorization server.
    /// </summary>
    /// <param name="request">An optional discovery document request; when null, uses the previously discovered token endpoint authority.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The <see cref="DiscoveryDocumentResponse"/> containing the OIDC configuration.</returns>
    Task<DiscoveryDocumentResponse> ResolveOpenIdConfig(DiscoveryDocumentRequest? request = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes a cached AIA intermediate certificate by its download URL.
    /// Requires <see cref="ICertificateDownloadCache"/> to be registered in DI.
    /// </summary>
    /// <param name="url">The AIA URL used to download the intermediate certificate.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>A task that completes when the cache entry is removed.</returns>
    Task RemoveCachedIntermediateAsync(string url, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes a cached CRL by its distribution point URL.
    /// Requires <see cref="ICertificateDownloadCache"/> to be registered in DI.
    /// </summary>
    /// <param name="url">The CDP URL used to download the CRL.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>A task that completes when the cache entry is removed.</returns>
    Task RemoveCachedCrlAsync(string url, CancellationToken cancellationToken = default);
}