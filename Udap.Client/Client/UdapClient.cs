﻿#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using IdentityModel.Client;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Udap.Client.Authentication;
using Udap.Client.Client.Extensions;
using Udap.Client.Client.Messages;
using Udap.Client.Configuration;
using Udap.Client.Extensions;
using Udap.Common.Certificates;
using Udap.Common.Extensions;
using Udap.Model;
using Udap.Model.Access;
using Udap.Model.Registration;
using Udap.Model.Statement;


#if NET7_0_OR_GREATER
using System.Net.Http.Headers;
#endif
// using Microsoft.AspNetCore.Authentication.OAuth;

namespace Udap.Client.Client
{
    public class UdapClient : IUdapClient
    {
        private readonly HttpClient _httpClient;
        private readonly UdapClientDiscoveryValidator _clientDiscoveryValidator;
        private readonly UdapClientOptions _udapClientOptions;
        private DiscoveryPolicy _discoveryPolicy;
        private readonly ILogger<UdapClient> _logger;

        public UdapClient(
            HttpClient httpClient,
            UdapClientDiscoveryValidator clientDiscoveryValidator,
            IOptionsMonitor<UdapClientOptions> udapClientOptions,
            ILogger<UdapClient> logger,
            DiscoveryPolicy? discoveryPolicy = null)
        {
            _httpClient = httpClient;
            _clientDiscoveryValidator = clientDiscoveryValidator;
            _clientDiscoveryValidator.TokenError += NotifyTokenError;
            _udapClientOptions = udapClientOptions.CurrentValue;
            _logger = logger;
            _discoveryPolicy = discoveryPolicy ?? DiscoveryPolicy.DefaultMetadataServerPolicy();
        }

        public UdapMetadata? UdapDynamicClientRegistrationDocument { get; set; }
        public UdapMetadata? UdapServerMetaData { get; set; }

        /// <inheritdoc/>
        public event Action<X509Certificate2>? Untrusted
        {
            add => _clientDiscoveryValidator.Untrusted += value;
            remove => _clientDiscoveryValidator.Untrusted -= value;
        }

        /// <inheritdoc/>
        public event Action<X509ChainElement>? Problem
        {
            add => _clientDiscoveryValidator.Problem += value;
            remove => _clientDiscoveryValidator.Problem -= value;
        }

        /// <inheritdoc/>
        public event Action<X509Certificate2, Exception>? Error
        {
            add => _clientDiscoveryValidator.Error += value;
            remove => _clientDiscoveryValidator.Error -= value;
        }

        /// <inheritdoc/>
        public event Action<string>? TokenError;

        //TODO the certs include the private key.  This needs work.  It should be a service or struct that
        // allows an abstraction in "Sign" so that a vault or HSM can sign the metadata.
        public async Task<UdapDynamicClientRegistrationDocument> RegisterTieredClient(string redirectUrl,
            IEnumerable<X509Certificate2> certificates,
            string scopes,
            CancellationToken token = default)
        {
            if (this.UdapServerMetaData == null)
            {
                throw new Exception("Tiered OAuth Client: UdapServerMetaData is null.  Call ValidateResource first.");
            }

            try
            {
                var resultDocument = await RegisterAuthCodeFlow(certificates, scopes, _udapClientOptions.TieredOAuthClientLogo, [redirectUrl], null, token);

                if(string.IsNullOrEmpty(resultDocument.GetError()))
                {
                    _logger.LogWarning("Tiered OAuth Client: Unable to register client to {RegistrationEndpoint}", this.UdapServerMetaData?.RegistrationEndpoint);
                }

                return resultDocument;
            }
            catch(Exception ex)
            {
                _logger.LogError(ex, "Tiered OAuth Client: Unable to register client to {RegistrationEndpoint}",
                        this.UdapServerMetaData?.RegistrationEndpoint);
                throw;
            }
        }

        /// <inheritdoc />
        public async Task<UdapDynamicClientRegistrationDocument> RegisterAuthCodeClient(
            IEnumerable<X509Certificate2> certificates,
            string scopes,
            string logo,
            ICollection<string> redirectUrl,
            string? issuer,
            CancellationToken token = default)
        {
            if (this.UdapServerMetaData == null)
            {
                throw new Exception("UdapClient: UdapServerMetaData is null.  Call ValidateResource first.");
            }

            try
            {
                var resultDocument = await RegisterAuthCodeFlow(certificates, scopes, logo, redirectUrl, issuer, token);

                if (string.IsNullOrEmpty(resultDocument.GetError()))
                {
                    _logger.LogWarning("UdapClient: Unable to register authorization_code client to {RegistrationEndpoint}", this.UdapServerMetaData?.RegistrationEndpoint);
                }

                return resultDocument;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "UdapClient: Unable to register authorization_code client to {RegistrationEndpoint}",
                    this.UdapServerMetaData?.RegistrationEndpoint);
                throw;
            }
        }

        /// <inheritdoc />
        public Task<UdapDynamicClientRegistrationDocument> RegisterAuthCodeClient(
            X509Certificate2 certificate, 
            string scopes,
            string logo,
            ICollection<string> redirectUrl,
            string? issuer,
            CancellationToken token = default)
        {
            return this.RegisterAuthCodeClient(
                new List<X509Certificate2> { certificate },
                scopes, 
                logo,
                redirectUrl,
                issuer,
                token
            );
        }

        /// <inheritdoc />
        public async Task<UdapDynamicClientRegistrationDocument> RegisterClientCredentialsClient(
            IEnumerable<X509Certificate2> certificates,
            string scopes,
            string? issuer,
            string? logo,
            CancellationToken token = default)
        {
            if (this.UdapServerMetaData == null)
            {
                throw new Exception("UdapClient: UdapServerMetaData is null.  Call ValidateResource first.");
            }

            try
            {
                var resultDocument = await RegisterClientCredFlow(certificates, scopes, logo, issuer, token);

                if (string.IsNullOrEmpty(resultDocument.GetError()))
                {
                    _logger.LogWarning("UdapClient: Unable to register client_credentials client to {RegistrationEndpoint}", this.UdapServerMetaData?.RegistrationEndpoint);
                }

                return resultDocument;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "UdapClient: Unable to register client_credentials client to {RegistrationEndpoint}",
                    this.UdapServerMetaData?.RegistrationEndpoint);
                throw;
            }
        }

        //// <inheritdoc />
        public Task<UdapDynamicClientRegistrationDocument> RegisterClientCredentialsClient(
            X509Certificate2 certificate, 
            string scopes,
            string? issuer, 
            string? logo,
            CancellationToken token = default)
        {
            return this.RegisterClientCredentialsClient(
                new List<X509Certificate2> { certificate },
                scopes, 
                logo,
                issuer,
                token
            );
        }

        public Task<HttpResponseMessage> Authorize(
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
            object? extra = null)
        {
            var url = new RequestUrl(authorizationUrl).CreateAuthorizeUrl(
                clientId: clientId,
                responseType: responseType,
                scope: scope,
                redirectUri: redirectUri,
                state: state,
                nonce: nonce,
                loginHint: loginHint,
                acrValues: acrValues,
                responseMode: responseMode,
                codeChallenge: codeChallenge,
                codeChallengeMethod: codeChallengeMethod,
                display: display,
                maxAge: maxAge,
                uiLocales: uiLocales,
                idTokenHint: idTokenHint,
                requestUri: requestUri,
                extra: extra == null ? null : Parameters.FromObject(extra)
                );
            
            return _httpClient.GetAsync(url);
        }

        /// <summary>
        /// UdapClient is enabled for PKCE by default in constructor.  This can be overridden by setting this property to false or at construction.
        /// Overriding at construction time will avoid the allocation of CodeVerifier and CodeChallenge.
        /// <a href="https://datatracker.ietf.org/doc/html/rfc7636"/>,
        /// <a href="https://build.fhir.org/ig/HL7/fhir-udap-security-ig/b2b.html#obtaining-an-authorization-code" /> and 
        /// <a href="https://build.fhir.org/ig/HL7/fhir-udap-security-ig/consumer.html#obtaining-an-authorization-code"/>
        /// </summary>
        public Pkce GeneratePkce()
        {
            return new Pkce();
        }
        
        
        /// <summary>
        /// Sends a token request using the authorization_code grant type.
        /// </summary>
        /// <param name="tokenRequest">The request.</param>
        /// <param name="token">The cancellation token.</param>
        /// <returns><see cref="TokenResponse"/></returns>
        public async Task<TokenResponse> ExchangeCodeForTokenResponse(
            UdapAuthorizationCodeTokenRequest tokenRequest, 
            CancellationToken token = default)
        {
            var response = await _httpClient.ExchangeCodeForTokenResponse(tokenRequest, token);
            _logger.LogDebug("OAuth Client Access Token: {TokenResponse}", JsonSerializer.Serialize(response));
            return response;
        }
        
        /// <summary>
        /// Sends a token request using the authorization_code grant type.  Typically used when called
        /// from a OAuthHandler implementation.  TieredOAuthAuthenticationHandler is an implementation that
        /// calls this method.
        /// </summary>
        /// <param name="tokenRequest">The request.</param>
        /// <param name="token">The cancellation token.</param>
        /// <returns><see cref="OAuthTokenResponse"/></returns>
        public async Task<OAuthTokenResponse> ExchangeCodeForAuthTokenResponse(
            UdapAuthorizationCodeTokenRequest tokenRequest, 
            CancellationToken token = default)
        {
            var response = await _httpClient.ExchangeCodeForAuthTokenResponse(tokenRequest, token);

            _logger.LogDebug("Tiered OAuth Client Access Token: {TokenResponse}", JsonSerializer.Serialize(response));
            return response;
        }

        /// <summary>
        /// Client dynamically supplying the trustAnchorStore
        /// </summary>
        /// <param name="baseUrl"></param>
        /// <param name="trustAnchorStore"></param>
        /// <param name="community"></param>
        /// <param name="discoveryPolicy"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        public Task<UdapDiscoveryDocumentResponse> ValidateResource(
            string baseUrl,
            ITrustAnchorStore? trustAnchorStore,
            string? community = null,
            DiscoveryPolicy? discoveryPolicy = null, 
            CancellationToken token = default)
        {
            return InternalValidateResource(baseUrl, trustAnchorStore, community, discoveryPolicy, token);
        }

        /// <summary>
        /// Typical dependency injection client where the trust anchors are loaded from a static resource.
        /// </summary>
        /// <param name="baseUrl"></param>
        /// <param name="community"></param>
        /// <param name="discoveryPolicy"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="UnauthorizedAccessException"></exception>
        public Task<UdapDiscoveryDocumentResponse> ValidateResource(
            string baseUrl,
            string? community,
            DiscoveryPolicy? discoveryPolicy,
            CancellationToken token = default)
        {
            return InternalValidateResource(baseUrl, null, community, discoveryPolicy, token);
        }

        private async Task<UdapDiscoveryDocumentResponse> InternalValidateResource(
            string baseUrl,
            ITrustAnchorStore? trustAnchorStore,
            string? community,
            DiscoveryPolicy? discoveryPolicy, 
            CancellationToken token = default)
         {

            baseUrl.AssertUri();

            try
            {
                if (discoveryPolicy != null)
                {
                    _discoveryPolicy = discoveryPolicy;

                }

                var disco = await _httpClient.GetUdapDiscoveryDocument(
                    new UdapDiscoveryDocumentRequest()
                    {
                        Address = baseUrl,
                        Community = community,
                        Policy = _discoveryPolicy
                    }, cancellationToken: token);

                if (disco.HttpStatusCode == HttpStatusCode.OK && !disco.IsError)
                {
                    UdapServerMetaData = disco.Json?.Deserialize<UdapMetadata>();
                    _logger.LogDebug("UdapServerMetaData: {UdapServerMetaDataJson}", UdapServerMetaData?.SerializeToJson());

                    if (baseUrl.Contains(UdapConstants.Discovery.DiscoveryEndpoint))
                    {
                        var i = baseUrl.IndexOf(UdapConstants.Discovery.DiscoveryEndpoint, StringComparison.Ordinal);
                        baseUrl = baseUrl.Substring(0, i).RemoveTrailingSlash();
                    }

                    if (UdapServerMetaData == null)
                    {
                        throw new NullReferenceException("Missing UDAP Metadata");
                    }

                    if (!await _clientDiscoveryValidator.ValidateJwtToken(UdapServerMetaData, baseUrl))
                    {
                        throw new SecurityTokenInvalidTypeException("Failed JWT Token Validation");
                    }

                    if (!await _clientDiscoveryValidator.ValidateTrustChain(community, trustAnchorStore))
                    {
                        throw new UnauthorizedAccessException("Failed Trust Chain Validation");
                    }
                }
                else
                {
                    NotifyTokenError(disco.Error ?? "Unknown Error");
                }

                return disco;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed validating resource metadata");
                return ProtocolResponse.FromException<UdapDiscoveryDocumentResponse>(ex);
            }
         }

        
        public async Task<IEnumerable<SecurityKey>?> ResolveJwtKeys(DiscoveryDocumentRequest? request = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(request);

            //TODO: Cache Discovery Document?
            var disco = await _httpClient.GetDiscoveryDocumentAsync(request, cancellationToken: cancellationToken);
           
            if (disco.HttpStatusCode != HttpStatusCode.OK || disco.IsError)
            {
                throw new Exception("Failed to retrieve discovery document: " + disco.Error);
            }

            IEnumerable<SecurityKey>? keys = disco.KeySet?.Keys
                .Where(x => x.N != null && x.E != null)
                .Select(x => {
                    var rsa = new RSAParameters
                    {
                        Exponent = Base64UrlEncoder.DecodeBytes(x.E),
                        Modulus = Base64UrlEncoder.DecodeBytes(x.N),
                    };

                    return new RsaSecurityKey(rsa)
                    {
                        KeyId = x.Kid
                    };
                });

            return keys;
        }

        public async Task<DiscoveryDocumentResponse> ResolveOpenIdConfig(DiscoveryDocumentRequest? request = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(request);

            //TODO: Cache Discovery Document?
            var disco = await _httpClient.GetDiscoveryDocumentAsync(request, cancellationToken: cancellationToken);

            if (disco.HttpStatusCode != HttpStatusCode.OK || disco.IsError)
            {
                throw new Exception("Failed to retrieve discovery document: " + disco.Error);
            }

            return disco;
        }


        private void NotifyTokenError(string message)
        {
            _logger.LogWarning("Token error occurred: {ErrorMessage}", message);

            if (TokenError != null)
            {
                try
                {
                    TokenError(message);
                }
                catch
                {
                    // ignored
                }
            }
        }

        private async Task<UdapDynamicClientRegistrationDocument> RegisterAuthCodeFlow(
            IEnumerable<X509Certificate2> certificates, 
            string scopes, 
            string logoUrl,
            ICollection<string>? redirectUrls,
            string? issuer,
            CancellationToken token)
        {
            var x509Certificates = certificates.ToList();
            if (certificates == null || x509Certificates.Count == 0)
            {
                throw new Exception("Tiered OAuth: No client certificates provided.");
            }

            if (string.IsNullOrEmpty(_udapClientOptions.ClientName))
            {
                throw new ArgumentException("UdapClientOptions.ClientName is empty");
            }

            UdapDynamicClientRegistrationDocument? resultDocument;

            foreach (var clientCert in x509Certificates)
            {
                _logger.LogDebug("Using certificate {CertificateSubjectName} [ {CertificateThumbprint} ]", clientCert.SubjectName.Name, clientCert.Thumbprint);

                var builder = UdapDcrBuilderForAuthorizationCode
                    .Create(clientCert)
                    .WithAudience(this.UdapServerMetaData?.RegistrationEndpoint)
                    .WithExpiration(TimeSpan.FromMinutes(5))
                    .WithJwtId()
                    .WithClientName(_udapClientOptions.ClientName)
                    .WithLogoUri(logoUrl)
                    .WithContacts(_udapClientOptions.Contacts)
                    .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
                    .WithScope(scopes)
                    .WithResponseTypes(["code"])
                    .WithRedirectUrls(redirectUrls);

                if (!string.IsNullOrEmpty(issuer))
                {
                    builder.WithIssuer(new Uri(issuer));
                }

                var signedSoftwareStatement = builder.BuildSoftwareStatement();

                var requestBody = new UdapRegisterRequest
                (
                    signedSoftwareStatement,
                    UdapConstants.UdapVersionsSupportedValue
                    // Array.Empty<string>()
                );

                // New StringContent constructor taking a MediaTypeHeaderValue to ensure CharSet can be controlled
                // by the caller.  
                // Good historical conversations.  
                // https://github.com/dotnet/runtime/pull/63231
                // https://github.com/dotnet/runtime/issues/17036
                //
#if NET7_0_OR_GREATER
                var content = new StringContent(
                    JsonSerializer.Serialize(requestBody),
                    new MediaTypeHeaderValue("application/json"));
#else
                    var content = new StringContent(JsonSerializer.Serialize(requestBody), null, "application/json");
                                        content.Headers.ContentType!.CharSet = string.Empty;
#endif

                var response = await _httpClient.PostAsync(this.UdapServerMetaData?.RegistrationEndpoint, content, token);

                if (response.StatusCode == HttpStatusCode.NotFound)
                {
                    return new UdapDynamicClientRegistrationDocument
                    {
                        { "error", "Not Found(404)" },
                        { "error_description", $"Registration endpoint not found {this.UdapServerMetaData?.RegistrationEndpoint}" }
                    };
                }

                if (((int)response.StatusCode) < 500)
                {
                    resultDocument =
                        await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>(
                            cancellationToken: token);

                    resultDocument ??= new UdapDynamicClientRegistrationDocument
                        {
                            { "error", "Unknown error" },
                            { "error_description", response.StatusCode }
                        };

                    return resultDocument;
                }
            }

            resultDocument = new UdapDynamicClientRegistrationDocument
            {
                { "error", "Unknown error" },
                { "error_description", "Failed to register with all client certificates" }
            };

            return resultDocument;
        }


        private async Task<UdapDynamicClientRegistrationDocument> RegisterClientCredFlow(
           IEnumerable<X509Certificate2> certificates,
           string scopes,
           string? issuer,
           string? logoUrl,
           CancellationToken token)
        {
            var x509Certificates = certificates.ToList();
            if (certificates == null || x509Certificates.Count == 0)
            {
                throw new Exception("Tiered OAuth: No client certificates provided.");
            }

            if (string.IsNullOrEmpty(_udapClientOptions.ClientName))
            {
                throw new ArgumentException("UdapClientOptions.ClientName is empty");
            }

            UdapDynamicClientRegistrationDocument? resultDocument;

            foreach (var clientCert in x509Certificates)
            {
                _logger.LogDebug("Using certificate {CertificateSubjectName} [{CertificateThumbprint}]", clientCert.SubjectName.Name, clientCert.Thumbprint);

                var builder = UdapDcrBuilderForClientCredentials
                    .Create(clientCert)
                    .WithAudience(this.UdapServerMetaData?.RegistrationEndpoint)
                    .WithExpiration(TimeSpan.FromMinutes(5))
                    .WithJwtId()
                    .WithClientName(_udapClientOptions.ClientName)
                    .WithContacts(_udapClientOptions.Contacts)
                    .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
                    .WithScope(scopes);

                if (logoUrl != null)
                {
                    builder.WithLogoUri(logoUrl);
                }

                if (!string.IsNullOrEmpty(issuer))
                {
                    builder.WithIssuer(new Uri(issuer));
                }

                var document = builder.Build();

                var signedSoftwareStatement =
                    SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                        .Create(clientCert, document)
                        .Build();

                var requestBody = new UdapRegisterRequest
                (
                    signedSoftwareStatement,
                    UdapConstants.UdapVersionsSupportedValue
                // Array.Empty<string>()
                );

                // New StringContent constructor taking a MediaTypeHeaderValue to ensure CharSet can be controlled
                // by the caller.  
                // Good historical conversations.  
                // https://github.com/dotnet/runtime/pull/63231
                // https://github.com/dotnet/runtime/issues/17036
                //
#if NET7_0_OR_GREATER
                var content = new StringContent(
                    JsonSerializer.Serialize(requestBody),
                    new MediaTypeHeaderValue("application/json"));
#else
                    var content = new StringContent(JsonSerializer.Serialize(requestBody), null, "application/json");
                                        content.Headers.ContentType!.CharSet = string.Empty;
#endif

                var response = await _httpClient.PostAsync(this.UdapServerMetaData?.RegistrationEndpoint, content, token);

                if (((int)response.StatusCode) < 500)
                {
                    resultDocument =
                        await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>(
                            cancellationToken: token);

                    resultDocument ??= new UdapDynamicClientRegistrationDocument
                        {
                            { "error", "Unknown error" },
                            { "error_description", response.StatusCode }
                        };

                    return resultDocument;
                }
            }

            resultDocument = new UdapDynamicClientRegistrationDocument
            {
                { "error", "Unknown error" },
                { "error_description", "Failed to register with all client certificates" }
            };

            return resultDocument;
        }
    }
}
