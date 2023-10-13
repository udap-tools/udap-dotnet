#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Net.Http;
using System.Text.Json.Serialization;
using System.Text.Json;
using System.Threading.Tasks;

using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using IdentityModel.Client;
// using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Udap.Client.Client.Extensions;
using Udap.Client.Client.Messages;
using Udap.Client.Configuration;
using Udap.Client.Extensions;
using Udap.Common.Certificates;
using Udap.Model;
using Udap.Model.Access;
using Udap.Model.Registration;
using Udap.Model.Statement;
using Microsoft.AspNetCore.Authentication.OAuth;

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
        // allows a an abstraction in "Sign" so that a vault or HSM can sign the metadata.
        public async Task<UdapDynamicClientRegistrationDocument> RegisterTieredClient(string redirectUrl,
            IEnumerable<X509Certificate2> certificates,
            string scopes,
            CancellationToken token = default)
        {
            if (this.UdapServerMetaData == null)
            {
                throw new Exception("Tiered OAuth: UdapServerMetaData is null.  Call ValidateResource first.");
            }

            try
            {
                var x509Certificates = certificates.ToList();
                if (certificates == null || !x509Certificates.Any())
                {
                    throw new Exception("Tiered OAuth: No client certificates provided.");
                }

                foreach (var clientCert in x509Certificates)
                {
                    _logger.LogDebug($"Using certificate {clientCert.SubjectName.Name} [ {clientCert.Thumbprint} ]");

                    var document = UdapDcrBuilderForAuthorizationCode
                        .Create(clientCert)
                        .WithAudience(this.UdapServerMetaData?.RegistrationEndpoint)
                        .WithExpiration(TimeSpan.FromMinutes(5))
                        .WithJwtId()
                        .WithClientName(_udapClientOptions.ClientName)
                        //Todo get logo from client registration, maybe Client object.  But still nee to retain logo in clientproperties during registration
                        .WithLogoUri("https://udaped.fhirlabs.net/images/udap-dotnet-auth-server.png")
                        .WithContacts(_udapClientOptions.Contacts)
                        .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues
                            .TokenEndpointAuthMethodValue)
                        .WithScope(scopes)
                        .WithResponseTypes(new List<string> { "code" })
                        .WithRedirectUrls(new List<string> { redirectUrl })
                        .Build();
                    

                    var signedSoftwareStatement =
                        SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                            .Create(clientCert, document)
                            .Build();

                    var requestBody = new UdapRegisterRequest
                    (
                        signedSoftwareStatement,
                        UdapConstants.UdapVersionsSupportedValue
                        // new string[] { }
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
                        new MediaTypeHeaderValue("application/json") );
#else
                    var content = new StringContent(JsonSerializer.Serialize(requestBody), null, "application/json");
                                        content.Headers.ContentType!.CharSet = string.Empty;
                    #endif

                    var response = await _httpClient.PostAsync(this.UdapServerMetaData?.RegistrationEndpoint, content, token);

                    if (((int)response.StatusCode) < 500)
                    {
                        var resultDocument =
                            await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>(cancellationToken: token);

                        return resultDocument;
                    }
                }
            }
            catch(Exception ex)
            {
                _logger.LogError(ex, "Tiered OAuth: Unable to register client to {RegistrationEndpoint}",
                        this.UdapServerMetaData?.RegistrationEndpoint);
                throw;
            }

            
            _logger.LogWarning("Tiered OAuth: Unable to register client to {RegistrationEndpoint}", this.UdapServerMetaData?.RegistrationEndpoint);
            // Todo: typed exception? or null return etc...
            throw new Exception($"Tiered OAuth: Unable to register client to {this.UdapServerMetaData?.RegistrationEndpoint}");
        }

        /// <summary>
        /// Sends a token request using the authorization_code grant type.
        /// </summary>
        /// <param name="tokenRequest">The request.</param>
        /// <param name="token">The cancellation token.</param>
        /// <returns></returns>
        public async Task<TokenResponse> ExchangeCodeForTokenResponse(
            UdapAuthorizationCodeTokenRequest tokenRequest, 
            CancellationToken token = default)
        {
            var response = await _httpClient.ExchangeCodeForTokenResponse(tokenRequest, token);
        
            return response;
        }

        /// <summary>
        /// Sends a token request using the authorization_code grant type.  Typically used when called from
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
        /// <returns></returns>
        public Task<UdapDiscoveryDocumentResponse> ValidateResource(
            string baseUrl,
            ITrustAnchorStore? trustAnchorStore,
            string? community = null,
            DiscoveryPolicy? discoveryPolicy = null)
        {
            return InternalValidateResource(baseUrl, trustAnchorStore, community, discoveryPolicy);
        }

        /// <summary>
        /// Typical dependency injection client where the trust anchors are loaded from a static resource.
        /// </summary>
        /// <param name="baseUrl"></param>
        /// <param name="community"></param>
        /// <param name="discoveryPolicy"></param>
        /// <returns></returns>
        /// <exception cref="UnauthorizedAccessException"></exception>
        public async Task<UdapDiscoveryDocumentResponse> ValidateResource(
            string baseUrl,
            string? community,
            DiscoveryPolicy? discoveryPolicy)
        {
            return await InternalValidateResource(baseUrl, null, community, discoveryPolicy);
        }

        private async Task<UdapDiscoveryDocumentResponse> InternalValidateResource(
            string baseUrl,
            ITrustAnchorStore? trustAnchorStore,
            string? community,
            DiscoveryPolicy? discoveryPolicy)
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
                    });

                if (disco.HttpStatusCode == HttpStatusCode.OK && !disco.IsError)
                {
                    UdapServerMetaData = disco.Json.Deserialize<UdapMetadata>();
                    _logger.LogDebug(UdapServerMetaData?.SerializeToJson());

                    if (!await _clientDiscoveryValidator.ValidateJwtToken(UdapServerMetaData!, baseUrl))
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

        public async Task<DiscoveryDocumentResponse?> ResolveOpenIdConfig(DiscoveryDocumentRequest? request = null, CancellationToken cancellationToken = default)
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
            _logger.LogWarning(message);

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
    }
    
}
