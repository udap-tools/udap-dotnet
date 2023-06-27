#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Hl7.Fhir.Rest;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Udap.Client.Client.Extensions;
using Udap.Client.Client.Messages;
using Udap.Client.Configuration;
using Udap.Client.Extensions;
using Udap.Common.Certificates;
using Udap.Common.Extensions;
using Udap.Common.Models;
using Udap.Model;
using Udap.Model.Access;
using Udap.Model.Registration;
using Udap.Model.Statement;
using Udap.Util.Extensions;

namespace Udap.Client.Client
{

    public interface IUdapClient
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
        /// Event fired when a certificate is untrusted
        /// </summary>
        event Action<X509Certificate2>? Untrusted;

        /// <summary>
        /// Event fired if a certificate has a problem.
        /// </summary>
        event Action<X509ChainElement>? Problem;

        /// <summary>
        /// Event fired if there was an error during certificate validation
        /// </summary>
        event Action<X509Certificate2, Exception>? Error;

        /// <summary>
        /// Event fired when JWT Token validation fails
        /// </summary>
        event Action<string>? TokenError;

        Task<UdapDynamicClientRegistrationDocument> RegisterClient(
            string redirectUrl,
            IEnumerable<X509Certificate2> certificates,
            CancellationToken token = default);

        Task<OAuthTokenResponse> ExchangeCode(UdapAuthorizationCodeTokenRequest tokenRequest, CancellationToken token = default);
    }

    public class UdapClient : IUdapClient
    {
        private readonly HttpClient _httpClient;
        private readonly TrustChainValidator _trustChainValidator;
        private readonly UdapClientOptions _udapClientOptions;
        private ITrustAnchorStore? _trustAnchorStore;
        private DiscoveryPolicy _discoveryPolicy;
        private readonly ILogger<UdapClient> _logger;
        private X509Certificate2? _publicCertificate;

        public UdapClient(
            HttpClient httpClient,
            TrustChainValidator trustChainValidator,
            IOptionsMonitor<UdapClientOptions> udapClientOptions,
            ILogger<UdapClient> logger,
            ITrustAnchorStore? trustAnchorStore = null,
            DiscoveryPolicy? discoveryPolicy = null)
        {
            _httpClient = httpClient;
            _trustChainValidator = trustChainValidator;
            _udapClientOptions = udapClientOptions.CurrentValue;
            _trustAnchorStore = trustAnchorStore;
            _logger = logger;
            _discoveryPolicy = discoveryPolicy ?? DiscoveryPolicy.DefaultMetadataServerPolicy();
        }

        public UdapMetadata? UdapDynamicClientRegistrationDocument { get; set; }
        public UdapMetadata? UdapServerMetaData { get; set; }

        /// <inheritdoc/>
        public event Action<X509Certificate2>? Untrusted
        {
            add => _trustChainValidator.Untrusted += value;
            remove => _trustChainValidator.Untrusted -= value;
        }

        /// <inheritdoc/>
        public event Action<X509ChainElement>? Problem
        {
            add => _trustChainValidator.Problem += value;
            remove => _trustChainValidator.Problem -= value;
        }

        /// <inheritdoc/>
        public event Action<X509Certificate2, Exception>? Error
        {
            add => _trustChainValidator.Error += value;
            remove => _trustChainValidator.Error -= value;
        }

        /// <inheritdoc/>
        public event Action<string>? TokenError;

        //TODO the certs include the private key.  This needs work.  It should be a service or struct that
        // allows a an abstraction in "Sign" so that a vault or HSM can sign the metadata.
        public async Task<UdapDynamicClientRegistrationDocument> RegisterClient(
            string redirectUrl,
            IEnumerable<X509Certificate2> certificates,
            CancellationToken token = default)
        {
            if (this.UdapServerMetaData == null)
            {
                throw new Exception("Tiered OAuth: UdapServerMetaData is null.  Call ValidateResource first.");
            }

            try
            {
                foreach (var clientCert in certificates)
                {

                    var document = UdapDcrBuilderForAuthorizationCode
                        .Create(clientCert)
                        .WithAudience(this.UdapServerMetaData?.RegistrationEndpoint)
                        .WithExpiration(TimeSpan.FromMinutes(5))
                        .WithJwtId()
                        .WithClientName(_udapClientOptions.ClientName)
                        .WithContacts(_udapClientOptions.Contacts)
                        .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues
                            .TokenEndpointAuthMethodValue)
                        .WithScope("openid udap email profile")
                        .WithResponseTypes(new List<string> { "code" })
                        .WithRedirectUrls(new List<string> { redirectUrl })
                        .Build();
                    //
                    // Example adding claims
                    //
                    // document.AddClaims(new List<Claim>() { new Claim("client_uri", "http://test.com/hello/") });

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

                    if (response.IsSuccessStatusCode)
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

        public async Task<OAuthTokenResponse> ExchangeCode(UdapAuthorizationCodeTokenRequest tokenRequest, CancellationToken token = default)
        {
            return await _httpClient.UdapExchangeCodeAsync(tokenRequest, token);
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
            ITrustAnchorStore trustAnchorStore,
            string? community = null,
            DiscoveryPolicy? discoveryPolicy = null)
        {
            _trustAnchorStore = trustAnchorStore;

            return ValidateResource(baseUrl, community, discoveryPolicy);
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

                    if (!await ValidateJwtToken(UdapServerMetaData!, baseUrl))
                    {
                        throw new SecurityTokenInvalidTypeException("Failed JWT Token Validation");
                    }

                    if (_publicCertificate != null && !await ValidateTrustChain(_publicCertificate, community))
                    {
                        throw new UnauthorizedAccessException("Failed Trust Chain Validation");
                    }
                }
                else
                {
                    NotifyTokenError(disco.Error);
                }

                return disco;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed validating resource metadata");
                return ProtocolResponse.FromException<UdapDiscoveryDocumentResponse>(ex);
            }
        }

        

        private async Task<bool> ValidateJwtToken(UdapMetadata udapServerMetaData, string baseUrl)
        {
            var tokenHandler = new JsonWebTokenHandler();
            var jwt = tokenHandler.ReadJsonWebToken(udapServerMetaData.SignedMetadata);
            _publicCertificate = jwt?.GetPublicCertificate();

            var subjectAltNames = _publicCertificate?
                .GetSubjectAltNames(n =>
                    n.TagNo == (int)X509Extensions.GeneralNameType.URI) //URI only, by udap.org specification
                .Select(n => new Uri(n.Item2).AbsoluteUri)
                .ToArray();

            var validatedToken = await ValidateToken(udapServerMetaData, tokenHandler, subjectAltNames, jwt);

            if (_publicCertificate == null)
            {
                NotifyTokenError("Software statement is missing the x5c header.");
                return false;
            }

            if (!validatedToken.IsValid)
            {
                NotifyTokenError(validatedToken.Exception.Message);
                return false;
            }

            if (!baseUrl.TrimEnd('/').Equals(jwt?.Issuer.TrimEnd('/'), StringComparison.OrdinalIgnoreCase))
            {
                NotifyTokenError($"JWT iss does not match baseUrl. iss: {jwt?.Issuer.TrimEnd('/')}  baseUrl: {baseUrl.TrimEnd('/')}");
                return false;
            }

            if (!udapServerMetaData.RegistrationEndpointJwtSigningAlgValuesSupported
                    .Contains(jwt!.GetHeaderValue<string>(JwtHeaderParameterNames.Alg)))
            {
                NotifyTokenError(
                    $"The x5c header does not match one of the algorithms listed in {UdapConstants.Discovery.TokenEndpointAuthSigningAlgValuesSupported}:" +
                    $"{string.Join(", ", udapServerMetaData.TokenEndpointAuthSigningAlgValuesSupported)} ");
                return false;
            }

            return true;

        }

        private async Task<TokenValidationResult> ValidateToken(
            UdapMetadata udapServerMetaData,
            JsonWebTokenHandler tokenHandler,
            string[]? subjectAltNames,
            JsonWebToken? jwt)
        {
            var publicKey = _publicCertificate?.PublicKey.GetRSAPublicKey();

            if (publicKey != null)
            {
                var validatedToken = await tokenHandler.ValidateTokenAsync(
                    udapServerMetaData.SignedMetadata,
                    new TokenValidationParameters
                    {
                        RequireSignedTokens = true,
                        ValidateIssuer = true,
                        ValidateIssuerSigningKey = true,
                        ValidIssuers =
                            subjectAltNames, //With ValidateIssuer = true issuer is validated against this list.  Docs are not clear on this, thus this example.
                        ValidateAudience = false, // No aud for UDAP metadata
                        ValidateLifetime = true,
                        IssuerSigningKey = new RsaSecurityKey(publicKey),
                        ValidAlgorithms = new[]
                            { jwt!.GetHeaderValue<string>(JwtHeaderParameterNames.Alg) }, //must match signing algorithm
                    });

                return validatedToken;
            }
            else
            {
                var ecdsaPublicKey = _publicCertificate?.PublicKey.GetECDsaPublicKey();

                var validatedToken = await tokenHandler.ValidateTokenAsync(
                    udapServerMetaData.SignedMetadata,
                    new TokenValidationParameters
                    {
                        RequireSignedTokens = true,
                        ValidateIssuer = true,
                        ValidateIssuerSigningKey = true,
                        ValidIssuers =
                            subjectAltNames, //With ValidateIssuer = true issuer is validated against this list.  Docs are not clear on this, thus this example.
                        ValidateAudience = false, // No aud for UDAP metadata
                        ValidateLifetime = true,
                        IssuerSigningKey = new ECDsaSecurityKey(ecdsaPublicKey),
                        ValidAlgorithms = new[]
                            { jwt!.GetHeaderValue<string>(JwtHeaderParameterNames.Alg) }, //must match signing algorithm
                    });

                return validatedToken;
            }
        }

        private async Task<bool> ValidateTrustChain(X509Certificate2 certificate, string? community)
        {
            var store = _trustAnchorStore == null ? null : await _trustAnchorStore.Resolve();
            var anchors = X509Certificate2Collection(community, store).ToList();

            if (!anchors.Any())
            {
                _logger.LogWarning($"{nameof(UdapClient)} does not contain any anchor certificates");
                return false;
            }

            var anchorCertificates = anchors.ToX509Collection();

            if (anchorCertificates == null || !anchorCertificates.Any())
            {
                _logger.LogWarning($"{nameof(UdapClient)} does not contain any anchor certificates");
                return false;
            }

            return _trustChainValidator.IsTrustedCertificate(
                nameof(UdapClient),
                certificate,
                anchors.SelectMany(a =>
                        a.Intermediates == null
                            ? Enumerable.Empty<X509Certificate2>()
                            : a.Intermediates.Select(i => X509Certificate2.CreateFromPem(i.Certificate)))
                    .ToArray().ToX509Collection(),
                anchorCertificates);
        }


        private static IEnumerable<Anchor> X509Certificate2Collection(string? community, ITrustAnchorStore? store)
        {
            IEnumerable<Anchor> anchorCertificates;

            if (store == null)
            {
                return Enumerable.Empty<Anchor>();
            }

            if (community != null && store.AnchorCertificates.Any(a => a.Community != null))
            {
                anchorCertificates = store.AnchorCertificates
                    .Where(a => a.Community == community)
                    .Select(a => a);
            }
            else
            {
                anchorCertificates = store.AnchorCertificates;
            }

            return anchorCertificates;
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

    // TODO: UdapClient should use UdapClientMessageHandler
    // The UdapClientMessageHandler came into existence when adding Tiered OAuth 
    // and attached it to the BackchannelHttpHandler of Microsoft.AspNetCore.Authentication.RemoteAuthenticationOptions
    public class UdapClientMessageHandler : DelegatingHandler
    {
        private readonly TrustChainValidator _trustChainValidator;
        private ITrustAnchorStore? _trustAnchorStore;
        private DiscoveryPolicy _discoveryPolicy;
        private readonly ILogger<UdapClient> _logger;
        private X509Certificate2? _publicCertificate;

        public UdapClientMessageHandler(
            TrustChainValidator trustChainValidator,
            ILogger<UdapClient> logger,
            ITrustAnchorStore? trustAnchorStore = null,
            DiscoveryPolicy? discoveryPolicy = null)
        {
            _trustChainValidator = trustChainValidator;
            _trustAnchorStore = trustAnchorStore;
            _logger = logger;
            _discoveryPolicy = discoveryPolicy ?? DiscoveryPolicy.DefaultMetadataServerPolicy();
        }

        public UdapMetadata? UdapDynamicClientRegistrationDocument { get; set; }
        public UdapMetadata? UdapServerMetaData { get; set; }



        /// <inheritdoc/>
        public event Action<X509Certificate2>? Untrusted
        {
            add => _trustChainValidator.Untrusted += value;
            remove => _trustChainValidator.Untrusted -= value;
        }

        /// <inheritdoc/>
        public event Action<X509ChainElement>? Problem
        {
            add => _trustChainValidator.Problem += value;
            remove => _trustChainValidator.Problem -= value;
        }

        /// <inheritdoc/>
        public event Action<X509Certificate2, Exception>? Error
        {
            add => _trustChainValidator.Error += value;
            remove => _trustChainValidator.Error -= value;
        }

        /// <inheritdoc/>
        public event Action<string>? TokenError;


        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var baseUrl = request.RequestUri?.AbsoluteUri.GetBaseUrlFromMetadataUrl();
            var community = request.RequestUri?.Query.GetCommunityFromQueryParams();

            var metadata = await base.SendAsync(request, cancellationToken);
            metadata.EnsureSuccessStatusCode();

            var disco = await metadata.Content.ReadFromJsonAsync<DiscoveryDocumentResponse>(cancellationToken: cancellationToken);

            if (disco == null)
            {
                throw new SecurityTokenInvalidTypeException("Failed to read UDAP Discovery Document");
            }

            if (disco.HttpStatusCode == HttpStatusCode.OK && !disco.IsError)
            {
                UdapServerMetaData = disco.Json.Deserialize<UdapMetadata>();

                if (!await ValidateJwtToken(UdapServerMetaData!, baseUrl!))
                {
                    throw new SecurityTokenInvalidTypeException("Failed JWT Token Validation");
                }

                if (_publicCertificate != null && !await ValidateTrustChain(_publicCertificate, community))
                {
                    throw new UnauthorizedAccessException("Failed Trust Chain Validation");
                }
            }
            else
            {
                NotifyTokenError(disco.Error);
            }

            return metadata;

        }



        private async Task<bool> ValidateJwtToken(UdapMetadata udapServerMetaData, string baseUrl)
        {
            var tokenHandler = new JsonWebTokenHandler();
            var jwt = tokenHandler.ReadJsonWebToken(udapServerMetaData.SignedMetadata);
            _publicCertificate = jwt?.GetPublicCertificate();

            var subjectAltNames = _publicCertificate?
                .GetSubjectAltNames(n =>
                    n.TagNo == (int)X509Extensions.GeneralNameType.URI) //URI only, by udap.org specification
                .Select(n => new Uri(n.Item2).AbsoluteUri)
                .ToArray();

            var validatedToken = await ValidateToken(udapServerMetaData, tokenHandler, subjectAltNames, jwt);

            if (_publicCertificate == null)
            {
                NotifyTokenError("Software statement is missing the x5c header.");
                return false;
            }

            if (!validatedToken.IsValid)
            {
                NotifyTokenError(validatedToken.Exception.Message);
                return false;
            }

            if (!baseUrl.Equals(jwt?.Issuer, StringComparison.OrdinalIgnoreCase))
            {
                NotifyTokenError("JWT iss does not match baseUrl.");
                return false;
            }

            if (!udapServerMetaData.RegistrationEndpointJwtSigningAlgValuesSupported
                    .Contains(jwt!.GetHeaderValue<string>(JwtHeaderParameterNames.Alg)))
            {
                NotifyTokenError(
                    $"The x5c header does not match one of the algorithms listed in {UdapConstants.Discovery.TokenEndpointAuthSigningAlgValuesSupported}:" +
                    $"{string.Join(", ", udapServerMetaData.TokenEndpointAuthSigningAlgValuesSupported)} ");
                return false;
            }

            return true;

        }




        private async Task<TokenValidationResult> ValidateToken(
            UdapMetadata udapServerMetaData,
            JsonWebTokenHandler tokenHandler,
            string[]? subjectAltNames,
            JsonWebToken? jwt)
        {
            var publicKey = _publicCertificate?.PublicKey.GetRSAPublicKey();

            if (publicKey != null)
            {
                var validatedToken = await tokenHandler.ValidateTokenAsync(
                    udapServerMetaData.SignedMetadata,
                    new TokenValidationParameters
                    {
                        RequireSignedTokens = true,
                        ValidateIssuer = true,
                        ValidateIssuerSigningKey = true,
                        ValidIssuers =
                            subjectAltNames, //With ValidateIssuer = true issuer is validated against this list.  Docs are not clear on this, thus this example.
                        ValidateAudience = false, // No aud for UDAP metadata
                        ValidateLifetime = true,
                        IssuerSigningKey = new RsaSecurityKey(publicKey),
                        ValidAlgorithms = new[]
                            { jwt!.GetHeaderValue<string>(JwtHeaderParameterNames.Alg) }, //must match signing algorithm
                    });

                return validatedToken;
            }
            else
            {
                var ecdsaPublicKey = _publicCertificate?.PublicKey.GetECDsaPublicKey();

                var validatedToken = await tokenHandler.ValidateTokenAsync(
                    udapServerMetaData.SignedMetadata,
                    new TokenValidationParameters
                    {
                        RequireSignedTokens = true,
                        ValidateIssuer = true,
                        ValidateIssuerSigningKey = true,
                        ValidIssuers =
                            subjectAltNames, //With ValidateIssuer = true issuer is validated against this list.  Docs are not clear on this, thus this example.
                        ValidateAudience = false, // No aud for UDAP metadata
                        ValidateLifetime = true,
                        IssuerSigningKey = new ECDsaSecurityKey(ecdsaPublicKey),
                        ValidAlgorithms = new[]
                            { jwt!.GetHeaderValue<string>(JwtHeaderParameterNames.Alg) }, //must match signing algorithm
                    });

                return validatedToken;
            }
        }



        private async Task<bool> ValidateTrustChain(X509Certificate2 certificate, string? community)
        {
            var store = _trustAnchorStore == null ? null : await _trustAnchorStore.Resolve();
            var anchors = X509Certificate2Collection(community, store).ToList();

            if (!anchors.Any())
            {
                _logger.LogWarning($"{nameof(UdapClient)} does not contain any anchor certificates");
                return false;
            }

            var anchorCertificates = anchors.ToX509Collection();

            if (anchorCertificates == null || !anchorCertificates.Any())
            {
                _logger.LogWarning($"{nameof(UdapClient)} does not contain any anchor certificates");
                return false;
            }

            return _trustChainValidator.IsTrustedCertificate(
                nameof(UdapClient),
                certificate,
                anchors.SelectMany(a =>
                        a.Intermediates == null
                            ? Enumerable.Empty<X509Certificate2>()
                            : a.Intermediates.Select(i => X509Certificate2.CreateFromPem(i.Certificate)))
                    .ToArray().ToX509Collection(),
                anchorCertificates);
        }


        private static IEnumerable<Anchor> X509Certificate2Collection(string? community, ITrustAnchorStore? store)
        {
            IEnumerable<Anchor> anchorCertificates;

            if (store == null)
            {
                return Enumerable.Empty<Anchor>();
            }

            if (community != null && store.AnchorCertificates.Any(a => a.Community != null))
            {
                anchorCertificates = store.AnchorCertificates
                    .Where(a => a.Community == community)
                    .Select(a => a);
            }
            else
            {
                anchorCertificates = store.AnchorCertificates;
            }

            return anchorCertificates;
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
