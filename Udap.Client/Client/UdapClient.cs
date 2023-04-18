#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using IdentityModel.Client;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Udap.Client.Client.Extensions;
using Udap.Client.Client.Messages;
using Udap.Common.Certificates;
using Udap.Common.Extensions;
using Udap.Model;
using Udap.Util.Extensions;

namespace Udap.Client.Client
{

    public interface IUdapClient
    {
        Task<UdapDiscoveryDocumentResponse> ValidateResource(
            string baseUrl,
            string? community = null,
            DiscoveryPolicy? discoveryPolicy = null);

        UdapMetadata? UdapDynamicClientRegistrationDocument { get; set; }
        UdapMetadata? UdapServerMetaData { get; set; }
    }

    public class UdapClient: IUdapClient
    {
        private readonly HttpClient _httpClient;
        private readonly TrustChainValidator _trustChainValidator;
        private readonly ICertificateStore _certificateStore;
        private DiscoveryPolicy _discoveryPolicy;
        private readonly ILogger<UdapClient> _logger;

        public UdapClient(
            HttpClient httpClient,
            TrustChainValidator trustChainValidator,
            ICertificateStore certificateStore,
            ILogger<UdapClient> logger,
            DiscoveryPolicy? discoveryPolicy = null)
        {
            _httpClient = httpClient;
            _trustChainValidator = trustChainValidator;
            _certificateStore = certificateStore;
            _logger = logger;
            _discoveryPolicy = discoveryPolicy ?? DiscoveryPolicy.DefaultMetadataServerPolicy();
        }

        public UdapMetadata? UdapDynamicClientRegistrationDocument { get; set; }
        public UdapMetadata? UdapServerMetaData { get; set; }

        public async Task<UdapDiscoveryDocumentResponse> ValidateResource(
            string baseUrl, 
            string? community,
            DiscoveryPolicy? discoveryPolicy)
        {
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
                    if (! await ValidateMetadata(UdapServerMetaData!, baseUrl, community))
                    {
                        throw new UnauthorizedAccessException();
                    }
                }

                return disco;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed validating resource metadata");
                return ProtocolResponse.FromException<UdapDiscoveryDocumentResponse>(ex);
            }
        }

        private async Task<bool> ValidateMetadata(UdapMetadata udapServerMetaData, string baseUrl, string? community)
        {
            var tokenHandler = new JsonWebTokenHandler();
            var jwt = tokenHandler.ReadJsonWebToken(udapServerMetaData.SignedMetadata);
            var publicCert = jwt?.GetPublicCertificate();

            var validatedToken = await tokenHandler.ValidateTokenAsync(
                udapServerMetaData.SignedMetadata,
                new TokenValidationParameters
                {
                    RequireSignedTokens = true,
                    ValidateIssuer = true,
                    ValidIssuers = new[]
                    {
                        baseUrl
                    }, //With ValidateIssuer = true issuer is validated against this list.  Docs are not clear on this, thus this example.
                    ValidateAudience = false, // No aud for UDAP metadata
                    ValidateLifetime = true,
                    IssuerSigningKey = new X509SecurityKey(publicCert),
                    ValidAlgorithms = new[] { jwt!.GetHeaderValue<string>(JwtHeaderParameterNames.Alg) }, //must match signing algorithm
                });

            if (!validatedToken.IsValid)
            {
                _logger.LogWarning(validatedToken.Exception?.Message);
                return false;
            }

            if (publicCert == null)
            {
                _logger.LogWarning("Software statement is missing the x5c header.");
                return false;
            }

            var store = await _certificateStore.Resolve();
            var anchorCertificates = X509Certificate2Collection(community, store);
            
            if (anchorCertificates == null)
            {
                _logger.LogWarning($"{nameof(UdapClient)} does not contain any anchor certificates");
                return false;
            }

            return _trustChainValidator.IsTrustedCertificate(
                nameof(UdapClient), 
                publicCert,
                _certificateStore.IntermediateCertificates.ToArray().ToX509Collection(),
                anchorCertificates);
        }


        private static X509Certificate2Collection? X509Certificate2Collection(string? community, ICertificateStore store)
        {
            X509Certificate2Collection? anchorCertificates;

            if (community != null)
            {
                anchorCertificates = store.AnchorCertificates
                    .Where(a => a.Community == community)
                    .ToX509Collection();
            }
            else
            {
                anchorCertificates = store.AnchorCertificates
                    .ToX509Collection();
            }

            return anchorCertificates;
        }
    }
}
