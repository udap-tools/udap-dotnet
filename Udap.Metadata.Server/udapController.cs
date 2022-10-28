#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using IdentityModel;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Udap.Client;
using Udap.Common;

namespace Udap.Metadata.Server
{
    [Route(".well-known/udap")]
    public class UdapController : ControllerBase
    {
        private readonly UdapConfig _udapConfig;
        private readonly ICertificateStore _certificateStore;
        private readonly ILogger<UdapController> _logger;

        public UdapController(
            IConfiguration configuration,
            IOptionsMonitor<UdapConfig> udapConfig,
            ICertificateStore certificateStore,
            ILogger<UdapController> logger)
        {
            _certificateStore = certificateStore;
            _udapConfig = udapConfig.CurrentValue;
            _logger = logger;
        }

        [HttpGet]
        // TODO: when this is pulled from data.  async Task<IActionResult>
        public IActionResult Get([FromQuery] string? community)
        {
            UdapMetadataConfig? udapMetadataConfig;

            //todo: probably need a first class resolver to substitute config files for DB
            if (community == null)
            {
                udapMetadataConfig = _udapConfig.UdapMetadataConfigs.FirstOrDefault();
            }
            else
            {
                udapMetadataConfig = _udapConfig.UdapMetadataConfigs
                    .SingleOrDefault(c => c.Community == community);
            }
             

            if (udapMetadataConfig == null)
            {
                _logger.LogWarning($"Cannot find UdapMetadataConfig from community: {community}");
                
                return NotFound();
            }

            var udapMetadata = new UdapMetadata();

            udapMetadata.UdapVersionsSupported = new[] { UdapConstants.UdapVersionsSupportedValue };
            udapMetadata.UdapProfilesSupported = new[]
            {
                UdapConstants.UdapProfilesSupportedValues.UdapDcr,
                UdapConstants.UdapProfilesSupportedValues.UdapAuthn,
                UdapConstants.UdapProfilesSupportedValues.UdapAuthz,
                UdapConstants.UdapProfilesSupportedValues.UdapTo
            };

            udapMetadata.UdapAuthorizationExtensionsSupported = new[]
            {
                UdapConstants.UdapAuthorizationExtensions.Hl7B2B,
                "acme-ext"
            };
            udapMetadata.UdapAuthorizationExtensionsRequired = new[]
            {
                UdapConstants.UdapAuthorizationExtensions.Hl7B2B
            };
            udapMetadata.UdapCertificationsSupported = new[]
            {
                "http://MyUdapCertification", "http://MyUdapCertification2"
            };
            udapMetadata.UdapCertificationsRequired = new[] { "http://MyUdapCertification" };
            udapMetadata.GrantTypesSupported = new[]
            {
                OidcConstants.GrantTypes.AuthorizationCode,
                OidcConstants.GrantTypes.RefreshToken,
                OidcConstants.GrantTypes.ClientCredentials
            };
            udapMetadata.ScopesSupported = new[]
            {
                OidcConstants.StandardScopes.OpenId,
                UdapConstants.FhirScopes.SystemPatientRead,
                UdapConstants.FhirScopes.SystemAllergyIntoleranceRead,
                UdapConstants.FhirScopes.SystemProcedureRead,
                "system/Observation.read"
            };

            //TODO: Fix config and multi community
            udapMetadata.AuthorizationEndpoint = udapMetadataConfig.SignedMetadataConfig.AuthorizationEndpoint;
            udapMetadata.TokenEndpoint = udapMetadataConfig.SignedMetadataConfig.TokenEndpoint;
            udapMetadata.RegistrationEndpoint = udapMetadataConfig.SignedMetadataConfig.RegistrationEndpoint;
            udapMetadata.TokenEndpointAuthMethodsSupported = new[] { UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue };
            udapMetadata.TokenEndpointAuthSigningAlgValuesSupported = new[] { UdapConstants.SupportedAlgorithm.RS256 };
            udapMetadata.RegistrationEndpointJwtSigningAlgValuesSupported = new[] { UdapConstants.SupportedAlgorithm.RS256 };

            udapMetadata.SignedMetadata = SignMetaData(udapMetadataConfig);

            return Ok(udapMetadata);
        }

        /// <summary>
        /// Essentials: OAuth 2.0 Authorization Server Metadata:: https://datatracker.ietf.org/doc/html/rfc8414#section-2.1
        /// Further restrained by UDAP IG:: https://build.fhir.org/ig/HL7/fhir-udap-security-ig/branches/main/discovery.html#signed-metadata-elements 
        /// </summary>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        private string SignMetaData(UdapMetadataConfig udapMetadataConfig)
        {
            var cert = Load(udapMetadataConfig);

            if (cert == null)
            {
                return string.Empty;
            }

            var securityKey = new X509SecurityKey(cert);
            var signingCredentials = new SigningCredentials(securityKey, UdapConstants.SupportedAlgorithm.RS256);

            var now = DateTime.UtcNow;

            var base64Der = Convert.ToBase64String(cert.Export(X509ContentType.Cert));
            var jwtHeader = new JwtHeader
            {
                { "alg", signingCredentials.Algorithm },
                { "x5c", new[] { base64Der } }
            };

            var jwtPayload = new JwtPayload(
                new List<Claim>
                {
                    new Claim(JwtClaimTypes.Issuer, udapMetadataConfig.SignedMetadataConfig.Issuer),
                    new Claim(JwtClaimTypes.Subject, udapMetadataConfig.SignedMetadataConfig.Subject),
                    new Claim(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(), ClaimValueTypes.Integer),
                    new Claim(JwtClaimTypes.Expiration, EpochTime.GetIntDate(now.AddMinutes(1).ToUniversalTime()).ToString(), ClaimValueTypes.Integer),
                    new Claim(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId()),
                    new Claim(UdapConstants.Discovery.AuthorizationEndpoint, udapMetadataConfig.SignedMetadataConfig.AuthorizationEndpoint),
                    new Claim(UdapConstants.Discovery.TokenEndpoint, udapMetadataConfig.SignedMetadataConfig.TokenEndpoint),
                    new Claim(UdapConstants.Discovery.RegistrationEndpoint, udapMetadataConfig.SignedMetadataConfig.RegistrationEndpoint)
                });

            // var token = new JwtSecurityToken(
            //     jwtHeader,
            //     jwtPayload);

            var encodedHeader = jwtHeader.Base64UrlEncode();
            var encodedPayload = jwtPayload.Base64UrlEncode();
            var encodedSignature = JwtTokenUtilities.CreateEncodedSignature(string.Concat(encodedHeader, ".", encodedPayload), signingCredentials);

            return string.Concat(encodedHeader, ".", encodedPayload, ".", encodedSignature);
        }

        private X509Certificate2? Load(UdapMetadataConfig udapMetadataConfig)
        {
            var store = _certificateStore.Resolve();

            var entity = store.IssuedCertificates
                .Where(c => c.Community == udapMetadataConfig.Community)
                .OrderBy(c => c.Certificate.NotBefore)
                .LastOrDefault();

            if (entity == null)
            {
                return null;
            }

            return entity.Certificate;
        }
    }
}
