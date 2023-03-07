#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using IdentityModel;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Udap.Common;
using Udap.Model;
using Udap.Model.Registration;
using Udap.Model.Statement;

namespace Udap.Metadata.Server
{
    [Route(".well-known/udap")]
    [AllowAnonymous]
    public class UdapController : ControllerBase
    {
        private readonly UdapMetadata _udapMetadata;
        private readonly ICertificateStore _certificateStore;
        private readonly ILogger<UdapController> _logger;

        public UdapController(
            UdapMetadata udapMetadata,
            ICertificateStore certificateStore,
            ILogger<UdapController> logger)
        {
            _udapMetadata = udapMetadata;
            _certificateStore = certificateStore;
            _logger = logger;
        }

        [HttpGet]
        public async Task<IActionResult> Get([FromQuery] string? community, CancellationToken token)
        {
            var udapMetadataConfig = _udapMetadata.GetUdapMetadataConfig(community);

            _udapMetadata.AuthorizationEndpoint = udapMetadataConfig?.SignedMetadataConfig.AuthorizationEndpoint;
            _udapMetadata.TokenEndpoint = udapMetadataConfig?.SignedMetadataConfig.TokenEndpoint;
            _udapMetadata.RegistrationEndpoint = udapMetadataConfig?.SignedMetadataConfig.RegistrationEndpoint;
            
            if (udapMetadataConfig == null)
            {
                _logger.LogWarning($"Cannot find UdapMetadataConfig from community: {community}");
                
                return NotFound();
            }

            _udapMetadata.SignedMetadata = await SignMetaData(udapMetadataConfig);

            return Ok(_udapMetadata);
        }

        [HttpGet("communities")]
        public Task<IActionResult> GetCommunities(bool html, CancellationToken token)
        {

            return Task.FromResult<IActionResult>(Ok(_udapMetadata.Communities()));
        }

        [HttpGet("communities/ashtml")]
        [Produces("text/html")]
        public ActionResult GetCommunitiesAsHtml()
        {
            return base.Content(_udapMetadata.CommunitiesAsHtml(Request.PathBase), "text/html", Encoding.UTF8);
        }

        /// <summary>
        /// Essentials: OAuth 2.0 Authorization Server Metadata:: https://datatracker.ietf.org/doc/html/rfc8414#section-2.1
        /// Further restrained by UDAP IG:: http://hl7.org/fhir/us/udap-security/discovery.html#signed-metadata-elements 
        /// </summary>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        private async Task<string?> SignMetaData(UdapMetadataConfig udapMetadataConfig)
        {
            var cert = await Load(udapMetadataConfig);

            if (cert == null)
            {
                return string.Empty;
            }
            
            var now = DateTime.UtcNow;

            var jwtPayload = new JwtPayLoadExtension(
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

            var builder = SignedSoftwareStatementBuilder<ISoftwareStatementSerializer>.Create(cert, jwtPayload);

            return builder.Build();
        }

        private async Task<X509Certificate2?> Load(UdapMetadataConfig udapMetadataConfig)
        {
            var store = await _certificateStore.Resolve();

            var entity = store.IssuedCertificates
                .Where(c => c.Community == udapMetadataConfig.Community)
                .OrderBy(c => c.Certificate.NotBefore)
                .LastOrDefault();

            if (entity == null)
            {
                _logger.LogInformation($"Missing certificate for community: {udapMetadataConfig.Community}");
                return null;
            }

            return entity.Certificate;
        }
    }
}
