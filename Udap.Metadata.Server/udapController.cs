#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net.Http;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Udap.Common.Extensions;

namespace Udap.Metadata.Server
{
    [Route(".well-known/udap")]
    [AllowAnonymous]
    public class UdapController : ControllerBase
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly UdapMetaDataBuilder _metaDataBuilder;
        private readonly ILogger<UdapController> _logger;

        public UdapController(
            UdapMetaDataBuilder metaDataBuilder,
            IHttpContextAccessor httpContextAccessor,
            ILogger<UdapController> logger)
        {
            _metaDataBuilder = metaDataBuilder;
            _httpContextAccessor = httpContextAccessor;
            _logger = logger;
        }

        [HttpGet]
        public async Task<IActionResult> Get([FromQuery] string? community, CancellationToken token)
        {
            return await _metaDataBuilder.SignMetaData(
                    _httpContextAccessor.HttpContext!.Request.GetDisplayUrl().GetBaseUrlFromMetadataUrl(),
                    community,
                    token)
                is { } udapMetadata
                ? Ok(udapMetadata)
                : NotFound();
        }

        [HttpGet("communities")]
        public IActionResult GetCommunities(bool html, CancellationToken token)
        {

            return Ok(_metaDataBuilder.GetCommunities());
        }

        [HttpGet("communities/ashtml")]
        [Produces("text/html")]
        public ActionResult GetCommunitiesAsHtml()
        {
            return base.Content(_metaDataBuilder.GetCommunitiesAsHtml(Request.GetDisplayUrl().GetBaseUrlFromMetadataUrl()), "text/html", Encoding.UTF8);
        }
    }
}
