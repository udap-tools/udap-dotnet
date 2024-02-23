#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using Udap.Client.Client;
using Udap.Client.Configuration;
using Udap.Common.Certificates;
using Udap.Common.Extensions;
using Udap.Common.Models;
using Udap.Model;
using Udap.Util.Extensions;
using UdapEd.Server.Extensions;
using UdapEd.Shared;
using UdapEd.Shared.Model;
using UdapEd.Shared.Model.Discovery;

namespace UdapEd.Server.Controllers;

[Route("[controller]")]
[EnableRateLimiting(RateLimitExtensions.Policy)]
public class MetadataController : Controller
{
    private readonly IUdapClient _udapClient;
    private readonly ILogger<MetadataController> _logger;
    private readonly HttpClient _httpClient;
    private readonly UdapClientOptions _udapClientOptions;

    public MetadataController(IUdapClient udapClient, HttpClient httpClient, IOptionsMonitor<UdapClientOptions> udapClientOptions, ILogger<MetadataController> logger)
    {
        _udapClient = udapClient;
        _httpClient = httpClient;
        _udapClientOptions = udapClientOptions.CurrentValue;
        _logger = logger;
    }

    // get fully validated metadata from .well-known/udap  
    [HttpGet]
    public async Task<IActionResult> Get([FromQuery] string metadataUrl, [FromQuery] string community)
    {
        var anchorString = HttpContext.Session.GetString(UdapEdConstants.ANCHOR_CERTIFICATE);

        if (anchorString != null)
        {
            var result = new MetadataVerificationModel();

            var certBytes = Convert.FromBase64String(anchorString);
            var anchorCert = new X509Certificate2(certBytes);
            var trustAnchorStore = new TrustAnchorMemoryStore()
            {
                AnchorCertificates = new HashSet<Anchor>
                {
                    new Anchor(anchorCert)
                }
            };

            
            _udapClient.Problem += element =>
                result.Notifications.Add(element.ChainElementStatus.Summarize(TrustChainValidator.DefaultProblemFlags));
            _udapClient.Untrusted += certificate2 => result.Notifications.Add("Untrusted: " + certificate2.Subject);
            _udapClient.TokenError += message => result.Notifications.Add("TokenError: " + message);

            await _udapClient.ValidateResource(
                metadataUrl, 
                trustAnchorStore,
                community);
            
            result.UdapServerMetaData = _udapClient.UdapServerMetaData;
            HttpContext.Session.SetString(UdapEdConstants.BASE_URL, metadataUrl);

            return Ok(result);
        }

        return BadRequest("Missing anchor");
    }

    // get metadata from .well-known/udap  that is not validated and trust is not validated
    [HttpGet("UnValidated")]
    public async Task<IActionResult> GetUnValidated([FromQuery] string metadataUrl, [FromQuery] string community)
    {
        var baseUrl = metadataUrl.EnsureTrailingSlash() + UdapConstants.Discovery.DiscoveryEndpoint;
        if (!string.IsNullOrEmpty(community))
        {
            baseUrl += $"?{UdapConstants.Community}={community}";
        }

        _logger.LogDebug(baseUrl);
        var response = await _httpClient.GetStringAsync(baseUrl);
        var result = JsonSerializer.Deserialize<UdapMetadata>(response);
        HttpContext.Session.SetString(UdapEdConstants.BASE_URL, baseUrl.GetBaseUrlFromMetadataUrl());

        var model = new MetadataVerificationModel
        {
            UdapServerMetaData = result,
            Notifications = new List<string>
            {
                "No anchor loaded.  Un-Validated resource server."
            }
        };

        return Ok(model);
    }

    [HttpPost("UploadAnchorCertificate")]
    public IActionResult UploadAnchorCertificate([FromBody] string base64String)
    {
        var result =  new CertificateStatusViewModel { CertLoaded = CertLoadedEnum.Negative };

        try
        {
            var certBytes = Convert.FromBase64String(base64String);
            var certificate = new X509Certificate2(certBytes);
            result.DistinguishedName = certificate.SubjectName.Name;
            result.Thumbprint = certificate.Thumbprint;
            result.CertLoaded = CertLoadedEnum.Positive;
            HttpContext.Session.SetString(UdapEdConstants.ANCHOR_CERTIFICATE, base64String);

            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed loading certificate");
            _logger.LogDebug(ex,
                $"Failed loading certificate from {nameof(base64String)} {base64String}");
            
            return BadRequest(result);
        }
    }

    [HttpPut("LoadUdapOrgAnchor")]
    public async Task<IActionResult> LoadUdapOrgAnchor([FromBody] string anchorCertificate)
    {
        var result = new CertificateStatusViewModel { CertLoaded = CertLoadedEnum.Negative };

        try
        {
            var response = await _httpClient.GetAsync(new Uri(anchorCertificate));
            response.EnsureSuccessStatusCode();
            var certBytes = await response.Content.ReadAsByteArrayAsync();
            var certificate = new X509Certificate2(certBytes);
            result.DistinguishedName = certificate.SubjectName.Name;
            result.Thumbprint = certificate.Thumbprint;
            result.CertLoaded = CertLoadedEnum.Positive;
            HttpContext.Session.SetString(UdapEdConstants.ANCHOR_CERTIFICATE, Convert.ToBase64String(certBytes));

            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed loading anchor from {anchorCertificate}", anchorCertificate);
            _logger.LogDebug(ex,
                $"Failed loading certificate from {nameof(anchorCertificate)} {anchorCertificate}");

            return BadRequest(result);
        }
    }

    [HttpGet("IsAnchorCertificateLoaded")]
    public IActionResult IsAnchorCertificateLoaded()
    {
        var result = new CertificateStatusViewModel
        {
            CertLoaded = CertLoadedEnum.Negative
        };

        try
        {
            var base64String = HttpContext.Session.GetString(UdapEdConstants.ANCHOR_CERTIFICATE);

            if (base64String != null)
            {
                var certBytes = Convert.FromBase64String(base64String);
                var certificate = new X509Certificate2(certBytes);
                result.DistinguishedName = certificate.SubjectName.Name;
                result.Thumbprint = certificate.Thumbprint;
                result.CertLoaded = CertLoadedEnum.Positive;
            }
            else
            {
                result.CertLoaded = CertLoadedEnum.Negative;
            }

            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex.Message);

            return Ok(result);
        }
    }

    [HttpPut]
    public IActionResult SetBaseFhirUrl([FromBody] string baseFhirUrl, [FromQuery] bool resetToken)
    {
        HttpContext.Session.SetString(UdapEdConstants.BASE_URL, baseFhirUrl);

        if (resetToken)
        {
            HttpContext.Session.Remove(UdapEdConstants.TOKEN);
        }

        return Ok();
    }

    [HttpGet("MyIp")]
    public IActionResult Get()
    {
        return Ok(Environment.GetEnvironmentVariable("MyIp"));
    }

    [HttpPut("SetClientHeaders")]
    public IActionResult SetClientHeaders([FromBody] Dictionary<string, string> headers)
    {
        // HttpContext.Session.SetString(UdapEdConstants.CLIENT_HEADERS, JsonSerializer.Serialize<Dictionary<string, string>>(headers));
        _udapClientOptions.Headers = headers;

        return Ok();
    }

    [HttpGet("FhirLabsCommunityList")]
    public async Task<IActionResult> GetFhirLabsCommunityList()
    {
        var response = await _httpClient.GetStringAsync("https://fhirlabs.net/fhir/r4/.well-known/udap/communities/ashtml");
        
        return Ok(response);
    }

    [HttpPost("CertificateDisplayFromJwtHeader")]
    public IActionResult BuildCertificateDisplay([FromBody] List<string> certificates)
    {
        var certBytes = Convert.FromBase64String(certificates.First());
        var cert = new X509Certificate2(certBytes);
        var result = new CertificateDisplayBuilder(cert).BuildCertificateDisplayData();

        return Ok(result);
    }

    [HttpPost("CertificateDisplay")]
    public IActionResult BuildCertificateDisplay([FromBody] string certificate)
    {
        var certBytes = Convert.FromBase64String(certificate);
        var cert = new X509Certificate2(certBytes);
        var result = new CertificateDisplayBuilder(cert).BuildCertificateDisplayData();

        return Ok(result);

    }
}
