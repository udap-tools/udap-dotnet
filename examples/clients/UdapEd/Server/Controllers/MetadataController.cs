#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Udap.Client.Client;
using Udap.Client.Configuration;
using Udap.Client.Internal;
using Udap.Common.Certificates;
using Udap.Common.Extensions;
using Udap.Common.Models;
using Udap.Model;
using Udap.Util.Extensions;
using UdapEd.Server.Extensions;
using UdapEd.Shared;
using UdapEd.Shared.Model;
using UdapEd.Shared.Model.Discovery;
using X509Extensions = Org.BouncyCastle.Asn1.X509.X509Extensions;

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
        var result = BuildCertificateDisplayData(cert);

        return Ok(result);
    }

    [HttpPost("CertificateDisplay")]
    public IActionResult BuildCertificateDisplay([FromBody] string certificate)
    {
        var certBytes = Convert.FromBase64String(certificate);
        var cert = new X509Certificate2(certBytes);
        var result = BuildCertificateDisplayData(cert);

        return Ok(result);

    }

    private CertificateViewModel BuildCertificateDisplayData(X509Certificate2 cert)
    {
        var data = new Dictionary<string, string>();

        data.Add("Serial Number", cert.SerialNumber);
        data.Add("Subject", cert.Subject);
        data.Add("Subject Alternative Names", GetSANs(cert));
        data.Add("Public Key Alogorithm", GetPublicKeyAlgorithm(cert));
        data.Add("Certificate Policy", BuildPolicyInfo(cert));
        data.Add("Start Date", cert.GetEffectiveDateString());
        data.Add("End Date", cert.GetExpirationDateString());
        data.Add("Key Usage", GetKeyUsage(cert));
        // data.Add("Extended Key Usage", GetExtendedKeyUsage(cert));
        data.Add("Issuer", cert.Issuer);
        data.Add("Subject Key Identifier", GetSubjectKeyIdentifier(cert));
        data.Add("Authority Key Identifier", GetAuthorityKeyIdentifier(cert));
        data.Add("Authority Information Access", GetAIAUrls(cert));
        data.Add("CRL Distribution", GetCrlDistributionPoint(cert));
        data.Add("Thumbprint SHA1", cert.Thumbprint);

        var result = new CertificateViewModel();

        result.TableDisplay.Add(data);
        return result;
    }

    private string GetAIAUrls(X509Certificate2 cert)
    {
        var aiaExtensions =
            cert.Extensions["1.3.6.1.5.5.7.1.1"] as X509AuthorityInformationAccessExtension;

        if (aiaExtensions == null)
        {
            return string.Empty;
        }
        var sb = new StringBuilder();
        foreach (var url in aiaExtensions!.EnumerateCAIssuersUris())
        {
            sb.AppendLine(url);
        }

        return sb.ToString();
    }

    private string GetPublicKeyAlgorithm(X509Certificate2 cert)
    {
        string keyAlgOid = cert.GetKeyAlgorithm(); 
        var oid = new Oid(keyAlgOid);

        var key = cert.GetRSAPublicKey() as AsymmetricAlgorithm ?? cert.GetECDsaPublicKey();
        return $"{oid.FriendlyName} ({key?.KeySize})";
    }

    private string GetSANs(X509Certificate2 cert)
    {
        var sans = cert.GetSubjectAltNames();

        if (!sans.Any())
        {
            return string.Empty;
        }

        var sb = new StringBuilder();

        foreach (var tuple in sans)
        {
            sb.AppendLine($"{tuple.Item1} : {tuple.Item2}");
        }
        
        return sb.ToString();
    }

    private string BuildPolicyInfo(X509Certificate2 cert)
    {
        var extension = cert.GetExtensionValue("2.5.29.32") as Asn1OctetString;
        if (extension == null)
        {
            return string.Empty;
        }
        var policies = extension.GetOctets();
        var policyInfoList = CertificatePolicies.GetInstance(policies).GetPolicyInformation();
        return string.Join("\r\n", policyInfoList.Select(p => p.PolicyIdentifier.ToString()));
    }

    private string GetKeyUsage(X509Certificate2 cert)
    {
        var extensions = cert.Extensions.OfType<X509KeyUsageExtension>().ToList();

        if (!extensions.Any())
        {
            return String.Empty;
        }

        var keyUsage = extensions.First().KeyUsages;

        return string.Join("; ", keyUsage.ToKeyUsageToString());
    }

    private string GetExtendedKeyUsage(X509Certificate2 cert)
    {
        var ext = cert.GetExtensionValue(X509Extensions.ExtendedKeyUsage.Id) as Asn1OctetString;

        if (ext == null)
        {
            return string.Empty;
        }

        var instance = ExtendedKeyUsage.GetInstance(Asn1Object.FromByteArray(ext.GetOctets()));

        var joe = instance.GetAllUsages();
        return joe.ToString();
    }

    private string GetSubjectKeyIdentifier(X509Certificate2 cert)
    {
        var extensions = cert.Extensions.OfType<X509SubjectKeyIdentifierExtension>().ToList();

        if (!extensions.Any())
        {
            return string.Empty;
        }

        return extensions.First().SubjectKeyIdentifier ?? string.Empty;
    }

    private string GetAuthorityKeyIdentifier(X509Certificate2 cert)
    {
        var extensions = cert.Extensions.OfType<X509AuthorityKeyIdentifierExtension>().ToList();

        if (!extensions.Any())
        {
            return string.Empty;
        }

        var bytes = extensions.First().KeyIdentifier?.ToArray();

        if (bytes == null)
        {
            return string.Empty;
        }

        return CreateByteStringRep(bytes);
    }

    private string GetCrlDistributionPoint(X509Certificate2 cert)
    {
        var ext = cert.GetExtensionValue(X509Extensions.CrlDistributionPoints.Id);

        if (ext == null)
        {
            return string.Empty;
        }
        
        var distPoints = CrlDistPoint.GetInstance(ext);
        var retVal = new List<string>();

        foreach (var distPoint in distPoints.GetDistributionPoints())
        {
            if (distPoint.DistributionPointName != null
                && distPoint.DistributionPointName.PointType == DistributionPointName.FullName)
            {
                var names = GeneralNames.GetInstance(distPoint.DistributionPointName.Name);
                
                foreach (var generalName in names.GetNames())
                {
                    var name = generalName.Name.ToString();
                    if (name != null)
                    {
                        retVal.Add(name);
                    }
                }
            }
        }

        return string.Join("\r\n", retVal);
    }

    private static string CreateByteStringRep(byte[] bytes)
    {
        var c = new char[bytes.Length * 2];
        for (var i = 0; i < bytes.Length; i++)
        {
            var b = bytes[i] >> 4;
            c[i * 2] = (char)(55 + b + (((b - 10) >> 31) & -7));
            b = bytes[i] & 0xF;
            c[i * 2 + 1] = (char)(55 + b + (((b - 10) >> 31) & -7));
        }
        return new string(c);

    }
}
