using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Google.Protobuf.WellKnownTypes;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Udap.Model;
using Udap.Util.Extensions;
using UdapEd.Server.Extensions;
using UdapEd.Shared.Model;
using X509Extensions = Org.BouncyCastle.Asn1.X509.X509Extensions;

namespace UdapEd.Server.Controllers;

[Route("[controller]")]
[EnableRateLimiting(RateLimitExtensions.Policy)]
public class MetadataController : Controller
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<MetadataController> _logger;

    public MetadataController(HttpClient httpClient, ILogger<MetadataController> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
    }

    [HttpGet]
    public async Task<IActionResult> Get([FromQuery] string metadataUrl)
    {
        var response = await _httpClient.GetStringAsync(metadataUrl);
        var result = JsonSerializer.Deserialize<UdapMetadata>(response);

        return Ok(result);
    }

    [HttpGet("MyIp")]
    public IActionResult Get()
    {
        return Ok(Environment.GetEnvironmentVariable("MyIp"));
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
        data.Add("Subject Alternative Name", GetSANs(cert));
        data.Add("Certificate Policy", BuildPolicyInfo(cert));
        data.Add("Start Date", cert.GetEffectiveDateString());
        data.Add("End Date", cert.GetExpirationDateString());
        data.Add("Key Usage", GetKeyUsage(cert));
        // data.Add("Extended Key Usage", GetExtendeKeyUsage(cert));
        data.Add("Issuer", cert.Issuer);
        data.Add("Subject Key Identifier", GetSubjectKeyIdentifier(cert));
        data.Add("Authority Key Identifier", GetAuthorityKeyIdentifier(cert));
        data.Add("CRL Distribution", GetCrlDistributionPoint(cert));
        data.Add("Thumbprint SHA1", cert.Thumbprint);

        var result = new CertificateViewModel();

        result.TableDisplay.Add(data);
        return result;
    }

    private string GetSANs(X509Certificate2 cert)
    {
        var sans = cert.GetSubjectAltNames();

        if (!sans.Any())
        {
            return String.Empty;
        }

        return string.Join("\r\n", sans);
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

    private string GetExtendeKeyUsage(X509Certificate2 cert)
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

        var bytes = extensions.First().KeyIdentifier.Value.ToArray();

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
