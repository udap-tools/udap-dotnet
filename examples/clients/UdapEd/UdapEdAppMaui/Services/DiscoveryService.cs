#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Udap.Client.Client;
using Udap.Client.Configuration;
using UdapEd.Shared;
using UdapEd.Shared.Model;
using UdapEd.Shared.Model.Discovery;
using UdapEd.Shared.Services;

namespace UdapEdAppMaui.Services;
internal class DiscoveryService : IDiscoveryService
{
    private readonly IUdapClient _udapClient;
    private readonly ILogger<DiscoveryService> _logger;
    private readonly HttpClient _httpClient;
    private readonly UdapClientOptions _udapClientOptions;

    public DiscoveryService(IUdapClient udapClient, HttpClient httpClient, IOptionsMonitor<UdapClientOptions> udapClientOptions, ILogger<DiscoveryService> logger)
    {
        _udapClient = udapClient;
        _httpClient = httpClient;
        _udapClientOptions = udapClientOptions.CurrentValue;
        _logger = logger;
    }

    public Task<MetadataVerificationModel?> GetMetadataVerificationModel(string metadataUrl, string? community, CancellationToken token)
    {
        throw new NotImplementedException();
    }

    public Task<CertificateStatusViewModel?> UploadAnchorCertificate(string certBytes)
    {
        throw new NotImplementedException();
    }

    public Task<CertificateStatusViewModel?> LoadUdapOrgAnchor()
    {
        throw new NotImplementedException();
    }

    public async Task<CertificateStatusViewModel?> AnchorCertificateLoadStatus()
    {
        var result = new CertificateStatusViewModel
        {
            CertLoaded = CertLoadedEnum.Negative
        };

        try
        {

            var base64String = await SecureStorage.Default.GetAsync(UdapEdConstants.ANCHOR_CERTIFICATE);
            // var base64String = HttpContext.Session.GetString(UdapEdConstants.ANCHOR_CERTIFICATE);

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

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex.Message);

            return result;
        }
    }

    public Task<bool> SetBaseFhirUrl(string? baseFhirUrl, bool resetToken = false)
    {
        throw new NotImplementedException();
    }

    public Task<bool> SetClientHeaders(Dictionary<string, string> headers)
    {
        throw new NotImplementedException();
    }

    public Task<CertificateViewModel?> GetCertificateData(IEnumerable<string>? base64EncodedCertificate, CancellationToken token)
    {
        throw new NotImplementedException();
    }

    public Task<CertificateViewModel?> GetCertificateData(string? base64EncodedCertificate, CancellationToken token)
    {
        throw new NotImplementedException();
    }
}
