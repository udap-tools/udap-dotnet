#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Udap.Client.Client;
using Udap.Client.Configuration;
using Udap.Common.Certificates;
using Udap.Common.Extensions;
using Udap.Common.Models;
using Udap.Model;
using Udap.Util.Extensions;
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


    public async Task<MetadataVerificationModel?> GetMetadataVerificationModel(string metadataUrl, string? community,
        CancellationToken token)
    {
        try
        {
            var loadedStatus = await AnchorCertificateLoadStatus();

            if (loadedStatus != null && (loadedStatus.CertLoaded == CertLoadedEnum.Positive))
            {
                var anchorString = await SecureStorage.Default.GetAsync(UdapEdConstants.ANCHOR_CERTIFICATE);

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
                        result.Notifications.Add(
                            element.ChainElementStatus.Summarize(TrustChainValidator.DefaultProblemFlags));
                    _udapClient.Untrusted += certificate2 =>
                        result.Notifications.Add("Untrusted: " + certificate2.Subject);
                    _udapClient.TokenError += message => result.Notifications.Add("TokenError: " + message);

                    await _udapClient.ValidateResource(
                        metadataUrl,
                        trustAnchorStore,
                        community, token: token);

                    result.UdapServerMetaData = _udapClient.UdapServerMetaData;
                    await SecureStorage.Default.SetAsync(UdapEdConstants.BASE_URL, metadataUrl);

                    return result;
                }

                _logger.LogError("Missing anchor");

                return null;
            }
            else
            {
                var baseUrl = metadataUrl.EnsureTrailingSlash() + UdapConstants.Discovery.DiscoveryEndpoint;
                if (!string.IsNullOrEmpty(community))
                {
                    baseUrl += $"?{UdapConstants.Community}={community}";
                }

                _logger.LogDebug(baseUrl);
                var response = await _httpClient.GetStringAsync(baseUrl, token);
                var unvalidatedResult = JsonSerializer.Deserialize<UdapMetadata>(response);
                await SecureStorage.Default.SetAsync(UdapEdConstants.BASE_URL, baseUrl.GetBaseUrlFromMetadataUrl());

                var model = new MetadataVerificationModel
                {
                    UdapServerMetaData = unvalidatedResult,
                    Notifications = new List<string>
                        {
                            "No anchor loaded.  Un-Validated resource server."
                        }
                };

                return model;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get UDAP metadata");

            return null;
        }
    }

    public async Task<CertificateStatusViewModel?> UploadAnchorCertificate(string base64String)
    {
        var result = new CertificateStatusViewModel { CertLoaded = CertLoadedEnum.Negative };

        try
        {
            var certBytes = Convert.FromBase64String(base64String);
            var certificate = new X509Certificate2(certBytes);
            result.DistinguishedName = certificate.SubjectName.Name;
            result.Thumbprint = certificate.Thumbprint;
            result.CertLoaded = CertLoadedEnum.Positive;
            await SecureStorage.Default.SetAsync(UdapEdConstants.ANCHOR_CERTIFICATE, base64String);

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed loading certificate");
            _logger.LogDebug(ex,
                $"Failed loading certificate from {nameof(base64String)} {base64String}");

            return result;
        }
    }

    public async Task<CertificateStatusViewModel?> LoadUdapOrgAnchor()
    {
        var anchorCertificate = "http://certs.emrdirect.com/certs/EMRDirectTestCA.crt";

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
            await SecureStorage.Default.SetAsync(UdapEdConstants.ANCHOR_CERTIFICATE, Convert.ToBase64String(certBytes));

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed loading anchor from {anchorCertificate}", anchorCertificate);
            _logger.LogDebug(ex,
                $"Failed loading certificate from {nameof(anchorCertificate)} {anchorCertificate}");

            return result;
        }
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

    public async Task<bool> SetBaseFhirUrl(string? baseFhirUrl, bool resetToken = false)
    {
        if (resetToken)
        {
            SecureStorage.Default.Remove(UdapEdConstants.TOKEN);
        }

        if (string.IsNullOrEmpty(baseFhirUrl))
        {
            return false;
        }

        await SecureStorage.Default.SetAsync(UdapEdConstants.BASE_URL, baseFhirUrl.GetBaseUrlFromMetadataUrl());

        return true;
    }

    public Task<bool> SetClientHeaders(Dictionary<string, string> headers)
    {
        _udapClientOptions.Headers = headers;

        return Task.FromResult(true);
    }

    public async Task<CertificateViewModel?> GetCertificateData(IEnumerable<string>? base64EncodedCertificate, CancellationToken token)
    {
        try
        {
            await Task.Delay(1, token);
            var certBytes = Convert.FromBase64String(base64EncodedCertificate!.First());
            var cert = new X509Certificate2(certBytes);
            var result = new CertificateDisplayBuilder(cert).BuildCertificateDisplayData();

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load first certificate from list");
            return null;
        }
    }

    public async Task<CertificateViewModel?> GetCertificateData(string? base64EncodedCertificate, CancellationToken token)
    {
        try
        {
            await Task.Delay(1, token);
            var certBytes = Convert.FromBase64String(base64EncodedCertificate!);
            var cert = new X509Certificate2(certBytes);
            var result = new CertificateDisplayBuilder(cert).BuildCertificateDisplayData();

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load certificate");
            return null!;
        }
    }

    public async Task<string> GetFhirLabsCommunityList()
    {
        var communityResponse = await _httpClient.GetAsync("https://fhirlabs.net/fhir/r4/.well-known/udap/communities/ashtml");

        if (communityResponse.IsSuccessStatusCode)
        {
            return await communityResponse.Content.ReadAsStringAsync();
        }
        else
        {
            return "Failed to load https://fhirlabs.net/fhir/r4/.well-known/udap/communities/ashtml";
        }
    }
}
