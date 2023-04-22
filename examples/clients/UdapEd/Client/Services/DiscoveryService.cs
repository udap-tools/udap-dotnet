#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net.Http.Json;
using Microsoft.IdentityModel.Tokens;
using UdapEd.Shared.Model;
using UdapEd.Shared.Model.Discovery;

namespace UdapEd.Client.Services;

public class DiscoveryService
{
    readonly HttpClient _httpClient;

    public DiscoveryService(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public async Task<MetadataVerificationModel?> GetMetadataVerificationModel(string metadataUrl, CancellationToken token)
    {
        try
        {
            var udapMetadataUrl = $"Metadata?metadataUrl={Base64UrlEncoder.Encode(metadataUrl) }";
            var result = await _httpClient.GetFromJsonAsync<MetadataVerificationModel>(udapMetadataUrl, token);

            return result;
        }
        catch (Exception ex)
        {
            return null;
        }
    }

    public async Task<CertificateStatusViewModel?> UploadAnchorCertificate(string certBytes)
    {
        var result = await _httpClient.PostAsJsonAsync("Metadata/UploadAnchorCertificate", certBytes);
        result.EnsureSuccessStatusCode();

        return await result.Content.ReadFromJsonAsync<CertificateStatusViewModel>();
    }

    public async Task<CertificateStatusViewModel?> AnchorCertificateLoadStatus()
    {
        var response = await _httpClient.GetFromJsonAsync<CertificateStatusViewModel>("Metadata/IsAnchorCertificateLoaded");

        return response;
    }

    public async Task<bool> SetBaseFhirUrl(string? baseFhirUrl, bool resetToken = false)
    {
        var response = await _httpClient.PutAsJsonAsync($"Metadata?resetToken={resetToken}", baseFhirUrl);

        if (response.IsSuccessStatusCode)
        {
            return true;
        }

        return false;
    }

    public async Task<CertificateViewModel?> GetCertificateData(IEnumerable<string>? base64EncodedCertificate,
        CancellationToken token)
    {
        try
        {
            var udapMetadataUrl = $"Metadata/CertificateDisplayFromJwtHeader";
            var result = await _httpClient.PostAsJsonAsync(udapMetadataUrl, base64EncodedCertificate, cancellationToken: token);

            result.EnsureSuccessStatusCode();

            return await result.Content.ReadFromJsonAsync<CertificateViewModel>(cancellationToken: token);
        }
        catch (Exception ex)
        {
            return null;
        }
    }

    public async Task<CertificateViewModel?> GetCertificateData(string? base64EncodedCertificate,
        CancellationToken token)
    {
        try
        {
            var udapMetadataUrl = $"Metadata/CertificateDisplay";
            var result = await _httpClient.PostAsJsonAsync(udapMetadataUrl, base64EncodedCertificate, cancellationToken: token);

            result.EnsureSuccessStatusCode();

            return await result.Content.ReadFromJsonAsync<CertificateViewModel>(cancellationToken: token);
        }
        catch (Exception ex)
        {
            return null;
        }
    }
}