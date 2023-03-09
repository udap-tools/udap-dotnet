#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net.Http.Json;
using Udap.Model;

namespace UdapEd.Client.Services;

public class DiscoveryService
{
    readonly HttpClient _http;

    public DiscoveryService(HttpClient http)
    {
        _http = http;
    }

    public async Task<UdapMetadata?> GetMetadata(string? metadataUrl, CancellationToken token)
    {
        try
        {
            var udapMetadataUrl = $"Metadata?metadataUrl={metadataUrl}";
            var result = await _http.GetFromJsonAsync<UdapMetadata>(udapMetadataUrl, token);

            return result;
        }
        catch (Exception ex)
        {
            return null;
        }
    }
}