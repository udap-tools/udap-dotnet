#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net.Http.Json;
using UdapClient.Shared.Model;

namespace UdapClient.Client.Services;

public class MetadataService
{
    readonly HttpClient _http;

    public MetadataService(HttpClient http)
    {
        _http = http;
    }
    
    public async Task UploadClientCert(string certBytes)
    {
        var result = await _http.PostAsJsonAsync("Metadata/UploadClientCert", certBytes);

        result.EnsureSuccessStatusCode();
    }

    public async Task<string> BuildSoftwareStatement(BuildSoftwareStatementRequest request)
    {
        var result = await _http.PostAsJsonAsync("Metadata/BuildSoftwareStatement", request);

        result.EnsureSuccessStatusCode();

        return await result.Content.ReadAsStringAsync();
    }

    public async Task<string> BuildRequestBody(BuildSoftwareStatementRequest request)
    {
        var result = await _http.PostAsJsonAsync("Metadata/BuildRequestBody", request);

        result.EnsureSuccessStatusCode();

        return await result.Content.ReadAsStringAsync();
    }
}
