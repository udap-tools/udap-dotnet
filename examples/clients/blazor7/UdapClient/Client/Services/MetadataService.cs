#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Org.BouncyCastle.Asn1.Ocsp;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Udap.Model;
using Udap.Model.Registration;
using UdapClient.Shared.Model;

namespace UdapClient.Client.Services;

public class MetadataService
{
    readonly HttpClient _http;

    public MetadataService(HttpClient http)
    {
        _http = http;
    }

    public async Task<UdapMetadata?> GetMetadata(string metadataUrl)
    {
        var result = await _http.GetFromJsonAsync<UdapMetadata>($"Metadata?metadataUrl={metadataUrl}");
        
        return result;
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

    public async Task<UdapRegisterRequest?> BuildRequestBody(BuildSoftwareStatementRequest request)
    {
        var result = await _http.PostAsJsonAsync("Metadata/BuildRequestBody", request);

        result.EnsureSuccessStatusCode();

        return await result.Content.ReadFromJsonAsync<UdapRegisterRequest>();
    }

    public async Task<UdapDynamicClientRegistrationDocument?> Register(RegistrationRequest registrationRequest)
    {
        var result = await _http.PostAsJsonAsync(
            "Metadata/Register", 
            registrationRequest, 
            new JsonSerializerOptions{DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull});

        if (!result.IsSuccessStatusCode)
        {
            Console.WriteLine(await result.Content.ReadAsStringAsync());
        }
        
        return await result.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
    }
}
