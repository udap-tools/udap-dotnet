using System.Net.Http.Json;

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
}
