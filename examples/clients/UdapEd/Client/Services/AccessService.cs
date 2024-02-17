#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using UdapEd.Shared.Model;
using UdapEd.Shared.Services;

namespace UdapEd.Client.Services;

public class AccessService : IAccessService
{
    readonly HttpClient _httpClient;
    private readonly ILogger<AccessService> _logger;

    public AccessService(HttpClient httpClient, ILogger<AccessService> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
    }

    public async Task<AccessCodeRequestResult?> Get(string authorizeQuery)
    {
        var response = await _httpClient
            .GetFromJsonAsync<AccessCodeRequestResult>(
                $"/Access/{Base64UrlEncoder.Encode(authorizeQuery)}");
        
        return response;
    }

    public async Task<UdapAuthorizationCodeTokenRequestModel?> BuildRequestAccessTokenForAuthCode(
        AuthorizationCodeTokenRequestModel tokenRequestModel,
        string signingAlgorithm)
    {
        var result = await _httpClient.PostAsJsonAsync(
            $"Access/BuildRequestToken/authorization_code?alg={signingAlgorithm}", tokenRequestModel);

        if (!result.IsSuccessStatusCode)
        {
            Console.WriteLine(await result.Content.ReadAsStringAsync());

            return null;
        }

        var response = JsonSerializer.Deserialize<UdapAuthorizationCodeTokenRequestModel>(
            await result.Content.ReadAsStringAsync(),
            new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });

        return response;
    }

    
    public async Task<UdapClientCredentialsTokenRequestModel?> BuildRequestAccessTokenForClientCredentials(
        ClientCredentialsTokenRequestModel tokenRequestModel,
        string signingAlgorithm)
    {
        var result = await _httpClient.PostAsJsonAsync(
            $"Access/BuildRequestToken/client_credentials?alg={signingAlgorithm}", tokenRequestModel);
        
        if (!result.IsSuccessStatusCode)
        {
            Console.WriteLine(await result.Content.ReadAsStringAsync());

            return null;
        }

        return await result.Content.ReadFromJsonAsync<UdapClientCredentialsTokenRequestModel>(
            new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });
    }

    public async Task<TokenResponseModel?> RequestAccessTokenForClientCredentials(UdapClientCredentialsTokenRequestModel request)
    {
        var result = await _httpClient.PostAsJsonAsync("Access/RequestToken/client_credentials", request);

        if (!result.IsSuccessStatusCode)
        {
            Console.WriteLine(await result.Content.ReadAsStringAsync());

            return null;
        }

        return await result.Content.ReadFromJsonAsync<TokenResponseModel>();
    }

    public async Task<TokenResponseModel?> RequestAccessTokenForAuthorizationCode(UdapAuthorizationCodeTokenRequestModel request)
    {
        var result = await _httpClient.PostAsJsonAsync("Access/RequestToken/authorization_code", request);
        
        if (!result.IsSuccessStatusCode)
        {
            Console.WriteLine(await result.Content.ReadAsStringAsync());

            return null;
        }

        var tokenResponse = await result.Content.ReadFromJsonAsync<TokenResponseModel>();

        return tokenResponse;
    }
}
