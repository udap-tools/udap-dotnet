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
using IdentityModel.Client;
using Microsoft.IdentityModel.Tokens;
using Udap.Model;
using Udap.Model.Access;
using UdapClient.Shared.Model;

namespace UdapClient.Client.Services;

public class AccessService
{
    readonly HttpClient _httpClient;

    public AccessService(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public async Task<AccessCodeRequestResult?> Get(string authorizeQuery)
    {
        var response = await _httpClient.GetFromJsonAsync<AccessCodeRequestResult>($"/Access/{Base64UrlEncoder.Encode(authorizeQuery)}");
        
        return response;
    }

    public async Task<UdapAuthorizationCodeTokenRequest?> BuildRequestAccessTokenForAuthCode(
        string clientId,
        string tokenEndpointUrl,
        string password)
    {

        var model = new AccessTokenRequestModel
        {
            ClientId = clientId,
            TokenEndpointUrl = tokenEndpointUrl,
            Password = password
        };

        var result = await _httpClient.PostAsJsonAsync("Access/BuildRequestToken/authorization_code", model);

        result.EnsureSuccessStatusCode();

        if (!result.IsSuccessStatusCode)
        {
            Console.WriteLine(await result.Content.ReadAsStringAsync());

            return null;
        }

        return await result.Content.ReadFromJsonAsync<UdapAuthorizationCodeTokenRequest>();
    }

    
    public async Task<UdapClientCredentialsTokenRequest?> BuildRequestAccessTokenForClientCredentials(
        string clientId,
        string tokenEndpointUrl,
        string password)
    {
        var model = new AccessTokenRequestModel
        {
            ClientId = clientId,
            TokenEndpointUrl = tokenEndpointUrl,
            Password = password
        };

        var result = await _httpClient.PostAsJsonAsync("Access/BuildRequestToken/client_credentials", model);

        result.EnsureSuccessStatusCode();

        if (!result.IsSuccessStatusCode)
        {
            Console.WriteLine(await result.Content.ReadAsStringAsync());

            return null;
        }

        return await result.Content.ReadFromJsonAsync<UdapClientCredentialsTokenRequest>();
    }

    public async Task<string?> RequestAccessTokenForClientCredentials(UdapClientCredentialsTokenRequest request)
    {
        var result = await _httpClient.PostAsJsonAsync("Access/RequestToken/client_credentials", request);

        result.EnsureSuccessStatusCode();

        if (!result.IsSuccessStatusCode)
        {
            Console.WriteLine(await result.Content.ReadAsStringAsync());

            return null;
        }

        return await result.Content.ReadAsStringAsync();
    }

    public async Task<TokenResponseModel?> RequestAccessTokenForAuthorizationCode(UdapAuthorizationCodeTokenRequest request)
    {
        var result = await _httpClient.PostAsJsonAsync("Access/RequestToken/authorization_code", request);

        result.EnsureSuccessStatusCode();

        if (!result.IsSuccessStatusCode)
        {
            Console.WriteLine(await result.Content.ReadAsStringAsync());

            return null;
        }

        var tokenResponse = await result.Content.ReadFromJsonAsync<TokenResponseModel>();

        return tokenResponse;
    }
}
