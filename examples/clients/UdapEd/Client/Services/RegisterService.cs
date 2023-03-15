#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Udap.Model.Registration;
using Udap.Util.Extensions;
using UdapEd.Shared.Model;

namespace UdapEd.Client.Services;

public class RegisterService
{
    readonly HttpClient _http;

    public RegisterService(HttpClient http)
    {
        _http = http;
    }

    public async Task UploadClientCert(string certBytes)
    {
        var result = await _http.PostAsJsonAsync("Register/UploadClientCert", certBytes);

        result.EnsureSuccessStatusCode();
    }

    public async Task<RawSoftwareStatementAndHeader?> BuildSoftwareStatementForClientCredentials(UdapDynamicClientRegistrationDocument request)
    {
        var result = await _http.PostAsJsonAsync("Register/BuildSoftwareStatement/ClientCredentials", request);

        result.EnsureSuccessStatusCode();

        return await result.Content.ReadFromJsonAsync<RawSoftwareStatementAndHeader>();
    }

    public async Task<RawSoftwareStatementAndHeader?> BuildSoftwareStatementForAuthorizationCode(UdapDynamicClientRegistrationDocument request)
    {
        var result = await _http.PostAsJsonAsync("Register/BuildSoftwareStatement/AuthorizationCode", request);

        result.EnsureSuccessStatusCode();

        return await result.Content.ReadFromJsonAsync<RawSoftwareStatementAndHeader>();
    }

    public async Task<UdapRegisterRequest?> BuildRequestBodyForClientCredentials(RawSoftwareStatementAndHeader? request)
    {
        var result = await _http.PostAsJsonAsync("Register/BuildRequestBody/ClientCredentials", request);

        result.EnsureSuccessStatusCode();

        return await result.Content.ReadFromJsonAsync<UdapRegisterRequest>();
    }

    public async Task<UdapRegisterRequest?> BuildRequestBodyForAuthorizationCode(RawSoftwareStatementAndHeader? request)
    {
        var result = await _http.PostAsJsonAsync("Register/BuildRequestBody/AuthorizationCode", request);

        result.EnsureSuccessStatusCode();

        return await result.Content.ReadFromJsonAsync<UdapRegisterRequest>();
    }

    public async Task<RegistrationResult?> Register(RegistrationRequest registrationRequest)
    {
        var result = await _http.PostAsJsonAsync(
            "Register/Register",
            registrationRequest,
            new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull });

        if (!result.IsSuccessStatusCode)
        {
            Console.WriteLine(await result.Content.ReadAsStringAsync());

            return new RegistrationResult
            {
                Success = false,
                ErrorMessage = await result.Content.ReadAsStringAsync()
            };
        }

        return new RegistrationResult
        {
            Success = true,
            Document = await result.Content.ReadFromJsonAsync<RegistrationDocument>()
        };
    }

    public async Task<CertLoadedEnum> ValidateCertificate(string password)
    {
        var result = await _http.PostAsJsonAsync(
            "Register/ValidateCertificate",
            password);

        if (!result.IsSuccessStatusCode)
        {
            Console.WriteLine(await result.Content.ReadAsStringAsync());

            return CertLoadedEnum.Negative;
        }

        return await result.Content.ReadFromJsonAsync<CertLoadedEnum>();
    }

    public async Task<CertLoadedEnum> ClientCertificateLoadStatus()
    {
        var response = await _http.GetFromJsonAsync<CertLoadedEnum>("Register/IsClientCertificateLoaded");

        return response;
    }

    public async Task<CertLoadedEnum> LoadTestCertificate()
    {
        var response = await _http.PutAsJsonAsync("Register/UploadTestClientCert", "fhirlabs.net.client.pfx");

        if (!response.IsSuccessStatusCode)
        {
            Console.WriteLine(await response.Content.ReadAsStringAsync());
        }

        return await response.Content.ReadFromJsonAsync<CertLoadedEnum>();
    }

    /// <summary>
    /// This service currently gets all scopes from Metadata published supported scopes.
    /// In the future we could maintain session data or local data to retain previous
    /// user preferences.
    /// </summary>
    /// <param name="scopes"></param>
    /// <returns></returns>
    /// <exception cref="NotImplementedException"></exception>
    public string GetScopes(ICollection<string>? scopes)
    {
        return scopes.ToSpaceSeparatedString();
    }

    public string? GetScopesForClientCredentials(ICollection<string>? scopes)
    {
        if (scopes != null)
        {
            return scopes
                .Where(s => !s.StartsWith("user") &&
                            !s.StartsWith("patient") &&
                            !s.StartsWith("openid"))
                .Take(10).ToList()
                .ToSpaceSeparatedString();
        }

        return null;
    }

    public string? GetScopesForAuthorizationCode(ICollection<string>? scopes)
    {
        if (scopes != null)
        {
            return scopes
                .Where(s => !s.StartsWith("system"))
                .Take(10).ToList()
                .ToSpaceSeparatedString();
        }

        return "openid";
    }
}