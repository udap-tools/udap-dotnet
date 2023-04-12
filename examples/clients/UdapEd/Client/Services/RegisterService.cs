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
using static System.Net.WebRequestMethods;
using Task = System.Threading.Tasks.Task;

namespace UdapEd.Client.Services;

public class RegisterService
{
    readonly HttpClient _httpClient;

    public RegisterService(HttpClient httpClientClient)
    {
        _httpClient = httpClientClient;
    }

    public async Task UploadClientCert(string certBytes)
    {
        var result = await _httpClient.PostAsJsonAsync("Register/UploadClientCert", certBytes);

        result.EnsureSuccessStatusCode();
    }

    public async Task<RawSoftwareStatementAndHeader?> BuildSoftwareStatementForClientCredentials(
        UdapDynamicClientRegistrationDocument request, 
        string signingAlgorithm)
    {
        var result = await _httpClient.PostAsJsonAsync(
            $"Register/BuildSoftwareStatement/ClientCredentials?alg={signingAlgorithm}", 
            request);

        result.EnsureSuccessStatusCode();

        return await result.Content.ReadFromJsonAsync<RawSoftwareStatementAndHeader>();
    }

    public async Task<RawSoftwareStatementAndHeader?> BuildSoftwareStatementForAuthorizationCode(
        UdapDynamicClientRegistrationDocument request,
        string signingAlgorithm)
    {
        var result = await _httpClient.PostAsJsonAsync(
            $"Register/BuildSoftwareStatement/AuthorizationCode?alg={signingAlgorithm}", 
            request);
        result.EnsureSuccessStatusCode();

        return await result.Content.ReadFromJsonAsync<RawSoftwareStatementAndHeader>();
    }

    public async Task<UdapRegisterRequest?> BuildRequestBodyForClientCredentials(
        RawSoftwareStatementAndHeader? request,
        string signingAlgorithm)
    {
        var result = await _httpClient.PostAsJsonAsync($"Register/BuildRequestBody/ClientCredentials?alg={signingAlgorithm}", request);

        result.EnsureSuccessStatusCode();

        return await result.Content.ReadFromJsonAsync<UdapRegisterRequest>();
    }

    public async Task<UdapRegisterRequest?> BuildRequestBodyForAuthorizationCode(
        RawSoftwareStatementAndHeader? request,
        string signingAlgorithm)
    {
        var result = await _httpClient.PostAsJsonAsync($"Register/BuildRequestBody/AuthorizationCode?alg={signingAlgorithm}", request);

        result.EnsureSuccessStatusCode();

        return await result.Content.ReadFromJsonAsync<UdapRegisterRequest>();
    }

    public async Task<RegistrationResult?> Register(RegistrationRequest registrationRequest)
    {
        var result = await _httpClient.PostAsJsonAsync(
            "Register/Register",
            registrationRequest,
            new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull });

        if (!result.IsSuccessStatusCode)
        {
            var joe = await result.Content.ReadAsStringAsync();
            Console.WriteLine(joe);

            return new RegistrationResult
            {
                Success = false,
                ErrorMessage = joe
            };
        }

        return new RegistrationResult
        {
            Success = true,
            Document = await result.Content.ReadFromJsonAsync<RegistrationDocument>()
        };
    }

    public async Task<CertificateStatusViewModel?> ValidateCertificate(string password)
    {

        var result = await _httpClient.PostAsJsonAsync(
            "Register/ValidateCertificate",
            password);

        if (!result.IsSuccessStatusCode)
        {
            Console.WriteLine(await result.Content.ReadAsStringAsync());

            return new CertificateStatusViewModel
            {
                CertLoaded = CertLoadedEnum.Negative
            };
        }

        return await result.Content.ReadFromJsonAsync<CertificateStatusViewModel>();
    }

    public async Task<CertificateStatusViewModel?> ClientCertificateLoadStatus()
    {
        var response = await _httpClient.GetFromJsonAsync<CertificateStatusViewModel>("Register/IsClientCertificateLoaded");

        return response;
    }

    public async Task<CertificateStatusViewModel?> LoadTestCertificate()
    {
        var response = await _httpClient.PutAsJsonAsync("Register/UploadTestClientCert", "fhirlabs.net.client.pfx");

        if (!response.IsSuccessStatusCode)
        {
            Console.WriteLine(await response.Content.ReadAsStringAsync());
        }

        return await response.Content.ReadFromJsonAsync<CertificateStatusViewModel>();
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