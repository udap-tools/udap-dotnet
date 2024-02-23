#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net.Http.Json;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using Udap.Model;
using Udap.Model.Registration;
using Udap.Util.Extensions;
using UdapEd.Shared.Model;
using UdapEd.Shared.Services;
using Task = System.Threading.Tasks.Task;

namespace UdapEd.Client.Services;

public class RegisterService : IRegisterService
{
    readonly HttpClient _httpClient;

    public RegisterService(HttpClient httpClientClient)
    {
        _httpClient = httpClientClient;
    }

    public async Task UploadClientCertificate(string certBytes)
    {
        var result = await _httpClient.PostAsJsonAsync("Register/UploadClientCertificate", certBytes);
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

    public async Task<ResultModel<RegistrationDocument>?> Register(RegistrationRequest registrationRequest)
    {
        var innerResponse = await _httpClient.PostAsJsonAsync(
            "Register/Register",
            registrationRequest,
            new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull });

        if (!innerResponse.IsSuccessStatusCode)
        {
            var error = await innerResponse.Content.ReadAsStringAsync();
            Console.WriteLine(error);

            return new ResultModel<RegistrationDocument>(error, innerResponse.StatusCode, innerResponse.Version);
        }

        var resultModel = await innerResponse.Content.ReadFromJsonAsync<ResultModel<RegistrationDocument>>();

        if (resultModel != null && resultModel.ErrorMessage != null)
        {
            var dcrResponseError =
                JsonSerializer.Deserialize<UdapDynamicClientRegistrationErrorResponse>(resultModel.ErrorMessage);

            resultModel.ErrorMessage =
                JsonSerializer.Serialize(dcrResponseError, new JsonSerializerOptions { WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping});
        }

        return resultModel;
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
        var response = await _httpClient.PutAsJsonAsync("Register/UploadTestClientCertificate", "fhirlabs.net.client.pfx");

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

    public string GetScopesForAuthorizationCodeB2B(ICollection<string>? scopes, bool tieredOauth = false)
    {
        var enrichScopes = scopes == null ? new List<string>() : scopes.ToList();

        if (tieredOauth)
        {
            if (!enrichScopes.Contains(UdapConstants.StandardScopes.Udap))
            {
                enrichScopes.Insert(0, UdapConstants.StandardScopes.Udap);
            }
        }

        if (enrichScopes.Any())
        {
            return enrichScopes
                .Where(s => !s.StartsWith("system") && !s.StartsWith("user"))
                .Take(10).ToList()
                .ToSpaceSeparatedString();
        }

        return "openid";
    }

    public string GetScopesForAuthorizationCodeConsumer(ICollection<string>? scopes, bool tieredOauth = false)
    {
        var enrichScopes = scopes == null ? new List<string>() : scopes.ToList();

        if (tieredOauth)
        {
            if (!enrichScopes.Contains(UdapConstants.StandardScopes.Udap))
            {
                enrichScopes.Insert(0, UdapConstants.StandardScopes.Udap);
            }
        }

        if (enrichScopes.Any())
        {
            return enrichScopes
                .Where(s => !s.StartsWith("system") && !s.StartsWith("patient"))
                .Take(10).ToList()
                .ToSpaceSeparatedString();
        }

        return "openid";
    }
}