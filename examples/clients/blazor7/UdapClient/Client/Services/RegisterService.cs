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
using System.Text.Json.Serialization;
using Udap.Model;
using Udap.Model.Registration;
using UdapClient.Shared.Model;

namespace UdapClient.Client.Services;

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

    public async Task<string> BuildSoftwareStatement(BuildSoftwareStatementRequest request)
    {
        var result = await _http.PostAsJsonAsync("Register/BuildSoftwareStatement", request);

        result.EnsureSuccessStatusCode();

        return await result.Content.ReadAsStringAsync();
    }

    public async Task<UdapRegisterRequest?> BuildRequestBody(BuildSoftwareStatementRequest request)
    {
        var result = await _http.PostAsJsonAsync("Register/BuildRequestBody", request);

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
}