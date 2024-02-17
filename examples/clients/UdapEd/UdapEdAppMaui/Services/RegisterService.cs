#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Udap.Model.Registration;
using UdapEd.Shared.Model;
using UdapEd.Shared.Services;

namespace UdapEdAppMaui.Services;
internal class RegisterService : IRegisterService
{
    public Task UploadClientCertificate(string certBytes)
    {
        throw new NotImplementedException();
    }

    public Task<RawSoftwareStatementAndHeader?> BuildSoftwareStatementForClientCredentials(UdapDynamicClientRegistrationDocument request, string signingAlgorithm)
    {
        throw new NotImplementedException();
    }

    public Task<RawSoftwareStatementAndHeader?> BuildSoftwareStatementForAuthorizationCode(UdapDynamicClientRegistrationDocument request, string signingAlgorithm)
    {
        throw new NotImplementedException();
    }

    public Task<UdapRegisterRequest?> BuildRequestBodyForClientCredentials(RawSoftwareStatementAndHeader? request, string signingAlgorithm)
    {
        throw new NotImplementedException();
    }

    public Task<UdapRegisterRequest?> BuildRequestBodyForAuthorizationCode(RawSoftwareStatementAndHeader? request, string signingAlgorithm)
    {
        throw new NotImplementedException();
    }

    public Task<ResultModel<RegistrationDocument>?> Register(RegistrationRequest registrationRequest)
    {
        throw new NotImplementedException();
    }

    public Task<CertificateStatusViewModel?> ValidateCertificate(string password)
    {
        throw new NotImplementedException();
    }

    public Task<CertificateStatusViewModel?> ClientCertificateLoadStatus()
    {
        throw new NotImplementedException();
    }

    public Task<CertificateStatusViewModel?> LoadTestCertificate()
    {
        throw new NotImplementedException();
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
        throw new NotImplementedException();
    }

    public string? GetScopesForClientCredentials(ICollection<string>? scopes)
    {
        throw new NotImplementedException();
    }

    public string GetScopesForAuthorizationCodeB2B(ICollection<string>? scopes, bool tieredOauth = false)
    {
        throw new NotImplementedException();
    }

    public string GetScopesForAuthorizationCodeConsumer(ICollection<string>? scopes, bool tieredOauth = false)
    {
        throw new NotImplementedException();
    }
}
