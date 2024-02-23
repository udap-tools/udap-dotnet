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

namespace UdapEd.Shared.Services;

public interface IRegisterService
{
    Task UploadClientCertificate(string certBytes);

    Task<RawSoftwareStatementAndHeader?> BuildSoftwareStatementForClientCredentials(
        UdapDynamicClientRegistrationDocument request, 
        string signingAlgorithm);

    Task<RawSoftwareStatementAndHeader?> BuildSoftwareStatementForAuthorizationCode(
        UdapDynamicClientRegistrationDocument request,
        string signingAlgorithm);

    Task<UdapRegisterRequest?> BuildRequestBodyForClientCredentials(
        RawSoftwareStatementAndHeader? request,
        string signingAlgorithm);

    Task<UdapRegisterRequest?> BuildRequestBodyForAuthorizationCode(
        RawSoftwareStatementAndHeader? request,
        string signingAlgorithm);

    Task<ResultModel<RegistrationDocument>?> Register(RegistrationRequest registrationRequest);
    Task<CertificateStatusViewModel?> ValidateCertificate(string password);
    Task<CertificateStatusViewModel?> ClientCertificateLoadStatus();
    Task<CertificateStatusViewModel?> LoadTestCertificate();

    /// <summary>
    /// This service currently gets all scopes from Metadata published supported scopes.
    /// In the future we could maintain session data or local data to retain previous
    /// user preferences.
    /// </summary>
    /// <param name="scopes"></param>
    /// <returns></returns>
    /// <exception cref="NotImplementedException"></exception>
    string GetScopes(ICollection<string>? scopes);

    string? GetScopesForClientCredentials(ICollection<string>? scopes);
    string GetScopesForAuthorizationCodeB2B(ICollection<string>? scopes, bool tieredOauth = false);
    string GetScopesForAuthorizationCodeConsumer(ICollection<string>? scopes, bool tieredOauth = false);
}