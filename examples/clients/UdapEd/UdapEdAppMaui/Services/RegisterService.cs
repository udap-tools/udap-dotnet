#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Udap.Model;
using Udap.Model.Registration;
using Udap.Util.Extensions;
using UdapEd.Shared;
using UdapEd.Shared.Model;
using UdapEd.Shared.Services;
using Udap.Model.Statement;
using UdapEd.Shared.Extensions;
using UdapEd.Shared.Model.Registration;

namespace UdapEdAppMaui.Services;
internal class RegisterService : IRegisterService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<RegisterService> _logger;


    public RegisterService(HttpClient httpClient, ILogger<RegisterService> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
    }

    public async Task UploadClientCertificate(string certBytes)
    {
        await SecureStorage.Default.SetAsync(UdapEdConstants.CLIENT_CERTIFICATE, certBytes);
    }

    public async Task<RawSoftwareStatementAndHeader?> BuildSoftwareStatementForClientCredentials(
        UdapDynamicClientRegistrationDocument request, string signingAlgorithm)
    {
        var clientCertWithKey = await SecureStorage.Default.GetAsync(UdapEdConstants.CLIENT_CERTIFICATE_WITH_KEY);

        if (clientCertWithKey == null)
        {
            throw new Exception("Cannot find a certificate.  Reload the certificate.");
        }

        var certBytes = Convert.FromBase64String(clientCertWithKey);
        var clientCert = new X509Certificate2(certBytes, "ILikePasswords", X509KeyStorageFlags.Exportable);

        UdapDcrBuilderForClientCredentialsUnchecked dcrBuilder;

        if (request.GrantTypes == null || !request.GrantTypes.Any())
        {
            dcrBuilder = UdapDcrBuilderForClientCredentialsUnchecked
                .Cancel(clientCert);
        }
        else
        {
            dcrBuilder = UdapDcrBuilderForClientCredentialsUnchecked
                .Create(clientCert);
        }

        dcrBuilder.Document.Issuer = request.Issuer;
        dcrBuilder.Document.Subject = request.Subject;


        var document = dcrBuilder
            .WithAudience(request.Audience)
            .WithExpiration(request.Expiration)
            .WithJwtId(request.JwtId)
            .WithClientName(request.ClientName ?? UdapEdConstants.CLIENT_NAME)
            .WithContacts(request.Contacts)
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope(request.Scope ?? string.Empty)
            .Build();


        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build(signingAlgorithm);

        var tokenHandler = new JsonWebTokenHandler();
        var jsonToken = tokenHandler.ReadToken(signedSoftwareStatement);
        var requestToken = jsonToken as JsonWebToken;

        if (requestToken == null)
        {
            throw new Exception("Failed to read signed software statement using JsonWebTokenHandler");
        }

        var result = new RawSoftwareStatementAndHeader
        {
            Header = requestToken.EncodedHeader.DecodeJwtHeader(),
            SoftwareStatement = Base64UrlEncoder.Decode(requestToken.EncodedPayload),
            Scope = request.Scope
        };

        return result;
    }

    public async Task<RawSoftwareStatementAndHeader?> BuildSoftwareStatementForAuthorizationCode(UdapDynamicClientRegistrationDocument request, string signingAlgorithm)
    {
        var clientCertWithKey = await SecureStorage.Default.GetAsync(UdapEdConstants.CLIENT_CERTIFICATE_WITH_KEY);

        if (clientCertWithKey == null)
        {
            throw new Exception("Cannot find a certificate.  Reload the certificate.");
        }

        var certBytes = Convert.FromBase64String(clientCertWithKey);
        var clientCert = new X509Certificate2(certBytes, "ILikePasswords", X509KeyStorageFlags.Exportable);

        UdapDcrBuilderForAuthorizationCodeUnchecked dcrBuilder;

        if (request.GrantTypes == null || !request.GrantTypes.Any())
        {
            dcrBuilder = UdapDcrBuilderForAuthorizationCodeUnchecked
                .Cancel(clientCert);
        }
        else
        {
            dcrBuilder = UdapDcrBuilderForAuthorizationCodeUnchecked
                .Create(clientCert);
        }

        dcrBuilder.Document.Issuer = request.Issuer;
        dcrBuilder.Document.Subject = request.Subject;


        var document = dcrBuilder
            .WithAudience(request.Audience)
            .WithExpiration(request.Expiration)
            .WithJwtId(request.JwtId)
            .WithClientName(request.ClientName ?? UdapEdConstants.CLIENT_NAME)
            .WithContacts(request.Contacts)
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope(request.Scope ?? string.Empty)
            .WithResponseTypes(request.ResponseTypes)
            .WithRedirectUrls(request.RedirectUris?.ToMauiAppSchemes())
            .WithLogoUri(request.LogoUri ?? "https://udaped.fhirlabs.net/images/hl7/icon-fhir-32.png")
            .Build();

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build(signingAlgorithm);

        var tokenHandler = new JsonWebTokenHandler();
        var jsonToken = tokenHandler.ReadToken(signedSoftwareStatement);
        var requestToken = jsonToken as JsonWebToken;

        if (requestToken == null)
        {
            throw new Exception("Failed to read signed software statement using JsonWebTokenHandler");
        }

        var result = new RawSoftwareStatementAndHeader
        {
            Header = requestToken.EncodedHeader.DecodeJwtHeader(),
            SoftwareStatement = Base64UrlEncoder.Decode(requestToken.EncodedPayload),
            Scope = request.Scope
        };

        return result;
    }

    public async Task<UdapRegisterRequest?> BuildRequestBodyForClientCredentials(RawSoftwareStatementAndHeader? request, string signingAlgorithm)
    {
        var clientCertWithKey = await SecureStorage.Default.GetAsync(UdapEdConstants.CLIENT_CERTIFICATE_WITH_KEY);

        if (clientCertWithKey == null)
        {
            throw new Exception("Cannot find a certificate.  Reload the certificate.");
        }

        var certBytes = Convert.FromBase64String(clientCertWithKey);
        var clientCert = new X509Certificate2(certBytes, "ILikePasswords", X509KeyStorageFlags.Exportable);

        var document = JsonSerializer
            .Deserialize<UdapDynamicClientRegistrationDocument>(request.SoftwareStatement)!;

        UdapDcrBuilderForClientCredentialsUnchecked dcrBuilder;

        if (document.GrantTypes == null || !document.GrantTypes.Any())
        {
            dcrBuilder = UdapDcrBuilderForClientCredentialsUnchecked
                .Cancel(clientCert);
        }
        else
        {
            dcrBuilder = UdapDcrBuilderForClientCredentialsUnchecked
                .Create(clientCert);
        }


        dcrBuilder.Document.Issuer = document.Issuer;
        dcrBuilder.Document.Subject = document.Subject;

        dcrBuilder.WithAudience(document.Audience)
            .WithExpiration(document.Expiration)
            .WithJwtId(document.JwtId)
            .WithClientName(document.ClientName!)
            .WithContacts(document.Contacts)
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope(document.Scope);

        if (!request.SoftwareStatement.Contains(UdapConstants.RegistrationDocumentValues.GrantTypes))
        {
            dcrBuilder.Document.GrantTypes = null;
        }

        var signedSoftwareStatement = dcrBuilder.BuildSoftwareStatement(signingAlgorithm);

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        return requestBody;
    }

    public async Task<UdapRegisterRequest?> BuildRequestBodyForAuthorizationCode(RawSoftwareStatementAndHeader? request, string signingAlgorithm)
    {
        var clientCertWithKey = await SecureStorage.Default.GetAsync(UdapEdConstants.CLIENT_CERTIFICATE_WITH_KEY);

        if (clientCertWithKey == null)
        {
            throw new Exception("Cannot find a certificate.  Reload the certificate.");
        }

        var certBytes = Convert.FromBase64String(clientCertWithKey);
        var clientCert = new X509Certificate2(certBytes, "ILikePasswords", X509KeyStorageFlags.Exportable);

        var document = JsonSerializer
            .Deserialize<UdapDynamicClientRegistrationDocument>(request.SoftwareStatement)!;

        UdapDcrBuilderForAuthorizationCodeUnchecked dcrBuilder;

        if (document.GrantTypes == null || !document.GrantTypes.Any())
        {
            dcrBuilder = UdapDcrBuilderForAuthorizationCodeUnchecked
                .Cancel(clientCert);
        }
        else
        {
            dcrBuilder = UdapDcrBuilderForAuthorizationCodeUnchecked
                .Create(clientCert);

            dcrBuilder.Document.GrantTypes = document.GrantTypes;
        }

        dcrBuilder.Document.Issuer = document.Issuer;
        dcrBuilder.Document.Subject = document.Subject;

        dcrBuilder.WithAudience(document.Audience)
            .WithExpiration(document.Expiration)
            .WithJwtId(document.JwtId)
            .WithClientName(document.ClientName!)
            .WithContacts(document.Contacts)
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope(document.Scope!)
            .WithResponseTypes(document.ResponseTypes)
            .WithRedirectUrls(document.RedirectUris)
            .WithLogoUri(document.LogoUri!);



        var signedSoftwareStatement = dcrBuilder.BuildSoftwareStatement(signingAlgorithm);

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        return requestBody;
    }

    public async Task<ResultModel<RegistrationDocument>?> Register(RegistrationRequest registrationRequest)
    {
        if (registrationRequest.UdapRegisterRequest == null)
        {
            return new ResultModel<RegistrationDocument>(
                $"{nameof(registrationRequest.UdapRegisterRequest)} is Null.");
        }

        var content = new StringContent(
            JsonSerializer.Serialize(registrationRequest.UdapRegisterRequest, new JsonSerializerOptions
            {
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
            }),
            new MediaTypeHeaderValue("application/json"));

        //TODO: Centralize all registration in UdapClient.  See RegisterTieredClient
        var response = await _httpClient.PostAsync(registrationRequest.RegistrationEndpoint, content);


        if (!response.IsSuccessStatusCode)
        {
            var failResult = new ResultModel<RegistrationDocument?>(
                await response.Content.ReadAsStringAsync(),
                response.StatusCode,
                response.Version);

            return failResult!;
        }

        var resultRaw = await response.Content.ReadAsStringAsync();

        try
        {
            var result = new ResultModel<RegistrationDocument?>(
                JsonSerializer.Deserialize<RegistrationDocument>(resultRaw),
                response.StatusCode,
                response.Version);

            return result!;
        }

        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed Registration");
            _logger.LogError(resultRaw);

            return new ResultModel<RegistrationDocument>(ex.Message);
        }
    }

    public async Task<CertificateStatusViewModel?> ValidateCertificate(string password)
    {
        var result = new CertificateStatusViewModel
        {
            CertLoaded = CertLoadedEnum.Negative
        };

        var clientCertSession = await SecureStorage.Default.GetAsync(UdapEdConstants.CLIENT_CERTIFICATE);

        if (clientCertSession == null)
        {
            return new CertificateStatusViewModel
            {
                CertLoaded = CertLoadedEnum.Negative
            };
        }

        var certBytes = Convert.FromBase64String(clientCertSession);
        try
        {
            var certificate = new X509Certificate2(certBytes, password, X509KeyStorageFlags.Exportable);

            var clientCertWithKeyBytes = certificate.Export(X509ContentType.Pkcs12, "ILikePasswords");
            await SecureStorage.Default.SetAsync(UdapEdConstants.CLIENT_CERTIFICATE_WITH_KEY, Convert.ToBase64String(clientCertWithKeyBytes));
            result.DistinguishedName = certificate.SubjectName.Name;
            result.Thumbprint = certificate.Thumbprint;
            result.CertLoaded = CertLoadedEnum.Positive;

            if (certificate.NotAfter < DateTime.Now.Date)
            {
                result.CertLoaded = CertLoadedEnum.Expired;
            }

            result.SubjectAltNames = certificate
                .GetSubjectAltNames(n => n.TagNo == (int)X509Extensions.GeneralNameType.URI)
                .Select(tuple => tuple.Item2)
                .ToList();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex.Message);
            result.CertLoaded = CertLoadedEnum.InvalidPassword;
            return result;
        }

        return result;
    }

    public async Task<CertificateStatusViewModel?> ClientCertificateLoadStatus()
    {
        var result = new CertificateStatusViewModel
        {
            CertLoaded = CertLoadedEnum.Negative
        };

        try
        {
            var clientCertSession = await SecureStorage.Default.GetAsync(UdapEdConstants.CLIENT_CERTIFICATE);

            if (clientCertSession != null)
            {
                result.CertLoaded = CertLoadedEnum.InvalidPassword;
            }
            else
            {
                result.CertLoaded = CertLoadedEnum.Negative;
            }

            var certBytesWithKey = await SecureStorage.Default.GetAsync(UdapEdConstants.CLIENT_CERTIFICATE_WITH_KEY);

            if (certBytesWithKey != null)
            {
                var certBytes = Convert.FromBase64String(certBytesWithKey);
                var clientCert = new X509Certificate2(certBytes, "ILikePasswords", X509KeyStorageFlags.Exportable);
                result.DistinguishedName = clientCert.SubjectName.Name;
                result.Thumbprint = clientCert.Thumbprint;
                result.CertLoaded = CertLoadedEnum.Positive;

                if (clientCert.NotAfter < DateTime.Now.Date)
                {
                    result.CertLoaded = CertLoadedEnum.Expired;
                }

                result.SubjectAltNames = clientCert
                    .GetSubjectAltNames(n => n.TagNo == (int)X509Extensions.GeneralNameType.URI)
                    .Select(tuple => tuple.Item2)
                    .ToList();
            }

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex.Message);

            return result;
        }
    }

    public async Task<CertificateStatusViewModel?> LoadTestCertificate()
    {
        var result = new CertificateStatusViewModel
        {
            CertLoaded = CertLoadedEnum.Negative
        };

        try
        {
            await using var fileStream = await FileSystem.Current.OpenAppPackageFileAsync("fhirlabs.net.client.pfx");
            var certBytes = new byte[fileStream.Length];

            await fileStream.ReadAsync(certBytes, 0, certBytes.Length);

            var certificate = new X509Certificate2(certBytes, "udap-test", X509KeyStorageFlags.Exportable);
            var clientCertWithKeyBytes = certificate.Export(X509ContentType.Pkcs12, "ILikePasswords");
            await SecureStorage.Default.SetAsync(UdapEdConstants.CLIENT_CERTIFICATE_WITH_KEY, Convert.ToBase64String(clientCertWithKeyBytes));
            result.DistinguishedName = certificate.SubjectName.Name;
            result.Thumbprint = certificate.Thumbprint;
            result.CertLoaded = CertLoadedEnum.Positive;
            result.SubjectAltNames = certificate
                .GetSubjectAltNames(n => n.TagNo == (int)X509Extensions.GeneralNameType.URI)
                .Select(tuple => tuple.Item2)
                .ToList();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex.Message);
            result.CertLoaded = CertLoadedEnum.InvalidPassword;

            return result;
        }

        return result;
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
