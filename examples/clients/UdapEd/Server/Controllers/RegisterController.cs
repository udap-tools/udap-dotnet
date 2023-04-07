#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net.Http.Headers;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using Udap.Model;
using Udap.Model.Registration;
using Udap.Model.Statement;
using Udap.Util.Extensions;
using UdapEd.Server.Extensions;
using UdapEd.Shared;
using UdapEd.Shared.Model;

namespace UdapEd.Server.Controllers;

[Route("[controller]")]
[EnableRateLimiting(RateLimitExtensions.Policy)]
public class RegisterController : Controller
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<RegisterController> _logger;
    

    public RegisterController(HttpClient httpClient, ILogger<RegisterController> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
    }

    [HttpPut("UploadTestClientCert")]
    public IActionResult UploadTestClientCert([FromBody] string testClientCert)
    {
        try
        {
            //todo secretManager
            var clientCertWithKeyBytes = new X509Certificate2(testClientCert, "udap-test", X509KeyStorageFlags.Exportable).Export(X509ContentType.Pkcs12);
            HttpContext.Session.SetString(UdapEdConstants.CLIENT_CERT_WITH_KEY, Convert.ToBase64String(clientCertWithKeyBytes));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex.Message);
            return Ok(CertLoadedEnum.InvalidPassword);
        }

        return Ok(CertLoadedEnum.Positive);
    }

    [HttpPost("UploadClientCert")]
    public IActionResult UploadClientCert([FromBody] string base64String)
    {
        HttpContext.Session.SetString(UdapEdConstants.CLIENT_CERT, base64String);
        
        return Ok();
    }

    [HttpPost("ValidateCertificate")]
    public IActionResult ValidateCertificate([FromBody] string password)
    {
        var clientCertSession = HttpContext.Session.GetString(UdapEdConstants.CLIENT_CERT);

        if (clientCertSession == null)
        {
            return Ok(CertLoadedEnum.Negative);
        }

        var certBytes = Convert.FromBase64String(clientCertSession);
        try
        {
            var clientCert = new X509Certificate2(certBytes, password, X509KeyStorageFlags.Exportable);

            var clientCertWithKeyBytes = clientCert.Export(X509ContentType.Pkcs12);
            HttpContext.Session.SetString(UdapEdConstants.CLIENT_CERT_WITH_KEY, Convert.ToBase64String(clientCertWithKeyBytes));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex.Message);
            return Ok(CertLoadedEnum.InvalidPassword);
        }

        return Ok(CertLoadedEnum.Positive);
    }

    [HttpGet("IsClientCertificateLoaded")]
    public IActionResult Get()
    {
        CertLoadedEnum result = CertLoadedEnum.Negative;

        try
        {
            var clientCertSession = HttpContext.Session.GetString(UdapEdConstants.CLIENT_CERT);

            if (clientCertSession != null)
            {
                result = CertLoadedEnum.InvalidPassword;
            }
            else
            {
                result = CertLoadedEnum.Negative;
            }

            var certBytesWithKey = HttpContext.Session.GetString(UdapEdConstants.CLIENT_CERT_WITH_KEY);

            if (certBytesWithKey != null)
            {
                result = CertLoadedEnum.Positive;
            }

            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex.Message);

            return Ok(result);
        }
    }

    [HttpPost("BuildSoftwareStatement/ClientCredentials")]
    public IActionResult BuildSoftwareStatementWithHeaderForClientCredentials([FromBody] UdapDynamicClientRegistrationDocument request)
    {
        var clientCertWithKey = HttpContext.Session.GetString(UdapEdConstants.CLIENT_CERT_WITH_KEY);

        if (clientCertWithKey == null)
        {
            return BadRequest("Cannot find a certificate.  Reload the certificate.");
        }

        var certBytes = Convert.FromBase64String(clientCertWithKey);
        var clientCert = new X509Certificate2(certBytes);
        
        var document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            //TODO: this only gets the first SubAltName
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
                .Build();

        var tokenHandler = new JsonWebTokenHandler();
        var jsonToken = tokenHandler.ReadToken(signedSoftwareStatement);
        var requestToken = jsonToken as JsonWebToken;

        if (requestToken == null)
        {
            return BadRequest("Failed to read signed software statement using JsonWebTokenHandler");
        }
        
        var result = new RawSoftwareStatementAndHeader
        {
            Header = requestToken.EncodedHeader.DecodeJwtHeader(),
            SoftwareStatement = Base64UrlEncoder.Decode(requestToken.EncodedPayload),
            Scope = request.Scope
        };
        
        return Ok(result);
    }

    

    [HttpPost("BuildSoftwareStatement/AuthorizationCode")]
    public IActionResult BuildSoftwareStatementWithHeaderForAuthorizationCode([FromBody] UdapDynamicClientRegistrationDocument request)
    {
        var clientCertWithKey = HttpContext.Session.GetString(UdapEdConstants.CLIENT_CERT_WITH_KEY);

        if (clientCertWithKey == null)
        {
            return BadRequest("Cannot find a certificate.  Reload the certificate.");
        }

        var certBytes = Convert.FromBase64String(clientCertWithKey);
        var clientCert = new X509Certificate2(certBytes);

        var document = UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithAudience(request.Audience)
            .WithExpiration(request.Expiration)
            .WithJwtId(request.JwtId)
            .WithClientName(request.ClientName ?? UdapEdConstants.CLIENT_NAME)
            .WithContacts(request.Contacts)
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope(request.Scope ?? string.Empty)
            .WithResponseTypes(request.ResponseTypes)
            .WithRedirectUrls(request.RedirectUris)
            .Build();
    
        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        var tokenHandler = new JsonWebTokenHandler();
        var jsonToken = tokenHandler.ReadToken(signedSoftwareStatement);
        var requestToken = jsonToken as JsonWebToken;

        if (requestToken == null)
        {
            return BadRequest("Failed to read signed software statement using JsonWebTokenHandler");
        }

        var result = new RawSoftwareStatementAndHeader
        {
            Header = requestToken.EncodedHeader.DecodeJwtHeader(),
            SoftwareStatement = Base64UrlEncoder.Decode(requestToken.EncodedPayload),
            Scope = request.Scope
        };
        
        return Ok(result);
    }

    [HttpPost("BuildRequestBody/ClientCredentials")]
    public IActionResult BuildRequestBodyForClientCredentials([FromBody] RawSoftwareStatementAndHeader request)
    {
        var clientCertWithKey = HttpContext.Session.GetString(UdapEdConstants.CLIENT_CERT_WITH_KEY);
        
        if (clientCertWithKey == null)
        {
            return BadRequest("Cannot find a certificate.  Reload the certificate.");
        }

        var certBytes = Convert.FromBase64String(clientCertWithKey);
        var clientCert = new X509Certificate2(certBytes);
        
        var document = JsonSerializer
            .Deserialize<UdapDynamicClientRegistrationDocument>(request.SoftwareStatement)!;

        var signedSoftwareStatement = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            //TODO: this only gets the first SubAltName
            .WithAudience(document.Audience)
            .WithExpiration(document.Expiration)
            .WithJwtId(document.JwtId)
            .WithClientName(document.ClientName!)
            .WithContacts(document.Contacts)
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope(document.Scope!)
            .BuildSoftwareStatement();
        
        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        return Ok(requestBody);
    }

    [HttpPost("BuildRequestBody/AuthorizationCode")]
    public IActionResult BuildRequestBodyForAuthorizationCode([FromBody] RawSoftwareStatementAndHeader request)
    {
        var clientCertWithKey = HttpContext.Session.GetString(UdapEdConstants.CLIENT_CERT_WITH_KEY);
    
        if (clientCertWithKey == null)
        {
            return BadRequest("Cannot find a certificate.  Reload the certificate.");
        }
    
        var certBytes = Convert.FromBase64String(clientCertWithKey);
        var clientCert = new X509Certificate2(certBytes);

        var document = JsonSerializer
            .Deserialize<UdapDynamicClientRegistrationDocument>(request.SoftwareStatement)!;
        
        var signedSoftwareStatement = UdapDcrBuilderForAuthorizationCode
                .Create(clientCert)
                .WithAudience(document.Audience)
                .WithExpiration(document.Expiration)
                .WithJwtId(document.JwtId)
                .WithClientName(document.ClientName!)
                .WithContacts(document.Contacts)
                .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
                .WithScope(document.Scope!)
                .WithResponseTypes(document.ResponseTypes)
                .WithRedirectUrls(document.RedirectUris)
                .BuildSoftwareStatement();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );
    
        return Ok(requestBody);
    }

    [HttpPost("Register")]
    public async Task<IActionResult> Register([FromBody] RegistrationRequest request)
    {
        if (request.UdapRegisterRequest == null)
        {
            return BadRequest($"{nameof(request.UdapRegisterRequest)} is Null.");
        }

        var content = new StringContent(
            JsonSerializer.Serialize(request.UdapRegisterRequest, new JsonSerializerOptions
            {
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
            }), 
            new MediaTypeHeaderValue("application/json"));

        var response = await _httpClient.PostAsync(request.RegistrationEndpoint, content);
        
        if (!response.IsSuccessStatusCode)
        {
            return BadRequest(await response.Content.ReadAsStringAsync());
        }

        var result = await response.Content
            .ReadFromJsonAsync<RegistrationDocument>();

        return Ok(JsonSerializer.Serialize(result));
    }
}