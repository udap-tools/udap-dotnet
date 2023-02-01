#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Udap.Model;
using Udap.Model.Registration;
using Udap.Util.Extensions;
using UdapClient.Shared.Model;

namespace UdapClient.Server.Controllers;

[Route("[controller]")]
[ApiController]
public class RegisterController : ControllerBase
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<RegisterController> _logger;
    

    public RegisterController(HttpClient httpClient, ILogger<RegisterController> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
    }

    [HttpPost("UploadClientCert")]
    public IActionResult UploadClientCert([FromBody] string base64String)
    {
        HttpContext.Session.SetString(Constants.CLIENT_CERT, base64String);
        
        return Ok();
    }

    [HttpPost("ValidateCertificate")]
    public IActionResult ValidateCertificate([FromBody] string password)
    {
        var clientCertSession = HttpContext.Session.GetString(Constants.CLIENT_CERT);

        if (clientCertSession == null)
        {
            return Ok(CertLoadedEnum.Negative);
        }

        var certBytes = Convert.FromBase64String(clientCertSession);
        try
        {
            var clientCert = new X509Certificate2(certBytes, password, X509KeyStorageFlags.Exportable);

            var clientCertWithKeyBytes = clientCert.Export(X509ContentType.Pkcs12);
            HttpContext.Session.SetString(Constants.CLIENT_CERT_WITH_KEY, Convert.ToBase64String(clientCertWithKeyBytes));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex.Message);
            return Ok(CertLoadedEnum.InvalidPassword);
        }

        return Ok(CertLoadedEnum.Positive);
    }

    [HttpGet("IsClientCertificateLoaded")]
    public async Task<IActionResult> Get()
    {
        CertLoadedEnum result = CertLoadedEnum.Negative;

        try
        {
            var clientCertSession = HttpContext.Session.GetString(Constants.CLIENT_CERT);

            if (clientCertSession != null)
            {
                result = CertLoadedEnum.InvalidPassword;
            }
            else
            {
                result = CertLoadedEnum.Negative;
            }

            var certBytesWithKey = HttpContext.Session.GetString(Constants.CLIENT_CERT_WITH_KEY);

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

    

    [HttpPost("BuildSoftwareStatement")]
    public IActionResult BuildSoftwareStatementWithHeader([FromBody] BuildSoftwareStatementRequest request)
    {
        var certBytes = Convert.FromBase64String(HttpContext.Session.GetString(Constants.CLIENT_CERT_WITH_KEY));
        var clientCert = new X509Certificate2(certBytes);
        var securityKey = new X509SecurityKey(clientCert);
        var signingCredentials = new SigningCredentials(securityKey, UdapConstants.SupportedAlgorithm.RS256);

        var certBase64 = Convert.ToBase64String(clientCert.Export(X509ContentType.Cert));
        var jwtHeader = new JwtHeader
            {
                { "alg", signingCredentials.Algorithm },
                { "x5c", new[] { certBase64 } }
            };

        UdapDynamicClientRegistrationDocument document;

        if (request.Oauth2Flow == Oauth2FlowEnum.client_credentials)
        {
            document = UdapDcrBuilderForClientCredentials
                .Create(clientCert)
                //TODO: this only gets the first SubAltName
                .WithAudience(request.Audience)
                .WithExpiration(TimeSpan.FromMinutes(5))
                .WithJwtId()
                .WithClientName("FhirLabs Client")
                .WithContacts(new HashSet<string>
                {
                    "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
                })
                .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
                .WithScope("system/Patient.* system/Practitioner.read")
                .Build();
        }
        else
        {
            document = UdapDcrBuilderForAuthorizationCode
                .Create(clientCert)
                .WithAudience(request.Audience)
                .WithExpiration(TimeSpan.FromMinutes(5))
                .WithJwtId()
                .WithClientName("FhirLabs Client")
                .WithContacts(new HashSet<string>
                {
                    "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
                })
                .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
                .WithScope("system/Patient.* system/Practitioner.read openid profile offline_access")
                .WithResponseTypes(new HashSet<string> { "code" })
                .WithRedirectUrls(new List<string> { "https://localhost:7041/udapBusinesstoBusiness" })
                .Build();
        }

        var encodedHeader = jwtHeader.Base64UrlEncode();
        var encodedPayload = document.Base64UrlEncode();
        var encodedSignature =
            JwtTokenUtilities.CreateEncodedSignature(string.Concat(encodedHeader, ".", encodedPayload),
                signingCredentials);
        var signedSoftwareStatement = string.Concat(encodedHeader, ".", encodedPayload, ".", encodedSignature);

        var tokenHandler = new JsonWebTokenHandler();
        var jsonToken = tokenHandler.ReadToken(signedSoftwareStatement);
        var requestToken = jsonToken as JsonWebToken;

        var sb = new StringBuilder();
        sb.Append("[");
        sb.Append(requestToken.EncodedHeader.DecodeJwtHeader());
        sb.Append(",");
        sb.Append(Base64UrlEncoder.Decode(requestToken.EncodedPayload));
        sb.Append("]");

        var softwareStatementBeforeEncoding = JsonObject.Parse(sb?.ToString())
            .ToJsonString(new JsonSerializerOptions()
            {
                WriteIndented = true,
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            });

        return Ok(softwareStatementBeforeEncoding);

        //
        // Maybe switch to this so we can easily get access to Softwarestatment so we can modify it at the client
        //
        // var result = new RawSoftwareStatementAndHeader
        // {
        //     Header = requestToken.EncodedHeader.DecodeJwtHeader(),
        //     SoftwareStatement = Base64UrlEncoder.Decode(requestToken.EncodedPayload)
        // };
        //
        // return Ok(result);
    }

    [HttpPost("BuildRequestBody")]
    public IActionResult BuildRequestBody([FromBody] BuildSoftwareStatementRequest request)
    {
        var certBytes = Convert.FromBase64String(HttpContext.Session.GetString(Constants.CLIENT_CERT_WITH_KEY));
        var clientCert = new X509Certificate2(certBytes);
        var securityKey = new X509SecurityKey(clientCert);
        var signingCredentials = new SigningCredentials(securityKey, UdapConstants.SupportedAlgorithm.RS256);

        var certBase64 = Convert.ToBase64String(clientCert.Export(X509ContentType.Cert));
        var jwtHeader = new JwtHeader
            {
                { "alg", signingCredentials.Algorithm },
                { "x5c", new[] { certBase64 } }
            };

        UdapDynamicClientRegistrationDocument document;

        if (request.Oauth2Flow == Oauth2FlowEnum.client_credentials)
        {
            document = UdapDcrBuilderForClientCredentials
                .Create(clientCert)
                //TODO: this only gets the first SubAltName
                .WithAudience(request.Audience)
                .WithExpiration(TimeSpan.FromMinutes(5))
                .WithJwtId()
                .WithClientName("FhirLabs Client")
                .WithContacts(new HashSet<string>
                {
                    "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
                })
                .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
                .WithScope("system/Patient.* system/Practitioner.read")
                .Build();
        }
        else
        {
            document = UdapDcrBuilderForAuthorizationCode
                .Create(clientCert)
                .WithAudience(request.Audience)
                .WithExpiration(TimeSpan.FromMinutes(5))
                .WithJwtId()
                .WithClientName("FhirLabs Client")
                .WithContacts(new HashSet<string>
                {
                    "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
                })
                .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
                .WithScope("system/Patient.* system/Practitioner.read openid profile offline_access")
                .WithResponseTypes(new HashSet<string> { "code" })
                .WithRedirectUrls(new List<string> { "https://localhost:7041/udapBusinesstoBusiness" })
                .Build();
        }

        var encodedHeader = jwtHeader.Base64UrlEncode();
        var encodedPayload = document.Base64UrlEncode();
        var encodedSignature =
            JwtTokenUtilities.CreateEncodedSignature(string.Concat(encodedHeader, ".", encodedPayload),
                signingCredentials);
        var signedSoftwareStatement = string.Concat(encodedHeader, ".", encodedPayload, ".", encodedSignature);

        var requestBody = new UdapRegisterRequest
        {
            SoftwareStatement = signedSoftwareStatement,
            // Certifications = new string[0],
            Udap = UdapConstants.UdapVersionsSupportedValue
        };

        return Ok(requestBody);
    }

    [HttpPost("Register")]
    public async Task<IActionResult> Register([FromBody] RegistrationRequest request)
    {
        var response = await _httpClient.PostAsJsonAsync<UdapRegisterRequest>(
            request.RegistrationEndpoint,
            request.UdapRegisterRequest);

        response.EnsureSuccessStatusCode();

        var result = await response.Content
            .ReadFromJsonAsync<RegistrationDocument>();

        return Ok(JsonSerializer.Serialize(result));
    }
}