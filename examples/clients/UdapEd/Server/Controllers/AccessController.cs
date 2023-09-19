#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.IdentityModel.Tokens;
using Udap.Client.Client.Extensions;
using Udap.Model.Access;
using Udap.Model.UdapAuthenticationExtensions;
using UdapEd.Server.Extensions;
using UdapEd.Shared;
using UdapEd.Shared.Model;

namespace UdapEd.Server.Controllers;

[Route("[controller]")]
[EnableRateLimiting(RateLimitExtensions.Policy)]
public class AccessController : Controller
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<RegisterController> _logger;

    public AccessController(
        HttpClient httpClient,
        IHttpContextAccessor httpContextAccessor,
        ILogger<RegisterController> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
    }

    [HttpGet("{authorizeQuery}")]
    public async Task<IActionResult> GetAuthorizationCode(string authorizeQuery, CancellationToken token)
    {
        var handler = new HttpClientHandler() { AllowAutoRedirect = false };
        var httpClient = new HttpClient(handler);
        
        var response = await httpClient
            .GetAsync(Base64UrlEncoder
                .Decode(authorizeQuery), cancellationToken: token);

        var cookies = response.Headers.SingleOrDefault(header => header.Key == "Set-Cookie").Value;

        try
        {
            if (!response.IsSuccessStatusCode && response.StatusCode != HttpStatusCode.Found)
            {
                var message = await response.Content.ReadAsStringAsync(token);
                _logger.LogWarning(message);

                return Ok(new AccessCodeRequestResult
                {
                    Message = $"{response.StatusCode}:: {message}",
                    IsError = true
                });
            }

            var result = new AccessCodeRequestResult
            {
                RedirectUrl = response.Headers.Location?.AbsoluteUri,
                Cookies = cookies
            };

            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex.Message);
            return Problem(ex.Message);
        }
    }

    [HttpPost("BuildRequestToken/authorization_code")]
    public Task<IActionResult> RequestAccessTokenAuthCode(
        [FromBody] AuthorizationCodeTokenRequestModel tokenRequestModel,
        [FromQuery] string alg)
    {
        var clientCertWithKey = HttpContext.Session.GetString(UdapEdConstants.CLIENT_CERTIFICATE_WITH_KEY);

        if (clientCertWithKey == null)
        {
            return Task.FromResult<IActionResult>(BadRequest("Cannot find a certificate.  Reload the certificate."));
        }

        var certBytes = Convert.FromBase64String(clientCertWithKey);
        var clientCert = new X509Certificate2(certBytes, "ILikePasswords", X509KeyStorageFlags.Exportable);

        var tokenRequestBuilder = AccessTokenRequestForAuthorizationCodeBuilder.Create(
            tokenRequestModel.ClientId,
            tokenRequestModel.TokenEndpointUrl,
            clientCert,
            tokenRequestModel.RedirectUrl,
            tokenRequestModel.Code);

        var tokenRequest = tokenRequestBuilder.Build(tokenRequestModel.LegacyMode, alg);
        
        return Task.FromResult<IActionResult>(Ok(tokenRequest));
    }

    [HttpPost("BuildRequestToken/client_credentials")]
    public Task<IActionResult> RequestAccessTokenClientCredentials(
        [FromBody] ClientCredentialsTokenRequestModel tokenRequestModel,
        [FromQuery] string alg)
    {
        var clientCertWithKey = HttpContext.Session.GetString(UdapEdConstants.CLIENT_CERTIFICATE_WITH_KEY);

        if (clientCertWithKey == null)
        {
            return Task.FromResult<IActionResult>(BadRequest("Cannot find a certificate.  Reload the certificate."));
        }

        var certBytes = Convert.FromBase64String(clientCertWithKey);
        var clientCert = new X509Certificate2(certBytes, "ILikePasswords", X509KeyStorageFlags.Exportable);

        var tokenRequestBuilder = AccessTokenRequestForClientCredentialsBuilder.Create(
            tokenRequestModel.ClientId,
            tokenRequestModel.TokenEndpointUrl,
            clientCert);

        var b2bHl7 = new B2BAuthorizationExtension()
        {
            SubjectId = "urn:oid:2.16.840.1.113883.4.6#1234567890",
            OrganizationId = new Uri("https://fhirlabs.net/fhir/r4").OriginalString,
            OraganizationName = "FhirLabs",
            PurposeOfUse = new List<string>
            {
                "urn:oid:2.16.840.1.113883.5.8#TREAT"
            }
            // },
            // ConsentReference = new HashSet<string>{
            //     "https://fhirlabs.net/fhir/r4"
            // }
        };
        tokenRequestBuilder.WithExtension("hl7-b2b", b2bHl7);


        if (tokenRequestModel.Scope != null)
        {
            tokenRequestBuilder.WithScope(tokenRequestModel.Scope);
        }

        var tokenRequest = tokenRequestBuilder.Build(tokenRequestModel.LegacyMode, alg);
        
        return Task.FromResult<IActionResult>(Ok(tokenRequest));
    }

    [HttpPost("RequestToken/client_credentials")]
    public async Task<IActionResult> RequestAccessTokenForClientCredentials([FromBody] UdapClientCredentialsTokenRequestModel request)
    {
        var tokenRequest = request.ToUdapClientCredentialsTokenRequest();
        var tokenResponse = await _httpClient.UdapRequestClientCredentialsTokenAsync(tokenRequest);

        var tokenResponseModel = new TokenResponseModel
        {
            Raw = tokenResponse.Json.AsJson(),
            IsError = tokenResponse.IsError,
            Error = tokenResponse.Error,
            AccessToken = tokenResponse.AccessToken,
            IdentityToken = tokenResponse.IdentityToken,
            RefreshToken = tokenResponse.RefreshToken,
            ExpiresAt = DateTime.UtcNow.AddSeconds(tokenResponse.ExpiresIn),
            Scope = tokenResponse.Raw,
            TokenType = tokenResponse.TokenType,
            Headers = JsonSerializer.Serialize(
                tokenResponse.HttpResponse.Headers,
                new JsonSerializerOptions{WriteIndented = true})
        };

        if (tokenResponseModel.AccessToken != null)
        {
            HttpContext.Session.SetString(UdapEdConstants.TOKEN, tokenResponseModel.AccessToken);
        }

        return Ok(tokenResponseModel);
    }

    [HttpPost("RequestToken/authorization_code")]
    public async Task<IActionResult> RequestAccessTokenForAuthorizationCode([FromBody] UdapAuthorizationCodeTokenRequestModel request)
    {
        var tokenRequest = request.ToUdapAuthorizationCodeTokenRequest();
        var tokenResponse = await _httpClient.ExchangeCodeForTokenResponse(tokenRequest);

        var tokenResponseModel = new TokenResponseModel
        {
            Raw = tokenResponse.Json.AsJson(),
            IsError = tokenResponse.IsError,
            Error = tokenResponse.Error,
            AccessToken = tokenResponse.AccessToken,
            IdentityToken = tokenResponse.IdentityToken,
            RefreshToken = tokenResponse.RefreshToken,
            ExpiresAt = DateTime.UtcNow.AddSeconds(tokenResponse.ExpiresIn),
            Scope = tokenResponse.Raw,
            TokenType = tokenResponse.TokenType
        };

        if (tokenResponseModel.AccessToken != null)
        {
            HttpContext.Session.SetString(UdapEdConstants.TOKEN, tokenResponseModel.AccessToken);
        }

        return Ok(tokenResponseModel);
    }
}
