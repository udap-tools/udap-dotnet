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
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.IdentityModel.Tokens;
using Udap.Client.Client.Extensions;
using Udap.Model.Access;
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

    public AccessController(HttpClient httpClient, ILogger<RegisterController> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
    }

    [HttpGet("{authorizeQuery}")]
    public async Task<IActionResult> GetTokens(string authorizeQuery, CancellationToken token)
    {
        var handler = new HttpClientHandler() { AllowAutoRedirect = false };
        var httpClient = new HttpClient(handler);
        
        var response = await httpClient
            .GetAsync(Base64UrlEncoder
                .Decode(authorizeQuery), cancellationToken: token);

        var result = new AccessCodeRequestResult
        {
            RedirectUrl = response.Headers.Location?.AbsoluteUri
        };

        if (response.StatusCode != HttpStatusCode.Redirect)
        {
            result.IsError = true;
        }

        return Ok(result);
    }

    [HttpPost("BuildRequestToken/authorization_code")]
    public Task<IActionResult> RequestAccessTokenAuthCode([FromBody] AuthorizationCodeTokenRequestModel model)
    {
        var clientCertWithKey = HttpContext.Session.GetString(Constants.CLIENT_CERT_WITH_KEY);

        if (clientCertWithKey == null)
        {
            return Task.FromResult<IActionResult>(BadRequest("Cannot find a certificate.  Reload the certificate."));
        }

        var certBytes = Convert.FromBase64String(clientCertWithKey);
        var clientCert = new X509Certificate2(certBytes);
        
        var tokenRequestBuilder = AccessTokenRequestForAuthorizationCodeBuilder.Create(
            model.ClientId,
            model.TokenEndpointUrl,
            clientCert,
            model.RedirectUrl,
            model.Code);

        var tokenRequest = tokenRequestBuilder.Build();
        
        return Task.FromResult<IActionResult>(Ok(tokenRequest));
    }

    [HttpPost("BuildRequestToken/client_credentials")]
    public Task<IActionResult> RequestAccessTokenClientCredentials([FromBody] ClientCredentialsTokenRequestModel model)
    {
        var clientCertWithKey = HttpContext.Session.GetString(Constants.CLIENT_CERT_WITH_KEY);

        if (clientCertWithKey == null)
        {
            return Task.FromResult<IActionResult>(BadRequest("Cannot find a certificate.  Reload the certificate."));
        }

        var certBytes = Convert.FromBase64String(clientCertWithKey);
        var clientCert = new X509Certificate2(certBytes);

        var tokenRequestBuilder = AccessTokenRequestForClientCredentialsBuilder.Create(
            model.ClientId,
            model.TokenEndpointUrl,
            clientCert);

        var tokenRequest = tokenRequestBuilder.build();
        
        return Task.FromResult<IActionResult>(Ok(tokenRequest));
    }

    [HttpPost("RequestToken/client_credentials")]
    public async Task<IActionResult> RequestAccessTokenForClientCredentials([FromBody] UdapClientCredentialsTokenRequest request)
    {
        var tokenResponse = await _httpClient
            .UdapRequestClientCredentialsTokenAsync(request);

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

        return Ok(tokenResponseModel);
    }

    [HttpPost("RequestToken/authorization_code")]
    public async Task<IActionResult> RequestAccessTokenForAuthorizationCode([FromBody] UdapAuthorizationCodeTokenRequest request)
    {
        var tokenResponse = await _httpClient
            .UdapRequestAuthorizationCodeTokenAsync(request);

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

        return Ok(tokenResponseModel);
    }
}
