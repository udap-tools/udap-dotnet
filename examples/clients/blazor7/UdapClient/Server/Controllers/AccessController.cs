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
using Microsoft.IdentityModel.Tokens;
using Udap.Client.Client.Extensions;
using Udap.Model.Access;
using UdapClient.Shared;
using UdapClient.Shared.Model;

namespace UdapClient.Server.Controllers;

[Route("[controller]")]
[ApiController]
public class AccessController : ControllerBase
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

        var result = new AccessCodeRequestResult();
        result.RedirctUrl = response.Headers.Location.AbsoluteUri;
        
        if (response.StatusCode != HttpStatusCode.Redirect)
        {
            result.IsError = true;
        }

        return Ok(result);
    }

    [HttpPost("BuildRequestToken/authorization_code")]
    public IActionResult RequestAccessTokenAuthCode([FromBody] AccessTokenRequestModel model)
    {
        var certBytes = Convert.FromBase64String(HttpContext.Session.GetString("clientCert"));
        var clientCert = new X509Certificate2(certBytes, model.Password);
        
        var tokenRequestBuilder = AccessTokenRequestBuilder.Create(
            model.ClientId,
            model.TokenEndpointUrl,
            clientCert);

        var tokenRequest = tokenRequestBuilder.Build();
        
        return Ok(tokenRequest);
    }

    [HttpPost("BuildRequestToken/client_credentials")]
    public IActionResult RequestAccessTokenClientCredentials([FromBody] AccessTokenRequestModel model)
    {
        var certBytes = Convert.FromBase64String(HttpContext.Session.GetString("clientCert"));
        var clientCert = new X509Certificate2(certBytes, model.Password);

        var tokenRequestBuilder = AccessTokenRequestBuilder.Create(
            model.ClientId,
            model.TokenEndpointUrl,
            clientCert);

        var tokenRequest = tokenRequestBuilder.Build();
        
        return Ok(tokenRequest);
    }

    [HttpPost("RequestToken/client_credentials")]
    public async Task<IActionResult> RequestAccessTokenForClientCredentials(UdapClientCredentialsTokenRequest request)
    {
        var tokenResponse = await _httpClient
            .UdapRequestClientCredentialsTokenAsync(request);

        return Ok(tokenResponse.Json.AsJson());
    }

    [HttpPost("RequestToken/authorization_code")]
    public async Task<IActionResult> RequestAccessTokenForAuthorizationCode(UdapAuthorizationCodeTokenRequest request)
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
