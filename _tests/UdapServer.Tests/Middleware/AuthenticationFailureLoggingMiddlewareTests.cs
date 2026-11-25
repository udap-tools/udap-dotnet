#region (c) 2025 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using Udap.Metadata.Server.Security;
using Xunit;

namespace UdapServer.Tests.Middleware;

public class SecurityEventMiddlewareTests
{
    private readonly ILogger<SecurityEventMiddleware> _logger;
    private readonly List<string> _logMessages;
    private readonly List<LogLevel> _logLevels;

    public SecurityEventMiddlewareTests()
    {
        _logger = Substitute.For<ILogger<SecurityEventMiddleware>>();
        _logMessages = new List<string>();
        _logLevels = new List<LogLevel>();

        _logger.WhenForAnyArgs(l => l.Log(
                default,
                default,
                default(object)!,
                default,
                default!))
            .Do(callInfo =>
            {
                _logLevels.Add((LogLevel)callInfo[0]);
                var state = callInfo[2];
                if (state != null)
                {
                    _logMessages.Add(state.ToString()!);
                }
            });
    }

    [Fact]
    public async Task NoAuthHeader_LogsAuthenticationFailure()
    {
        var middleware = new SecurityEventMiddleware(
            _ => Task.CompletedTask,
            _logger);

        var context = new DefaultHttpContext();
        context.Request.Path = "/fhir/r4/Patient";
        context.Request.Method = "GET";

        await middleware.InvokeAsync(context);

        Assert.Contains(_logMessages, m => m.Contains("AuthenticationFailure") && m.Contains("/fhir/r4/Patient"));
        Assert.Contains(LogLevel.Warning, _logLevels);
    }

    [Fact]
    public async Task AuthenticatedUser_LogsSuccessfulAccess()
    {
        var middleware = new SecurityEventMiddleware(
            _ => Task.CompletedTask,
            _logger);

        var context = new DefaultHttpContext();
        context.User = new ClaimsPrincipal(new ClaimsIdentity(
            new[] { new Claim("client_id", "my-client"), new Claim("sub", "user1") },
            "TestScheme"));
        context.Request.Path = "/fhir/r4/Patient";
        context.Request.Method = "GET";

        await middleware.InvokeAsync(context);

        Assert.Contains(_logMessages, m => m.Contains("SuccessfulAccess") && m.Contains("my-client"));
        Assert.Contains(LogLevel.Information, _logLevels);
    }

    [Fact]
    public async Task AuthenticatedUser_FallsBackToSubClaim()
    {
        var middleware = new SecurityEventMiddleware(
            _ => Task.CompletedTask,
            _logger);

        var context = new DefaultHttpContext();
        context.User = new ClaimsPrincipal(new ClaimsIdentity(
            new[] { new Claim("sub", "user-subject") },
            "TestScheme"));
        context.Request.Path = "/test";
        context.Request.Method = "POST";

        await middleware.InvokeAsync(context);

        Assert.Contains(_logMessages, m => m.Contains("SuccessfulAccess") && m.Contains("user-subject"));
    }

    [Fact]
    public async Task FailedAuth_WithValidJwt_ExtractsClientId()
    {
        var token = CreateTestJwt("failed-client");
        var middleware = new SecurityEventMiddleware(
            _ => Task.CompletedTask,
            _logger);

        var context = new DefaultHttpContext();
        context.Request.Path = "/fhir/r4/Patient";
        context.Request.Method = "GET";
        context.Request.Headers.Authorization = $"Bearer {token}";

        await middleware.InvokeAsync(context);

        Assert.Contains(_logMessages, m => m.Contains("AuthenticationFailure") && m.Contains("failed-client") && m.Contains("Bearer"));
    }

    [Fact]
    public async Task FailedAuth_DPoPScheme_ExtractsSchemeAndClientId()
    {
        var token = CreateTestJwt("dpop-client");
        var middleware = new SecurityEventMiddleware(
            _ => Task.CompletedTask,
            _logger);

        var context = new DefaultHttpContext();
        context.Request.Path = "/fhir/r4/Observation";
        context.Request.Method = "GET";
        context.Request.Headers.Authorization = $"DPoP {token}";

        await middleware.InvokeAsync(context);

        Assert.Contains(_logMessages, m => m.Contains("AuthenticationFailure") && m.Contains("dpop-client") && m.Contains("DPoP"));
    }

    [Fact]
    public async Task FailedAuth_InvalidJwt_LoginIsNull()
    {
        var middleware = new SecurityEventMiddleware(
            _ => Task.CompletedTask,
            _logger);

        var context = new DefaultHttpContext();
        context.Request.Path = "/fhir/r4/Patient";
        context.Request.Method = "GET";
        context.Request.Headers.Authorization = "Bearer not-a-jwt";

        await middleware.InvokeAsync(context);

        Assert.Contains(_logMessages, m => m.Contains("AuthenticationFailure") && m.Contains("Bearer"));
    }

    [Fact]
    public async Task CapturesHttpResponse()
    {
        var middleware = new SecurityEventMiddleware(
            ctx => { ctx.Response.StatusCode = 401; return Task.CompletedTask; },
            _logger);

        var context = new DefaultHttpContext();
        context.Request.Path = "/test";
        context.Request.Method = "GET";

        await middleware.InvokeAsync(context);

        Assert.Contains(_logMessages, m => m.Contains("401"));
    }

    [Fact]
    public async Task CapturesMethodAndQuery()
    {
        var middleware = new SecurityEventMiddleware(
            _ => Task.CompletedTask,
            _logger);

        var context = new DefaultHttpContext();
        context.Request.Path = "/fhir/r4/Patient";
        context.Request.Method = "POST";
        context.Request.QueryString = new QueryString("?_count=10&_sort=name");

        await middleware.InvokeAsync(context);

        // Parameter names only: search values are often patient details.
        Assert.Contains(_logMessages, m => m.Contains("POST") && m.Contains("Query=_count,_sort"));
        Assert.DoesNotContain(_logMessages, m => m.Contains("=10") || m.Contains("=name"));
    }

    [Fact]
    public async Task CapturesAcceptEncoding()
    {
        var middleware = new SecurityEventMiddleware(
            _ => Task.CompletedTask,
            _logger);

        var context = new DefaultHttpContext();
        context.Request.Path = "/test";
        context.Request.Method = "GET";
        context.Request.Headers.AcceptEncoding = "gzip, br";

        await middleware.InvokeAsync(context);

        Assert.Contains(_logMessages, m => m.Contains("gzip, br"));
    }

    [Fact]
    public async Task CapturesContentEncoding()
    {
        var middleware = new SecurityEventMiddleware(
            ctx => { ctx.Response.Headers.ContentEncoding = "gzip"; return Task.CompletedTask; },
            _logger);

        var context = new DefaultHttpContext();
        context.Request.Path = "/test";
        context.Request.Method = "GET";

        await middleware.InvokeAsync(context);

        Assert.Contains(_logMessages, m => m.Contains("gzip"));
    }

    [Fact]
    public async Task NextDelegateAlwaysCalled()
    {
        var nextCalled = false;
        var middleware = new SecurityEventMiddleware(
            _ => { nextCalled = true; return Task.CompletedTask; },
            _logger);

        var context = new DefaultHttpContext();

        await middleware.InvokeAsync(context);

        Assert.True(nextCalled);
    }

    [Fact]
    public void ExtractTokenValue_BearerWithToken_ReturnsToken()
    {
        var result = SecurityEventMiddleware.ExtractTokenValue("Bearer eyJ0eXAiOiJKV1Qi");
        Assert.Equal("eyJ0eXAiOiJKV1Qi", result);
    }

    [Fact]
    public void ExtractTokenValue_SchemeOnly_ReturnsNull()
    {
        var result = SecurityEventMiddleware.ExtractTokenValue("Bearer");
        Assert.Null(result);
    }

    [Fact]
    public void ExtractTokenValue_ExtraSpaces_ReturnsCleanToken()
    {
        var result = SecurityEventMiddleware.ExtractTokenValue("Bearer   eyJ0eXAiOiJKV1Qi  ");
        Assert.Equal("eyJ0eXAiOiJKV1Qi", result);
    }

    [Fact]
    public void ExtractAuthScheme_Bearer_ReturnsBearer()
    {
        var result = SecurityEventMiddleware.ExtractAuthScheme("Bearer eyJ0eXA");
        Assert.Equal("Bearer", result);
    }

    [Fact]
    public void ExtractAuthScheme_DPoP_ReturnsDPoP()
    {
        var result = SecurityEventMiddleware.ExtractAuthScheme("DPoP eyJ0eXA");
        Assert.Equal("DPoP", result);
    }

    [Fact]
    public void ExtractAuthScheme_Null_ReturnsNull()
    {
        var result = SecurityEventMiddleware.ExtractAuthScheme(null);
        Assert.Null(result);
    }

    [Fact]
    public void ExtractClientId_ValidJwt_ReturnsClientId()
    {
        var token = CreateTestJwt("my-client");
        var result = SecurityEventMiddleware.ExtractClientId(token);
        Assert.Equal("my-client", result);
    }

    [Fact]
    public void ExtractClientId_InvalidToken_ReturnsNull()
    {
        var result = SecurityEventMiddleware.ExtractClientId("not-a-jwt");
        Assert.Null(result);
    }

    [Fact]
    public void ExtractClientId_JwtWithNoClientId_ReturnsNull()
    {
        var token = CreateTestJwtWithClaims(new Claim("sub", "some-subject"));
        var result = SecurityEventMiddleware.ExtractClientId(token, _logger);
        Assert.Null(result);
        Assert.Contains(_logMessages, m => m.Contains("no client_id claim"));
    }

    [Fact]
    public void ExtractClientId_JwtWithNoClientId_NullLogger_ReturnsNull()
    {
        var token = CreateTestJwtWithClaims(new Claim("sub", "some-subject"));
        var result = SecurityEventMiddleware.ExtractClientId(token);
        Assert.Null(result);
    }

    [Fact]
    public async Task FailedAuth_SchemeOnly_WithAuthFailureFeature_LogsReason()
    {
        var middleware = new SecurityEventMiddleware(
            _ => Task.CompletedTask,
            _logger);

        var context = new DefaultHttpContext();
        context.Request.Path = "/fhir/r4/Patient";
        context.Request.Method = "GET";
        context.Request.Headers.Authorization = "Bearer";

        var authFeature = Substitute.For<IAuthenticateResultFeature>();
        authFeature.AuthenticateResult.Returns(
            AuthenticateResult.Fail("Token expired"));
        context.Features.Set(authFeature);

        await middleware.InvokeAsync(context);

        Assert.Contains(_logMessages, m => m.Contains("Token expired"));
    }

    [Fact]
    public void ExtractClientId_UnreadableToken_ReturnsNull()
    {
        // Three base64 segments that look like JWT structure but aren't valid
        var result = SecurityEventMiddleware.ExtractClientId("eyx.eyy.ezz", _logger);
        Assert.Null(result);
    }

    [Fact]
    public async Task SuccessfulAccess_LogsAllFields()
    {
        var middleware = new SecurityEventMiddleware(
            ctx => { ctx.Response.StatusCode = 200; ctx.Response.Headers.ContentEncoding = "br"; return Task.CompletedTask; },
            _logger);

        var context = new DefaultHttpContext();
        context.User = new ClaimsPrincipal(new ClaimsIdentity(
            new[] { new Claim("client_id", "full-test-client") },
            "Bearer"));
        context.Request.Method = "GET";
        context.Request.Path = "/fhir/r4/Patient";
        context.Request.QueryString = new QueryString("?_count=5");
        context.Request.Headers.AcceptEncoding = "gzip";
        context.Request.Headers.Authorization = "Bearer some-token";
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("192.168.1.100");

        await middleware.InvokeAsync(context);

        var logEntry = Assert.Single(_logMessages);
        Assert.Contains("SuccessfulAccess", logEntry);
        Assert.Contains("full-test-client", logEntry);
        Assert.Contains("Bearer", logEntry);
        Assert.Contains("192.168.1.100", logEntry);
        Assert.Contains("200", logEntry);
        Assert.Contains("GET", logEntry);
        Assert.Contains("/fhir/r4/Patient", logEntry);
        Assert.Contains("Query=_count", logEntry);
        Assert.DoesNotContain("=5", logEntry);
        Assert.Contains("LoginVerified=True", logEntry);
        Assert.Contains("gzip", logEntry);
        Assert.Contains("br", logEntry);
    }

    [Fact]
    public async Task FailedAuth_LoginFromUnvalidatedToken_IsMarkedUnverified()
    {
        var token = CreateTestJwt("claimed-client");
        var middleware = new SecurityEventMiddleware(_ => Task.CompletedTask, _logger);

        var context = new DefaultHttpContext();
        context.Request.Path = "/fhir/r4/Patient";
        context.Request.Method = "GET";
        context.Request.Headers.Authorization = $"Bearer {token}";

        await middleware.InvokeAsync(context);

        var logEntry = Assert.Single(_logMessages, m => m.StartsWith("SecurityEvent="));
        Assert.Contains("Login=claimed-client", logEntry);
        Assert.Contains("LoginVerified=False", logEntry);
    }

    [Fact]
    public async Task FailedAuth_LoginWithLineBreaks_CannotForgeLogLines()
    {
        var token = CreateTestJwt("evil\r\nSecurityEvent=SuccessfulAccess, Login=admin");
        var middleware = new SecurityEventMiddleware(_ => Task.CompletedTask, _logger);

        var context = new DefaultHttpContext();
        context.Request.Path = "/fhir/r4/Patient";
        context.Request.Method = "GET";
        context.Request.Headers.Authorization = $"Bearer {token}";

        await middleware.InvokeAsync(context);

        var logEntry = Assert.Single(_logMessages, m => m.StartsWith("SecurityEvent="));
        Assert.Contains("evilSecurityEvent=SuccessfulAccess", logEntry);
        Assert.DoesNotContain("\r", logEntry);
        Assert.DoesNotContain("\n", logEntry);
    }

    [Fact]
    public async Task LongHeaderValues_AreCapped()
    {
        var middleware = new SecurityEventMiddleware(_ => Task.CompletedTask, _logger);

        var context = new DefaultHttpContext();
        context.Request.Path = "/fhir/r4/Patient";
        context.Request.Method = "GET";
        context.Request.Headers.AcceptEncoding = new string('x', 1000);

        await middleware.InvokeAsync(context);

        var logEntry = Assert.Single(_logMessages, m => m.StartsWith("SecurityEvent="));
        Assert.Contains(new string('x', 256) + "...", logEntry);
        Assert.DoesNotContain(new string('x', 257), logEntry);
    }

    private static string CreateTestJwt(string clientId)
    {
        return CreateTestJwtWithClaims(new Claim("sub", "test-subject"), new Claim("client_id", clientId));
    }

    private static string CreateTestJwtWithClaims(params Claim[] claims)
    {
        var key = new SymmetricSecurityKey(
            System.Text.Encoding.UTF8.GetBytes("this-is-a-test-key-that-is-long-enough-for-hmac"));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            claims: claims,
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
