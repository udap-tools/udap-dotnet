#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Text;
using Duende.IdentityModel.Client;
using Udap.Client.Extensions;
using Udap.Model.Access;

namespace Udap.Common.Tests.Client;

public class HttpClientTokenRequestExtensionsTests
{
    #region UdapRequestClientCredentialsTokenAsync

    [Fact]
    public async Task ClientCredentials_Success_ReturnsTokenResponse()
    {
        var json = """{"access_token":"tok123","token_type":"Bearer","expires_in":3600}""";
        var client = CreateClient(HttpStatusCode.OK, json);

        var request = new UdapClientCredentialsTokenRequest
        {
            Address = "https://auth.example.com/token",
            Scope = "system/*.read"
        };

        var response = await client.UdapRequestClientCredentialsTokenAsync(request);

        Assert.False(response.IsError);
        Assert.Equal("tok123", response.AccessToken);
    }

    [Fact]
    public async Task ClientCredentials_ServerError_ReturnsError()
    {
        var client = CreateClient(HttpStatusCode.BadRequest, """{"error":"invalid_client"}""");

        var request = new UdapClientCredentialsTokenRequest
        {
            Address = "https://auth.example.com/token"
        };

        var response = await client.UdapRequestClientCredentialsTokenAsync(request);

        Assert.True(response.IsError);
    }

    [Fact]
    public async Task ClientCredentials_NetworkException_ReturnsError()
    {
        var client = new HttpClient(new ThrowingHandler());

        var request = new UdapClientCredentialsTokenRequest
        {
            Address = "https://auth.example.com/token"
        };

        var response = await client.UdapRequestClientCredentialsTokenAsync(request);

        Assert.True(response.IsError);
        Assert.NotNull(response.Exception);
    }

    #endregion

    #region ExchangeCodeForTokenResponse

    [Fact]
    public async Task ExchangeCode_Success_ReturnsTokenResponse()
    {
        var json = """{"access_token":"code-tok","token_type":"Bearer"}""";
        var client = CreateClient(HttpStatusCode.OK, json);

        var request = new AuthorizationCodeTokenRequest
        {
            Address = "https://auth.example.com/token",
            Code = "auth-code-123",
            RedirectUri = "https://app.example.com/callback"
        };

        var response = await client.ExchangeCodeForTokenResponse(request);

        Assert.False(response.IsError);
        Assert.Equal("code-tok", response.AccessToken);
    }

    [Fact]
    public async Task ExchangeCode_WithCodeVerifier_IncludesPkce()
    {
        string? capturedBody = null;
        var handler = new CapturingHandler(HttpStatusCode.OK,
            """{"access_token":"t","token_type":"Bearer"}""",
            req => capturedBody = req.Content?.ReadAsStringAsync().Result);

        var client = new HttpClient(handler);

        var request = new AuthorizationCodeTokenRequest
        {
            Address = "https://auth.example.com/token",
            Code = "code",
            CodeVerifier = "my-verifier-value"
        };

        await client.ExchangeCodeForTokenResponse(request);

        Assert.NotNull(capturedBody);
        Assert.Contains("code_verifier=my-verifier-value", capturedBody);
    }

    [Fact]
    public async Task ExchangeCode_WithoutCodeVerifier_NoPkce()
    {
        string? capturedBody = null;
        var handler = new CapturingHandler(HttpStatusCode.OK,
            """{"access_token":"t","token_type":"Bearer"}""",
            req => capturedBody = req.Content?.ReadAsStringAsync().Result);

        var client = new HttpClient(handler);

        var request = new AuthorizationCodeTokenRequest
        {
            Address = "https://auth.example.com/token",
            Code = "code"
        };

        await client.ExchangeCodeForTokenResponse(request);

        Assert.NotNull(capturedBody);
        Assert.DoesNotContain("code_verifier", capturedBody);
    }

    [Fact]
    public async Task ExchangeCode_WithResources_IncludesResourceParams()
    {
        string? capturedBody = null;
        var handler = new CapturingHandler(HttpStatusCode.OK,
            """{"access_token":"t","token_type":"Bearer"}""",
            req => capturedBody = req.Content?.ReadAsStringAsync().Result);

        var client = new HttpClient(handler);

        var request = new AuthorizationCodeTokenRequest
        {
            Address = "https://auth.example.com/token",
            Code = "code",
            Resource = { "https://fhir.example.com/r4" }
        };

        await client.ExchangeCodeForTokenResponse(request);

        Assert.NotNull(capturedBody);
        Assert.Contains("resource=", capturedBody);
    }

    #endregion

    #region ExchangeCodeForAuthTokenResponse

    [Fact]
    public async Task ExchangeCodeForAuth_Success_ReturnsOAuthTokenResponse()
    {
        var json = """{"access_token":"auth-tok","token_type":"Bearer"}""";
        var client = CreateClient(HttpStatusCode.OK, json);

        var request = new AuthorizationCodeTokenRequest
        {
            Address = "https://auth.example.com/token",
            Code = "auth-code"
        };

        var response = await client.ExchangeCodeForAuthTokenResponse(request);

        Assert.Null(response.Error);
        Assert.NotNull(response.Response);
    }

    [Fact]
    public async Task ExchangeCodeForAuth_Failure_ReturnsPreparedError()
    {
        var json = """{"error":"invalid_grant","error_description":"Code expired","error_uri":"https://docs.example.com/err"}""";
        var client = CreateClient(HttpStatusCode.BadRequest, json);

        var request = new AuthorizationCodeTokenRequest
        {
            Address = "https://auth.example.com/token",
            Code = "expired-code"
        };

        var response = await client.ExchangeCodeForAuthTokenResponse(request);

        Assert.NotNull(response.Error);
        Assert.Contains("invalid_grant", response.Error.Message);
        Assert.Contains("Code expired", response.Error.Message);
        Assert.Contains("https://docs.example.com/err", response.Error.Message);
        Assert.Equal("invalid_grant", response.Error.Data["error"]);
    }

    [Fact]
    public async Task ExchangeCodeForAuth_FailureWithoutOptionalFields_StillWorks()
    {
        var json = """{"error":"server_error"}""";
        var client = CreateClient(HttpStatusCode.InternalServerError, json);

        var request = new AuthorizationCodeTokenRequest
        {
            Address = "https://auth.example.com/token",
            Code = "code"
        };

        var response = await client.ExchangeCodeForAuthTokenResponse(request);

        Assert.NotNull(response.Error);
        Assert.Contains("server_error", response.Error.Message);
        Assert.DoesNotContain("Description=", response.Error.Message);
        Assert.DoesNotContain("Uri=", response.Error.Message);
    }

    [Fact]
    public async Task ExchangeCodeForAuth_WithCodeVerifier_IncludesPkce()
    {
        string? capturedBody = null;
        var handler = new CapturingHandler(HttpStatusCode.OK,
            """{"access_token":"t","token_type":"Bearer"}""",
            req => capturedBody = req.Content?.ReadAsStringAsync().Result);

        var client = new HttpClient(handler);

        var request = new AuthorizationCodeTokenRequest
        {
            Address = "https://auth.example.com/token",
            Code = "code",
            CodeVerifier = "pkce-verifier"
        };

        await client.ExchangeCodeForAuthTokenResponse(request);

        Assert.NotNull(capturedBody);
        Assert.Contains("code_verifier=pkce-verifier", capturedBody);
    }

    [Fact]
    public async Task ExchangeCodeForAuth_WithResources_IncludesResourceParams()
    {
        string? capturedBody = null;
        var handler = new CapturingHandler(HttpStatusCode.OK,
            """{"access_token":"t","token_type":"Bearer"}""",
            req => capturedBody = req.Content?.ReadAsStringAsync().Result);

        var client = new HttpClient(handler);

        var request = new AuthorizationCodeTokenRequest
        {
            Address = "https://auth.example.com/token",
            Code = "code",
            Resource = { "https://fhir.example.com/r4" }
        };

        await client.ExchangeCodeForAuthTokenResponse(request);

        Assert.NotNull(capturedBody);
        Assert.Contains("resource=", capturedBody);
    }

    #endregion

    #region Helpers

    private static HttpClient CreateClient(HttpStatusCode statusCode, string responseBody)
    {
        return new HttpClient(new FakeHandler(statusCode, responseBody));
    }

    private class FakeHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _statusCode;
        private readonly string _body;

        public FakeHandler(HttpStatusCode statusCode, string body)
        {
            _statusCode = statusCode;
            _body = body;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(new HttpResponseMessage(_statusCode)
            {
                Content = new StringContent(_body, Encoding.UTF8, "application/json")
            });
        }
    }

    private class CapturingHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _statusCode;
        private readonly string _body;
        private readonly Action<HttpRequestMessage> _onSend;

        public CapturingHandler(HttpStatusCode statusCode, string body, Action<HttpRequestMessage> onSend)
        {
            _statusCode = statusCode;
            _body = body;
            _onSend = onSend;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            _onSend(request);
            return Task.FromResult(new HttpResponseMessage(_statusCode)
            {
                Content = new StringContent(_body, Encoding.UTF8, "application/json")
            });
        }
    }

    private class ThrowingHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            throw new HttpRequestException("Network failure");
        }
    }

    #endregion
}
