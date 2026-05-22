#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using Udap.Client;
using Udap.Common.Certificates;
using Udap.Model;

namespace Udap.Common.Tests.Client;

public class UdapClientMessageHandlerTests
{
    private readonly ILogger<UdapClient> _logger = Substitute.For<ILogger<UdapClient>>();

    private static readonly string ValidDiscoJson = """
        {
            "udap_versions_supported": ["1"],
            "signed_metadata": "test-jwt"
        }
        """;

    #region SendAsync — HTTP error (EnsureSuccessStatusCode)

    [Fact]
    public async Task SendAsync_InnerHandlerReturnsFailureStatusCode_Throws()
    {
        var validator = CreateValidator();
        var handler = new UdapClientMessageHandler(validator, _logger)
        {
            InnerHandler = new FakeInnerHandler(HttpStatusCode.InternalServerError)
        };

        var client = new HttpClient(handler);

        await Assert.ThrowsAsync<HttpRequestException>(
            () => client.GetAsync("https://fhirlabs.net/fhir/r4/.well-known/udap"));
    }

    [Fact]
    public async Task SendAsync_BadRequest_ThrowsBeforeDeserialization()
    {
        var validator = CreateValidator();
        var handler = new UdapClientMessageHandler(validator, _logger)
        {
            InnerHandler = new FakeInnerHandler(HttpStatusCode.BadRequest, """{"error":"bad"}""")
        };

        var client = new HttpClient(handler);

        await Assert.ThrowsAsync<HttpRequestException>(
            () => client.GetAsync("https://fhirlabs.net/fhir/r4/.well-known/udap"));
    }

    #endregion

    #region SendAsync — disco OK path (validation)

    [Fact]
    public async Task SendAsync_DiscoOk_BothValidatorsPass_ReturnsSuccessfully()
    {
        var validator = new TestableValidator(jwtResult: true, trustChainResult: true);
        var handler = new UdapClientMessageHandler(validator, _logger)
        {
            InnerHandler = new FakeInnerHandler(ValidDiscoJson)
        };

        var client = new HttpClient(handler);
        var response = await client.GetAsync("https://fhirlabs.net/fhir/r4/.well-known/udap");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task SendAsync_DiscoOk_JwtValidationFails_ThrowsSecurityTokenException()
    {
        var validator = new TestableValidator(jwtResult: false, trustChainResult: true);
        var handler = new UdapClientMessageHandler(validator, _logger)
        {
            InnerHandler = new FakeInnerHandler(ValidDiscoJson)
        };

        var ex = await Assert.ThrowsAsync<SecurityTokenInvalidTypeException>(
            () => new HttpClient(handler).GetAsync("https://fhirlabs.net/fhir/r4/.well-known/udap"));

        Assert.Equal("Failed JWT Token Validation", ex.Message);
    }

    [Fact]
    public async Task SendAsync_DiscoOk_TrustChainFails_ThrowsUnauthorizedAccess()
    {
        var validator = new TestableValidator(jwtResult: true, trustChainResult: false);
        var handler = new UdapClientMessageHandler(validator, _logger)
        {
            InnerHandler = new FakeInnerHandler(ValidDiscoJson)
        };

        var ex = await Assert.ThrowsAsync<UnauthorizedAccessException>(
            () => new HttpClient(handler).GetAsync("https://fhirlabs.net/fhir/r4/.well-known/udap"));

        Assert.Equal("Failed Trust Chain Validation", ex.Message);
    }

    [Fact]
    public async Task SendAsync_DiscoOk_SetsUdapServerMetadata()
    {
        var validator = new TestableValidator(jwtResult: true, trustChainResult: true);
        var handler = new UdapClientMessageHandler(validator, _logger)
        {
            InnerHandler = new FakeInnerHandler(ValidDiscoJson)
        };

        var client = new HttpClient(handler);
        await client.GetAsync("https://fhirlabs.net/fhir/r4/.well-known/udap");

        Assert.NotNull(validator.UdapServerMetadata);
    }

    [Fact]
    public async Task SendAsync_DiscoOk_ExtractsBaseUrl()
    {
        string? capturedBaseUrl = null;
        var validator = new TestableValidator(jwtResult: true, trustChainResult: true,
            onValidateJwt: (_, baseUrl) => capturedBaseUrl = baseUrl);
        var handler = new UdapClientMessageHandler(validator, _logger)
        {
            InnerHandler = new FakeInnerHandler(ValidDiscoJson)
        };

        var client = new HttpClient(handler);
        await client.GetAsync("https://fhirlabs.net/fhir/r4/.well-known/udap");

        Assert.Equal("https://fhirlabs.net/fhir/r4", capturedBaseUrl);
    }

    #endregion

    #region NotifyTokenError — error path only reachable if disco.IsError on a 200 response

    [Fact]
    public async Task SendAsync_DiscoOkButIsError_CallsNotifyTokenError()
    {
        var validator = new TestableValidator(jwtResult: true, trustChainResult: true);
        var handler = new UdapClientMessageHandler(validator, _logger)
        {
            InnerHandler = new FakeInnerHandler(HttpStatusCode.OK, "not-valid-json{{{")
        };

        string? capturedError = null;
        handler.TokenError += msg => capturedError = msg;

        var client = new HttpClient(handler);
        var response = await client.GetAsync("https://fhirlabs.net/fhir/r4/.well-known/udap");

        Assert.NotNull(capturedError);
    }

    [Fact]
    public async Task SendAsync_NotifyTokenError_SubscriberThrows_IsSwallowed()
    {
        var validator = new TestableValidator(jwtResult: true, trustChainResult: true);
        var handler = new UdapClientMessageHandler(validator, _logger)
        {
            InnerHandler = new FakeInnerHandler(HttpStatusCode.OK, "not-valid-json{{{")
        };

        handler.TokenError += _ => throw new InvalidOperationException("subscriber boom");

        var client = new HttpClient(handler);
        var response = await client.GetAsync("https://fhirlabs.net/fhir/r4/.well-known/udap");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    #endregion

    #region Event delegation

    [Fact]
    public void TokenError_EventDelegation_CanSubscribeAndUnsubscribe()
    {
        var validator = CreateValidator();
        var handler = new UdapClientMessageHandler(validator, _logger);

        string? captured = null;
        Action<string> listener = msg => captured = msg;

        handler.TokenError += listener;
        handler.TokenError -= listener;

        Assert.Null(captured);
    }

    [Fact]
    public void Untrusted_EventDelegation_CanSubscribeAndUnsubscribe()
    {
        var validator = CreateValidator();
        var handler = new UdapClientMessageHandler(validator, _logger);

        Action<X509Certificate2> listener = _ => { };
        handler.Untrusted += listener;
        handler.Untrusted -= listener;
    }

    [Fact]
    public void Problem_EventDelegation_CanSubscribeAndUnsubscribe()
    {
        var validator = CreateValidator();
        var handler = new UdapClientMessageHandler(validator, _logger);

        Action<ChainElementInfo> listener = _ => { };
        handler.Problem += listener;
        handler.Problem -= listener;
    }

    [Fact]
    public void Error_EventDelegation_CanSubscribeAndUnsubscribe()
    {
        var validator = CreateValidator();
        var handler = new UdapClientMessageHandler(validator, _logger);

        Action<X509Certificate2, Exception> listener = (_, _) => { };
        handler.Error += listener;
        handler.Error -= listener;
    }

    [Fact]
    public void UdapDynamicClientRegistrationDocument_DefaultsToNull()
    {
        var validator = CreateValidator();
        var handler = new UdapClientMessageHandler(validator, _logger);

        Assert.Null(handler.UdapDynamicClientRegistrationDocument);
    }

    #endregion

    #region Helpers

    private static UdapClientDiscoveryValidator CreateValidator()
    {
        var trustChainValidator = new TrustChainValidator(
            Substitute.For<ILogger<TrustChainValidator>>());

        return new UdapClientDiscoveryValidator(
            trustChainValidator,
            Substitute.For<ILogger<UdapClientDiscoveryValidator>>());
    }

    private class TestableValidator : UdapClientDiscoveryValidator
    {
        private readonly bool _jwtResult;
        private readonly bool _trustChainResult;
        private readonly Action<UdapMetadata, string>? _onValidateJwt;
        private readonly Action<string?>? _onValidateTrustChain;

        public TestableValidator(
            bool jwtResult,
            bool trustChainResult,
            Action<UdapMetadata, string>? onValidateJwt = null,
            Action<string?>? onValidateTrustChain = null)
            : base(
                new TrustChainValidator(Substitute.For<ILogger<TrustChainValidator>>()),
                Substitute.For<ILogger<UdapClientDiscoveryValidator>>())
        {
            _jwtResult = jwtResult;
            _trustChainResult = trustChainResult;
            _onValidateJwt = onValidateJwt;
            _onValidateTrustChain = onValidateTrustChain;
        }

        public override Task<bool> ValidateJwtToken(UdapMetadata udapServerMetaData, string baseUrl)
        {
            _onValidateJwt?.Invoke(udapServerMetaData, baseUrl);
            return Task.FromResult(_jwtResult);
        }

        public override Task<bool> ValidateTrustChain(string? community)
        {
            _onValidateTrustChain?.Invoke(community);
            return Task.FromResult(_trustChainResult);
        }
    }

    private class FakeInnerHandler : HttpMessageHandler
    {
        private readonly string? _responseBody;
        private readonly HttpStatusCode _statusCode;

        public FakeInnerHandler(string responseBody)
        {
            _responseBody = responseBody;
            _statusCode = HttpStatusCode.OK;
        }

        public FakeInnerHandler(HttpStatusCode statusCode)
        {
            _responseBody = null;
            _statusCode = statusCode;
        }

        public FakeInnerHandler(HttpStatusCode statusCode, string responseBody)
        {
            _responseBody = responseBody;
            _statusCode = statusCode;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(new HttpResponseMessage(_statusCode)
            {
                Content = new StringContent(_responseBody ?? "", Encoding.UTF8, "application/json")
            });
        }
    }

    #endregion
}
