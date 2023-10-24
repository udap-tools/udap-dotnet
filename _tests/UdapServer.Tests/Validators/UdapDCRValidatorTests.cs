#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using Duende.IdentityServer.Stores;
using FluentAssertions;
using IdentityModel;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Moq.Protected;
using Udap.Common.Certificates;
using Udap.Model;
using Udap.Model.Registration;
using Udap.Server.Configuration;
using Udap.Server.Registration;
using Udap.Server.Validation.Default;
using UdapServer.Tests.Common;

namespace UdapServer.Tests.Validators;
public class UdapDcrValidatorTests
{
    private StubClock _clock = new StubClock();

    private DateTime _now = new DateTime(2020, 3, 10, 9, 0, 0, DateTimeKind.Utc);

    public DateTime UtcNow
    {
        get
        {
            if (_now > DateTime.MinValue) return _now;
            return DateTime.UtcNow;
        }
    }

    [Fact]
    public async Task ValidateLogo_Missing()
    {
        var document = BuildUdapDcrValidator(GetHttpClientForLogo("image/png"), out var validator);
        var (successFlag, errorResponse) = await validator.ValidateLogoUri(document);
        successFlag.Should().BeFalse();
        errorResponse.Should().NotBeNull();
        errorResponse!.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidClientMetadata);
        errorResponse.ErrorDescription.Should().Be($"{UdapDynamicClientRegistrationErrorDescriptions.LogoMissing}");
    }

    [Fact]
    public async Task ValidateLogo_ValidContentType()
    {
        var document = BuildUdapDcrValidator(GetHttpClientForLogo("image/png"), out var validator);
        document.LogoUri = "https://avatars.githubusercontent.com/u/77421324?s=48&v=4";
        var (successFlag, errorResponse) = await validator.ValidateLogoUri(document);
        successFlag.Should().BeTrue();
        errorResponse.Should().BeNull();
    }


    [Fact]
    public async Task ValidateLogo_InvalidContentType()
    {
        var document = BuildUdapDcrValidator(GetHttpClientForLogo("image/tiff"), out var validator);
        document.LogoUri = "https://localhost/logo";
        var (successFlag, errorResponse) = await validator.ValidateLogoUri(document);
        successFlag.Should().BeFalse();
        errorResponse.Should().NotBeNull();
        errorResponse!.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidClientMetadata);
        errorResponse.ErrorDescription.Should().Be($"{UdapDynamicClientRegistrationErrorDescriptions.LogoInvalidContentType}");
    }

    [Fact]
    public async Task ValidateLogo_InvalidScheme()
    {
        var document = BuildUdapDcrValidator(GetHttpClientForLogo("image/png"), out var validator);
        document.LogoUri = "http://localhost/logo.png";
        var (successFlag, errorResponse) = await validator.ValidateLogoUri(document);
        successFlag.Should().BeFalse();
        errorResponse.Should().NotBeNull();
        errorResponse!.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidClientMetadata);
        errorResponse.ErrorDescription.Should().Be($"{UdapDynamicClientRegistrationErrorDescriptions.LogoInvalidScheme}");
    }

    [Fact]
    public async Task ValidateLogo_InvalidUri()
    {
        var document = BuildUdapDcrValidator(GetHttpClientForLogo("image/png"), out var validator);
        document.LogoUri = "http:/localhost/logo.png"; // missing a slash
        var (successFlag, errorResponse) = await validator.ValidateLogoUri(document);
        successFlag.Should().BeFalse();
        errorResponse.Should().NotBeNull();
        errorResponse!.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidClientMetadata);
        errorResponse.ErrorDescription.Should().Be($"{UdapDynamicClientRegistrationErrorDescriptions.LogoInvalidUri}");
    }


    [Fact]
    public async Task ValidateJti_And_ReplayTest()
    {
        var now = DateTime.UtcNow;
        var expires = now.AddMinutes(1).ToUniversalTime();
        var document = new UdapDynamicClientRegistrationDocument
        {
            Issuer = "http://localhost/",
            Subject = "http://localhost/",
            Audience = "https://localhost/connect/register",
            Expiration = EpochTime.GetIntDate(expires),
            IssuedAt = EpochTime.GetIntDate(now.ToUniversalTime()),
            ClientName = "udapTestClient",
            Contacts = new HashSet<string> { "FhirJoe@BridgeTown.lab", "FhirJoe@test.lab" },
            GrantTypes = new HashSet<string> { "authorization_code" },
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "user/Patient.* user/Practitioner.read",
            RedirectUris = new List<string>
                { new Uri($"https://client.fhirlabs.net/redirect/{Guid.NewGuid()}").AbsoluteUri },
        };

        var serverSettings = new ServerSettings { LogoRequired = false };

        var mockHttpContextAccessor = new Mock<IHttpContextAccessor>();
        var context = new DefaultHttpContext();
        context.Request.Scheme = "http";
        context.Request.Host = new HostString("localhost:5001");
        context.Request.Path = "/connect/register";
        mockHttpContextAccessor.Setup(_ => _.HttpContext).Returns(context);

        _clock.UtcNowFunc = () => UtcNow;

        var mockHandler = new Mock<HttpMessageHandler>(MockBehavior.Strict);
        mockHandler.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>()
            )
            .ReturnsAsync((HttpRequestMessage request, CancellationToken token) =>
            {
                HttpResponseMessage response = new HttpResponseMessage();

                return response;
            });

        var httpClient = new HttpClient(mockHandler.Object);

        var validator = new UdapDynamicClientRegistrationValidator(
            new Mock<TrustChainValidator>(new Mock<ILogger<TrustChainValidator>>().Object).Object,
            httpClient,
            new TestReplayCache(_clock),
            serverSettings,
            mockHttpContextAccessor.Object,
            new DefaultScopeExpander(),
            new Mock<IResourceStore>().Object,
            new Mock<ILogger<UdapDynamicClientRegistrationValidator>>().Object);

    
        var result = await validator.ValidateJti(document, expires);

        result.Should().NotBeNull();
        result.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidClientMetadata);
        result.ErrorDescription.Should().Be($"{UdapDynamicClientRegistrationErrorDescriptions.InvalidJti}");

        document.JwtId = string.Empty;
        result = await validator.ValidateJti(document, expires);

        result.Should().NotBeNull();
        result.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidClientMetadata);
        result.ErrorDescription.Should().Be($"{UdapDynamicClientRegistrationErrorDescriptions.InvalidJti}");
        
        document.JwtId = "   ";
        result = await validator.ValidateJti(document, expires);

        result.Should().NotBeNull();
        result.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidClientMetadata);
        result.ErrorDescription.Should().Be($"{UdapDynamicClientRegistrationErrorDescriptions.InvalidJti}");


        //
        // Replay testing
        //

        document.JwtId = CryptoRandom.CreateUniqueId();
        result = await validator.ValidateJti(document, expires);
        result.Should().NotBeNull();
        result.Error.Should().BeEmpty(result.Error);

        result = await validator.ValidateJti(document, expires);

        result.Should().NotBeNull();
        result!.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidClientMetadata);
        result.ErrorDescription.Should().Be(UdapDynamicClientRegistrationErrorDescriptions.Replay);
    }


    private static UdapDynamicClientRegistrationDocument BuildUdapDcrValidator(
        HttpClient httpClient,
        out UdapDynamicClientRegistrationValidator validator)
    {
        var _clock = new StubClock();
        var now = DateTime.UtcNow;
        var jwtId = CryptoRandom.CreateUniqueId();

        var document = new UdapDynamicClientRegistrationDocument
        {
            Issuer = "http://localhost/",
            Subject = "http://localhost/",
            Audience = "https://localhost/connect/register",
            Expiration = EpochTime.GetIntDate(now.AddMinutes(1).ToUniversalTime()),
            IssuedAt = EpochTime.GetIntDate(now.ToUniversalTime()),
            JwtId = jwtId,
            ClientName = "udapTestClient",
            Contacts = new HashSet<string> { "FhirJoe@BridgeTown.lab", "FhirJoe@test.lab" },
            GrantTypes = new HashSet<string> { "authorization_code" },
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "user/Patient.* user/Practitioner.read",
            RedirectUris = new List<string>
                { new Uri($"https://client.fhirlabs.net/redirect/{Guid.NewGuid()}").AbsoluteUri },
        };

        var serverSettings = new ServerSettings { LogoRequired = true };

        var mockHttpContextAccessor = new Mock<IHttpContextAccessor>();
        var context = new DefaultHttpContext();
        context.Request.Scheme = "http";
        context.Request.Host = new HostString("localhost:5001");
        context.Request.Path = "/connect/register";
        mockHttpContextAccessor.Setup(_ => _.HttpContext).Returns(context);
        
        validator = new UdapDynamicClientRegistrationValidator(
            new Mock<TrustChainValidator>(new Mock<ILogger<TrustChainValidator>>().Object).Object,
            httpClient,
            new TestReplayCache(_clock),
            serverSettings,
            mockHttpContextAccessor.Object,
            new DefaultScopeExpander(),
            new Mock<IResourceStore>().Object,
            new Mock<ILogger<UdapDynamicClientRegistrationValidator>>().Object);
        return document;
    }

    private HttpClient GetHttpClientForLogo(string? contentType)
    {
        var mockHandler = new Mock<HttpMessageHandler>(MockBehavior.Strict);
        mockHandler.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>()
            )
            .ReturnsAsync((HttpRequestMessage request, CancellationToken token) =>
            {
                HttpResponseMessage response = new HttpResponseMessage(HttpStatusCode.OK);
                if (contentType != null)
                {
                    response.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(contentType);
                }

                return response;
            });

        return new HttpClient(mockHandler.Object);
    }
}

public static class TestValidationExtensions{

    public static UdapDynamicClientRegistrationDocument WithDefaultLogo(
        this UdapDynamicClientRegistrationDocument document)
    {
        document.LogoUri = "https://localhost/logo.png";
        return document;
    }

}
