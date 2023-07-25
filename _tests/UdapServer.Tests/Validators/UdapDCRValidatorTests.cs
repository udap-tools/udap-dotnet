using FluentAssertions;
using IdentityModel;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Udap.Common.Certificates;
using Udap.Model;
using Udap.Model.Registration;
using Udap.Server.Configuration;
using Udap.Server.Registration;

namespace UdapServer.Tests.Validators;
public class UdapDcrValidatorTests
{

    [Fact]
    public async Task ValidateLogo_Missing()
    {
        var document = BuildUdapDcrValidator(out var validator);

        validator.ValidateLogoUri(document, out var errorResponse).Should().BeFalse();

        errorResponse.Should().NotBeNull();
        errorResponse!.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidClientMetadata);
        errorResponse.ErrorDescription.Should().Be($"{UdapDynamicClientRegistrationErrorDescriptions.LogoMissing}");
    }

    [Fact]
    public async Task ValidateLogo_InvalidFileType()
    {
        var document = BuildUdapDcrValidator(out var validator);
        document.LogoUri = "https://localhost/logo";
        validator.ValidateLogoUri(document, out var errorResponse).Should().BeFalse();

        errorResponse.Should().NotBeNull();
        errorResponse!.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidClientMetadata);
        errorResponse.ErrorDescription.Should().Be($"{UdapDynamicClientRegistrationErrorDescriptions.LogoInvalidFileType}");
    }

    [Fact]
    public async Task ValidateLogo_InvalidScheme()
    {
        var document = BuildUdapDcrValidator(out var validator);
        document.LogoUri = "http://localhost/logo.png";
        validator.ValidateLogoUri(document, out var errorResponse).Should().BeFalse();

        errorResponse.Should().NotBeNull();
        errorResponse!.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidClientMetadata);
        errorResponse.ErrorDescription.Should().Be($"{UdapDynamicClientRegistrationErrorDescriptions.LogoInvalidScheme}");
    }

    [Fact]
    public async Task ValidateLogo_InvalidUri()
    {
        var document = BuildUdapDcrValidator(out var validator);
        document.LogoUri = "http:/localhost/logo.png";
        validator.ValidateLogoUri(document, out var errorResponse).Should().BeFalse();

        errorResponse.Should().NotBeNull();
        errorResponse!.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidClientMetadata);
        errorResponse.ErrorDescription.Should().Be($"{UdapDynamicClientRegistrationErrorDescriptions.LogoInvalidUri}");
    }


    private static UdapDynamicClientRegistrationDocument BuildUdapDcrValidator(
        out UdapDynamicClientRegistrationValidator validator)
    {
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
            serverSettings,
            mockHttpContextAccessor.Object,
            new Mock<ILogger<UdapDynamicClientRegistrationValidator>>().Object);
        return document;
    }
}
