#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using FluentAssertions;
using IdentityModel;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Udap.Common;
using Udap.Metadata.Server;
using Xunit.Abstractions;
using program = FhirLabsApi.Program;


namespace WebApi.Tests.FhirLabsApi;

public class ApiTestFixture : WebApplicationFactory<program>
{
    private UdapMetadata? _wellKnownUdap;
    public ITestOutputHelper? Output { get; set; }
    
    public UdapMetadata WellKnownUdap
    {
        get
        {
            if (_wellKnownUdap == null)
            {
                var response = CreateClient().GetAsync($"fhir/r4/.well-known/udap").GetAwaiter().GetResult();
                response.StatusCode.Should().Be(HttpStatusCode.OK);
                var content = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                _wellKnownUdap = System.Text.Json.JsonSerializer.Deserialize<UdapMetadata>(content);
            }

            return _wellKnownUdap!;
        }
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        //
        // Linux needs to know how to find appsettings file in web api under test.
        // Still works with Windows but what a pain.  This feels fragile
        // TODO: 
        //
        builder.UseSetting("contentRoot", "../../../../../examples/FhirLabsApi");
    }

    protected override IHost CreateHost(IHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        builder.ConfigureLogging(logging =>
        {
            logging.ClearProviders();
            logging.AddXUnit(Output!);
        });

        return base.CreateHost(builder);
    }
}

public class UdapControllerTests : IClassFixture<ApiTestFixture>
{
    private readonly ApiTestFixture _fixture;

    public UdapControllerTests(ApiTestFixture fixture, ITestOutputHelper output)
    {
        //
        // Tests json once
        //
        if (fixture == null) throw new ArgumentNullException(nameof(fixture));
        fixture.Output = output;
        _fixture = fixture;
    }

    /// <summary>
    /// 200 response.
    /// Well formed Json
    /// </summary>
    [Fact]
    public void UdapWellKnownConfigIsAvailable()
    {
        _fixture.WellKnownUdap.Should().NotBeNull();
    }

    /// <summary>
    /// udap_versions_supported must contain a fixed array with one string
    /// </summary>
    [Fact]
    public void udap_versions_supportedTest()
    {
        var verSupported = _fixture.WellKnownUdap.UdapVersionsSupported;
        verSupported.Should().NotBeNullOrEmpty();
        verSupported!.Single().Should().Be("1");
    }


    [Fact]
    public void udap_authorization_extensions_supportedTest()
    {
        var extensions = _fixture.WellKnownUdap.UdapAuthorizationExtensionsSupported;
        extensions.Should().NotBeNullOrEmpty();

        var hl7B2B = extensions!.SingleOrDefault(c => c == "hl7-b2b");
        hl7B2B.Should().NotBeNullOrEmpty();
    }

    /// <summary>
    /// Conditional.  Not required but setup for this test.
    /// </summary>
    [Fact]
    public void udap_authorization_extensions_requiredTest()
    {
        _fixture.WellKnownUdap.UdapAuthorizationExtensionsRequired.Should().Contain("hl7-b2b");
    }

    /// <summary>
    /// udap_certifications_supported is an array of zero or more certification URIs
    /// </summary>
    [Fact]
    public void udap_certifications_supportedTest()
    {
        var certificationsSupported = _fixture.WellKnownUdap.UdapCertificationsSupported?.SingleOrDefault(c => c == "http://MyUdapCertification");
        certificationsSupported.Should().NotBeNullOrEmpty();
        var uriCertificationsSupported = new Uri(certificationsSupported!);
        uriCertificationsSupported.Should().Be("http://MyUdapCertification");

        certificationsSupported = _fixture.WellKnownUdap.UdapCertificationsSupported?.SingleOrDefault(c => c == "http://MyUdapCertification2");
        certificationsSupported.Should().NotBeNullOrEmpty();
        uriCertificationsSupported = new Uri(certificationsSupported!);
        uriCertificationsSupported.Should().Be("http://MyUdapCertification2");
    }

    /// <summary>
    /// udap_certifications_required is an array of zero or more certification URIs
    /// </summary>
    [Fact]
    public void udap_certifications_requiredTest()
    {
        var certificationsSupported = _fixture.WellKnownUdap.UdapCertificationsRequired?.SingleOrDefault();
        certificationsSupported.Should().NotBeNullOrEmpty();
        var uriCertificationsSupported = new Uri(certificationsSupported!);
        uriCertificationsSupported.Should().Be("http://MyUdapCertification");
    }

    [Fact]
    public void grant_types_supportedTest()
    {
        var grantTypes = _fixture.WellKnownUdap.GrantTypesSupported;
        grantTypes.Should().NotBeNullOrEmpty();

        grantTypes.Count.Should().Be(1);
        // grantTypes.Should().Contain("authorization_code");
        // grantTypes.Should().Contain("refresh_token");
        grantTypes.Should().Contain("client_credentials");
    }

    [Fact]
    public void scopes_supported_supportedTest()
    {
        var scopesSupported = _fixture.WellKnownUdap.ScopesSupported;

        scopesSupported.Should().Contain("openid");
        scopesSupported.Should().Contain("system/Patient.read");
        scopesSupported.Should().Contain("system/AllergyIntolerance.read");
        scopesSupported.Should().Contain("system/Procedures.read");
    }

    [Fact]
    public void authorization_endpointTest()
    {
        var authorizationEndpoint = _fixture.WellKnownUdap.AuthorizationEndpoint;
        authorizationEndpoint.Should().Be("https://host.docker.internal:5002/connect/authorize");
    }

    [Fact]
    public void token_endpointTest()
    {
        var tokenEndpoint = _fixture.WellKnownUdap.TokenEndpoint;
        tokenEndpoint.Should().Be("https://host.docker.internal:5002/connect/token");
    }

    [Fact]
    public void registration_endpointTest()
    {
        var registrationEndpoint = _fixture.WellKnownUdap.RegistrationEndpoint;
        registrationEndpoint.Should().Be("https://host.docker.internal:5002/connect/register");
    }

    [Fact]
    public void token_endpoint_auth_methods_supportedTest()
    {
        var scopesSupported = _fixture.WellKnownUdap.TokenEndpointAuthMethodsSupported?.SingleOrDefault();
        scopesSupported.Should().NotBeNullOrEmpty();
        scopesSupported.Should().Be("private_key_jwt");
    }

    [Fact]
    public void token_endpoint_auth_signing_alg_values_supportedTest()
    {
        var scopesSupported = _fixture.WellKnownUdap.TokenEndpointAuthSigningAlgValuesSupported?.SingleOrDefault();
        scopesSupported.Should().NotBeNullOrEmpty();
        scopesSupported.Should().Be(UdapConstants.SupportedAlgorithm.RS256);
    }

    [Fact]
    public void registration_endpoint_jwt_signing_alg_values_supportedTest()
    {
        var scopesSupported = _fixture.WellKnownUdap.RegistrationEndpointJwtSigningAlgValuesSupported?.SingleOrDefault();
        scopesSupported.Should().NotBeNullOrEmpty();
        scopesSupported.Should().Be(UdapConstants.SupportedAlgorithm.RS256);
    }

    [Fact]
    public void signed_metadataTest()
    {
        var signedMetatData = _fixture.WellKnownUdap.SignedMetadata;
        signedMetatData.Should().NotBeNullOrEmpty();

        var pattern = @"^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+\/=]*$";
        var regex = new Regex(pattern);
        regex.IsMatch(signedMetatData!).Should().BeTrue("signed_metadata is not a valid JWT");
    }

    [Fact]
    public void signed_metadataContentTest()
    {
        var jwt = new JwtSecurityToken(_fixture.WellKnownUdap.SignedMetadata);
        var tokenHeader = jwt.Header;
        
        var x5CArray = JsonConvert.DeserializeObject<string[]>(tokenHeader.X5c);

        // bad keys
        //x5cArray[0] = "MIIFJDCCBAygAwIBAgIIUFnObaPiufEwDQYJKoZIhvcNAQELBQAwgbMxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlTYW4gRGllZ28xEzARBgNVBAoMCkVNUiBEaXJlY3QxPzA9BgNVBAsMNlRlc3QgUEtJIENlcnRpZmljYXRpb24gQXV0aG9yaXR5IChjZXJ0cy5lbXJkaXJlY3QuY29tKTElMCMGA1UEAwwcRU1SIERpcmVjdCBUZXN0IENsaWVudCBTdWJDQTAeFw0yMTAxMTUyMTQ1MTRaFw0yNDAxMTYyMTQ1MTRaMIGlMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTETMBEGA1UECgwKRU1SIERpcmVjdDEzMDEGA1UECwwqVURBUCBUZXN0IENlcnRpZmljYXRlIE5PVCBGT1IgVVNFIFdJVEggUEhJMTcwNQYDVQQDDC5odHRwczovL3N0YWdlLmhlYWx0aHRvZ28ubWU6ODE4MS9maGlyL3I0L3N0YWdlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt9j718Yu8HjoIdSvLTloVLnFLdfdL7T/BylPcIpcKhB7zJvNzZOpq8T/fXhc9b4p6cY6gBPBq1Vnax4zTCAP/te5W6FfoRoKhKqpExuYmgIw0lE8a4UAnHVwPOAvuKS3abGzYfLxxUc4PFXp4HrBx/QWOMqR408GlbSYG0wpeifhMx1VD8TFmU13FmFqgP3cEHjT7RxulfJnPcPPXZ8b5tZIkQMlApJRULVnHEBcICixaRWCJjzzArgoFUydPiAfMZELi80W4n0Wn/WduSYZqwQAosI7AfS3NINd44w8kek1X9WVwX/QtcAVuCXvSFoqoIAa3l4kBCQIHmY9UhltZwIDAQABo4IBRjCCAUIwWQYIKwYBBQUHAQEETTBLMEkGCCsGAQUFBzAChj1odHRwOi8vY2VydHMuZW1yZGlyZWN0LmNvbS9jZXJ0cy9FTVJEaXJlY3RUZXN0Q2xpZW50U3ViQ0EuY3J0MB0GA1UdDgQWBBRZmXqpQzFDSamfvPKiKtjg9gp8cTAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFKOVbWu9K1HN4c/lkG/XJk+/3T7eMEwGA1UdHwRFMEMwQaA/oD2GO2h0dHA6Ly9jZXJ0cy5lbXJkaXJlY3QuY29tL2NybC9FTVJEaXJlY3RUZXN0Q2xpZW50U3ViQ0EuY3JsMA4GA1UdDwEB/wQEAwIHgDA5BgNVHREEMjAwhi5odHRwczovL3N0YWdlLmhlYWx0aHRvZ28ubWU6ODE4MS9maGlyL3I0L3N0YWdlMA0GCSqGSIb3DQEBCwUAA4IBAQAePi+wIAPubt2Fk2jbELZt/bgkc7KTGC5C4sLX25NNYyzvHh0kwmHvgBx3thCv7uOvf/nbmhnk+l3EmgdaB1ZjzcjLMFc7xec9YJWsegzEkR2pzYQp/41cmhTfwNSnXxUSZrBtqInx+mALi9r96lg6RpqQh+DxlToC2vreW7Fy3pFa3DQKFN6j6azYTj5ljqrGprKQRh/iyqRvY+j+BC44Wl+POfBVObwtf71irMuLsSCmMptPGFGTqQdtLYbFjkB4wowiFfEe0PYL+N015iPZA4wimlXbau4XaEvipnIsWxqzT30RbQgrrOw7zN1QjGRURBbdBkMrgLkzmfGxhjuV";

        var cert = new X509Certificate2(Convert.FromBase64String(x5CArray!.First()));

        var tokenHandler = new JwtSecurityTokenHandler();


        tokenHandler.ValidateToken(_fixture.WellKnownUdap.SignedMetadata, new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateLifetime = true,
            IssuerSigningKey = new X509SecurityKey(cert),
            ValidAlgorithms = new[] { tokenHeader.Alg },
            ValidateAudience = false
        }, out SecurityToken validatedToken);

        var issClaim = jwt.Payload.Claims.Single(c => c.Type == JwtClaimTypes.Issuer);
        issClaim.ValueType.Should().Be(ClaimValueTypes.String);

        // should be the same as the web base url
        issClaim.Value.Should().Be("https://fhirlabs.net:7016/fhir/r4");

        var subjectAltName = cert.GetNameInfo(X509NameType.UrlName, false);
        subjectAltName.Should().Be(issClaim.Value, $"iss: {issClaim.Value} does not match Subject Alternative Name extension");
        
        var subClaim = jwt.Payload.Claims.Single(c => c.Type == JwtClaimTypes.Subject);
        subClaim.ValueType.Should().Be(ClaimValueTypes.String);

        issClaim.Value.Should().BeEquivalentTo(subClaim.Value);


        var iatClaim = jwt.Payload.Claims.Single(c => c.Type == JwtClaimTypes.IssuedAt);
        iatClaim.ValueType.Should().Be(ClaimValueTypes.Integer);

        var expClaim = jwt.Payload.Claims.Single(c => c.Type == JwtClaimTypes.Expiration);
        expClaim.ValueType.Should().Be(ClaimValueTypes.Integer);

        var iat = int.Parse(iatClaim.Value);
        var exp = int.Parse(expClaim.Value);
        var year = DateTimeOffset.FromUnixTimeSeconds(exp).AddYears(1).ToUnixTimeSeconds();
        iat.Should().BeLessOrEqualTo((int)year);
    }
}