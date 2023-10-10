#region (c) 2023 Joseph Shook. All rights reserved.
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
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Udap.Client.Client;
using Udap.Client.Configuration;
using Udap.Common;
using Udap.Common.Certificates;
using Udap.Model;
using Udap.Util.Extensions;
using Xunit.Abstractions;
using fhirLabsProgram = FhirLabsApi.Program;


namespace UdapMetadata.Tests.FhirLabsApi;

public class ApiTestFixture : WebApplicationFactory<fhirLabsProgram>
{
    public ITestOutputHelper? Output { get; set; }
    public const string ProgramPath = "../../../../../examples/FhirLabsApi";

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        //
        // Linux needs to know how to find appsettings file in web api under test.
        // Still works with Windows but what a pain.  This feels fragile
        // TODO: 
        //
        builder.UseSetting("contentRoot", ProgramPath);
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
    private readonly IServiceProvider _serviceProvider;

    public UdapControllerTests(ApiTestFixture fixture, ITestOutputHelper output, ITestOutputHelper testOutputHelper)
    {
        //
        // Fixture is for FHIR Server configuration
        //
        if (fixture == null) throw new ArgumentNullException(nameof(fixture));
        fixture.Output = output;
        _fixture = fixture;


        //
        // This are is for client Dependency injection and Configuration
        //
        var configuration = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json", false, true)
            // .AddUserSecrets<UdapControllerTests>()
            .Build();

        //
        // Important to test UdapClient with DI because we want to take advantage of DotNet DI and the HttpClientFactory
        //
        var services = new ServiceCollection();

        services.AddLogging(logging =>
        {
            logging.ClearProviders();
            logging.AddXUnit(testOutputHelper);
        });
        
        // UDAP CertStore
        services.Configure<UdapFileCertStoreManifest>(configuration.GetSection(Constants.UDAP_FILE_STORE_MANIFEST));
        services.AddSingleton<ITrustAnchorStore>(sp =>
            new TrustAnchorFileStore(
                sp.GetRequiredService<IOptionsMonitor<UdapFileCertStoreManifest>>(),
                new Mock<ILogger<TrustAnchorFileStore>>().Object));

        var problemFlags = X509ChainStatusFlags.NotTimeValid |
                           X509ChainStatusFlags.Revoked |
                           X509ChainStatusFlags.NotSignatureValid |
                           X509ChainStatusFlags.InvalidBasicConstraints |
                           X509ChainStatusFlags.CtlNotTimeValid |
                           // X509ChainStatusFlags.OfflineRevocation |
                           X509ChainStatusFlags.CtlNotSignatureValid;
                       // X509ChainStatusFlags.RevocationStatusUnknown;


        services.TryAddScoped(_ => new TrustChainValidator(
            new X509ChainPolicy()
            {
                DisableCertificateDownloads = true,
                UrlRetrievalTimeout = TimeSpan.FromMicroseconds(1),
            }, 
            problemFlags,
            testOutputHelper.ToLogger<TrustChainValidator>()));

        services.AddSingleton<UdapClientDiscoveryValidator>();
        services.AddTransient<HeaderAugmentationHandler>();
        services.Configure<UdapClientOptions>(configuration.GetSection("UdapClientOptions"));

        services.AddScoped<IUdapClient>(sp => 
            new UdapClient(_fixture.CreateDefaultClient(sp.GetRequiredService<HeaderAugmentationHandler>()), 
                sp.GetRequiredService<UdapClientDiscoveryValidator>(),
                sp.GetRequiredService<IOptionsMonitor<UdapClientOptions>>(),
                sp.GetRequiredService<ILogger<UdapClient>>()));

        //
        // Use this method in an application
        //
        //services.AddHttpClient<IUdapClient, UdapClient>();

        _serviceProvider = services.BuildServiceProvider();
    }

    /// <summary>
    /// 200 response.
    /// Well formed Json
    /// </summary>
    [Fact]
    public async Task UdapClientTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4");
        
        disco.IsError.Should().BeFalse($"\nError: {disco.Error} \nError Type: {disco.ErrorType}\n{disco.Raw}");
        disco.HttpStatusCode.Should().Be(HttpStatusCode.OK);
        Assert.NotNull(udapClient.UdapServerMetaData);
    }
    

    /// <summary>
    /// udap_versions_supported must contain a fixed array with one string
    /// </summary>
    [Fact]
    public async Task udap_versions_supportedTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4");

        var verSupported = disco.UdapVersionsSupported.ToList();
        verSupported.Should().NotBeNullOrEmpty();
        verSupported.Single().Should().Be("1");
    }


    [Fact]
    public async Task udap_authorization_extensions_supportedTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4");

        var extensions = disco.UdapAuthorizationExtensionsSupported.ToList();
        extensions.Should().NotBeNullOrEmpty();

        var hl7B2B = extensions.SingleOrDefault(c => c == "hl7-b2b");
        hl7B2B.Should().NotBeNullOrEmpty();
    }

    /// <summary>
    /// Conditional.  Not required but setup for this test.
    /// </summary>
    [Fact]
    public async Task udap_authorization_extensions_requiredTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4");

        disco.UdapAuthorizationExtensionsRequired.Should().Contain("hl7-b2b");
    }

    /// <summary>
    /// udap_certifications_supported is an array of zero or more certification URIs
    /// </summary>
    [Fact]
    public async Task udap_certifications_supportedTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4");

        var certificationsSupported = disco.UdapCertificationsSupported.SingleOrDefault(c => c == "http://MyUdapCertification");
        certificationsSupported.Should().NotBeNullOrEmpty();
        var uriCertificationsSupported = new Uri(certificationsSupported!);
        uriCertificationsSupported.Should().Be("http://MyUdapCertification");

        certificationsSupported = disco.UdapCertificationsSupported.SingleOrDefault(c => c == "http://MyUdapCertification2");
        certificationsSupported.Should().NotBeNullOrEmpty();
        uriCertificationsSupported = new Uri(certificationsSupported!);
        uriCertificationsSupported.Should().Be("http://MyUdapCertification2");
    }

    /// <summary>
    /// udap_certifications_required is an array of zero or more certification URIs
    /// </summary>
    [Fact]
    public async Task udap_certifications_requiredTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4");

        var certificationsSupported = disco.UdapCertificationsRequired.SingleOrDefault();
        certificationsSupported.Should().NotBeNullOrEmpty();
        var uriCertificationsSupported = new Uri(certificationsSupported!);
        uriCertificationsSupported.Should().Be("http://MyUdapCertification");
    }

    [Fact]
    public async Task grant_types_supportedTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4");

        var grantTypes = disco.GrantTypesSupported.ToList();
        grantTypes.Should().NotBeNullOrEmpty();

        grantTypes.Count().Should().Be(3);
        grantTypes.Should().Contain("authorization_code");
        grantTypes.Should().Contain("refresh_token");
        grantTypes.Should().Contain("client_credentials");
    }

    [Fact]
    public async Task scopes_supported_supportedTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4");

        var scopesSupported = disco.ScopesSupported.ToList();

        scopesSupported.Should().Contain("openid");
        scopesSupported.Should().Contain("system/*.read");
        scopesSupported.Should().Contain("user/*.read");
        scopesSupported.Should().Contain("patient/*.read");
    }

    [Fact]
    public async Task authorization_endpointTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4");

        var authorizationEndpoint = disco.AuthorizeEndpoint;
        authorizationEndpoint.Should().Be("https://host.docker.internal:5002/connect/authorize");
    }

    [Fact]
    public async Task token_endpointTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4");

        var tokenEndpoint = disco.TokenEndpoint;
        tokenEndpoint.Should().Be("https://host.docker.internal:5002/connect/token");
    }

    [Fact]
    public async Task registration_endpointTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4");

        var registrationEndpoint = disco.RegistrationEndpoint;
        registrationEndpoint.Should().Be("https://host.docker.internal:5002/connect/register");
    }

    [Fact]
    public async Task token_endpoint_auth_methods_supportedTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4");

        var scopesSupported = disco.TokenEndpointAuthMethodsSupported.SingleOrDefault();
        scopesSupported.Should().NotBeNullOrEmpty();
        scopesSupported.Should().Be("private_key_jwt");
    }

    [Fact]
    public async Task token_endpoint_auth_signing_alg_values_supportedTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();
        
        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4");
        
        var signingAlgValuesSupported = disco.RegistrationEndpointJwtSigningAlgValuesSupported.ToList();
        signingAlgValuesSupported.Should().NotBeNullOrEmpty();
        signingAlgValuesSupported.Should().Contain(UdapConstants.SupportedAlgorithm.RS256);
        signingAlgValuesSupported.Should().Contain(UdapConstants.SupportedAlgorithm.RS384);
        signingAlgValuesSupported.Count().Should().Be(2);
    }

    [Fact]
    public async Task registration_endpoint_jwt_signing_alg_values_supportedTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4");

        var scopesSupported = disco.RegistrationEndpointJwtSigningAlgValuesSupported.ToList();
        scopesSupported.Should().NotBeNullOrEmpty();
        scopesSupported.Should().Contain(UdapConstants.SupportedAlgorithm.RS256);
        scopesSupported.Should().Contain(UdapConstants.SupportedAlgorithm.RS384);
        scopesSupported.Count().Should().Be(2);
    }

    [Fact]
    public async Task signed_metadataTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4");

        var signedMetatData = disco.SignedMetadata;
        signedMetatData.Should().NotBeNullOrEmpty();

        var pattern = @"^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+\/=]*$";
        var regex = new Regex(pattern);
        regex.IsMatch(signedMetatData!).Should().BeTrue("signed_metadata is not a valid JWT");
    }

    [Fact]
    public async Task signed_metadataContentTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();

        var disco = await udapClient.ValidateResource(_fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4");
        disco.IsError.Should().BeFalse($"\nError: {disco.Error} \nError Type: {disco.ErrorType}\n{disco.Raw}");

        var jwt = new JwtSecurityToken(disco.SignedMetadata);
        var tokenHeader = jwt.Header;

        var x5CArray = tokenHeader["x5c"] as List<object>;

        // bad keys
        //x5cArray[0] = "MIIFJDCCBAygAwIBAgIIUFnObaPiufEwDQYJKoZIhvcNAQELBQAwgbMxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlTYW4gRGllZ28xEzARBgNVBAoMCkVNUiBEaXJlY3QxPzA9BgNVBAsMNlRlc3QgUEtJIENlcnRpZmljYXRpb24gQXV0aG9yaXR5IChjZXJ0cy5lbXJkaXJlY3QuY29tKTElMCMGA1UEAwwcRU1SIERpcmVjdCBUZXN0IENsaWVudCBTdWJDQTAeFw0yMTAxMTUyMTQ1MTRaFw0yNDAxMTYyMTQ1MTRaMIGlMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTETMBEGA1UECgwKRU1SIERpcmVjdDEzMDEGA1UECwwqVURBUCBUZXN0IENlcnRpZmljYXRlIE5PVCBGT1IgVVNFIFdJVEggUEhJMTcwNQYDVQQDDC5odHRwczovL3N0YWdlLmhlYWx0aHRvZ28ubWU6ODE4MS9maGlyL3I0L3N0YWdlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt9j718Yu8HjoIdSvLTloVLnFLdfdL7T/BylPcIpcKhB7zJvNzZOpq8T/fXhc9b4p6cY6gBPBq1Vnax4zTCAP/te5W6FfoRoKhKqpExuYmgIw0lE8a4UAnHVwPOAvuKS3abGzYfLxxUc4PFXp4HrBx/QWOMqR408GlbSYG0wpeifhMx1VD8TFmU13FmFqgP3cEHjT7RxulfJnPcPPXZ8b5tZIkQMlApJRULVnHEBcICixaRWCJjzzArgoFUydPiAfMZELi80W4n0Wn/WduSYZqwQAosI7AfS3NINd44w8kek1X9WVwX/QtcAVuCXvSFoqoIAa3l4kBCQIHmY9UhltZwIDAQABo4IBRjCCAUIwWQYIKwYBBQUHAQEETTBLMEkGCCsGAQUFBzAChj1odHRwOi8vY2VydHMuZW1yZGlyZWN0LmNvbS9jZXJ0cy9FTVJEaXJlY3RUZXN0Q2xpZW50U3ViQ0EuY3J0MB0GA1UdDgQWBBRZmXqpQzFDSamfvPKiKtjg9gp8cTAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFKOVbWu9K1HN4c/lkG/XJk+/3T7eMEwGA1UdHwRFMEMwQaA/oD2GO2h0dHA6Ly9jZXJ0cy5lbXJkaXJlY3QuY29tL2NybC9FTVJEaXJlY3RUZXN0Q2xpZW50U3ViQ0EuY3JsMA4GA1UdDwEB/wQEAwIHgDA5BgNVHREEMjAwhi5odHRwczovL3N0YWdlLmhlYWx0aHRvZ28ubWU6ODE4MS9maGlyL3I0L3N0YWdlMA0GCSqGSIb3DQEBCwUAA4IBAQAePi+wIAPubt2Fk2jbELZt/bgkc7KTGC5C4sLX25NNYyzvHh0kwmHvgBx3thCv7uOvf/nbmhnk+l3EmgdaB1ZjzcjLMFc7xec9YJWsegzEkR2pzYQp/41cmhTfwNSnXxUSZrBtqInx+mALi9r96lg6RpqQh+DxlToC2vreW7Fy3pFa3DQKFN6j6azYTj5ljqrGprKQRh/iyqRvY+j+BC44Wl+POfBVObwtf71irMuLsSCmMptPGFGTqQdtLYbFjkB4wowiFfEe0PYL+N015iPZA4wimlXbau4XaEvipnIsWxqzT30RbQgrrOw7zN1QjGRURBbdBkMrgLkzmfGxhjuV";

        var cert = new X509Certificate2(Convert.FromBase64String(x5CArray!.First()?.ToString()!));

        var tokenHandler = new JwtSecurityTokenHandler();
        
        tokenHandler.ValidateToken(disco.SignedMetadata, new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateLifetime = true,
            IssuerSigningKey = new X509SecurityKey(cert),
            ValidAlgorithms = new[] { tokenHeader.Alg },
            ValidateAudience = false
        }, out _);

        var issClaim = jwt.Payload.Claims.Single(c => c.Type == JwtClaimTypes.Issuer);
        issClaim.ValueType.Should().Be(ClaimValueTypes.String);

        // should be the same as the web base url
        issClaim.Value.Should().Be("http://localhost/fhir/r4");

        var subjectAltNames = cert.GetSubjectAltNames(n => n.TagNo == (int)X509Extensions.GeneralNameType.URI); //specification (predicate) will filter to only SANs of type uniformResourceIdentifier

        subjectAltNames.Select(s => s.Item2).Should().Contain(issClaim.Value, $"iss: {issClaim.Value} does not match Subject Alternative Name extension");
        
        var subClaim = jwt.Payload.Claims.Single(c => c.Type == JwtClaimTypes.Subject);
        subClaim.ValueType.Should().Be(ClaimValueTypes.String);

        issClaim.Value.Should().BeEquivalentTo(subClaim.Value);


        var iatClaim = jwt.Payload.Claims.Single(c => c.Type == JwtClaimTypes.IssuedAt);
        iatClaim.ValueType.Should().Be(ClaimValueTypes.Integer64);

        var expClaim = jwt.Payload.Claims.Single(c => c.Type == JwtClaimTypes.Expiration);
        expClaim.ValueType.Should().Be(ClaimValueTypes.Integer64);

        var iat = int.Parse(iatClaim.Value);
        var exp = int.Parse(expClaim.Value);
        var year = DateTimeOffset.FromUnixTimeSeconds(exp).AddYears(1).ToUnixTimeSeconds();
        iat.Should().BeLessOrEqualTo((int)year);
    }
}