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
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.RegularExpressions;
using Duende.IdentityModel;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using Udap.Client;
using Udap.Client.Configuration;
using Udap.Common;
using Udap.Common.Certificates;
using Udap.Model;
using Udap.Smart.Model;
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

public class SmartControllerTests : IClassFixture<ApiTestFixture>
{
    private readonly ApiTestFixture _fixture;

    public SmartControllerTests(ApiTestFixture fixture, ITestOutputHelper testOutputHelper)
    {
        //
        // Fixture is for FHIR Server configuration
        //
        ArgumentNullException.ThrowIfNull(fixture);
        fixture.Output = testOutputHelper;
        _fixture = fixture;
    }

    /// <summary>
    /// 200 response.
    /// Well-formed Json
    /// </summary>
    [Fact]
    public async Task SmartClientTest()
    {
        var httpClient = _fixture.CreateClient(); //.BaseAddress?.AbsoluteUri + "fhir/r4";
        
        var result = await httpClient.GetAsync("fhir/r4/.well-known/smart-configuration");
        Assert.Equal(HttpStatusCode.OK, result.StatusCode);

        var smartMetadata = await result.Content.ReadFromJsonAsync<SmartMetadata>();
        Assert.NotNull(smartMetadata);
        Assert.Equal("https://host.docker.internal:5002", smartMetadata!.issuer);

        result = await httpClient.GetAsync("fhir/r4/.well-known/smart-configurationx");
        Assert.Equal(HttpStatusCode.NotFound, result.StatusCode);
    }
}

public class UdapControllerTests : IClassFixture<ApiTestFixture>
{
    private readonly ApiTestFixture _fixture;
    private readonly IServiceProvider _serviceProvider;

    public UdapControllerTests(ApiTestFixture fixture, ITestOutputHelper testOutputHelper)
    {
        //
        // Fixture is for FHIR Server configuration
        //
        ArgumentNullException.ThrowIfNull(fixture);
        fixture.Output = testOutputHelper;
        _fixture = fixture;


        //
        // This are is for client Dependency injection and Configuration
        //
        var configuration = new ConfigurationBuilder()
            .AddJsonFile("appsettings.FhirLabsApi.json", false, true)
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
        services.Configure<UdapFileCertStoreManifest>(configuration.GetSection(Constants.UdapFileCertStoreManifestSectionName));
        services.AddSingleton<ITrustAnchorStore>(sp =>
            new TrustAnchorFileStore(
                sp.GetRequiredService<IOptionsMonitor<UdapFileCertStoreManifest>>(),
                Substitute.For<ILogger<TrustAnchorFileStore>>()));

        var problemFlags = ChainProblemStatus.NotTimeValid |
                           ChainProblemStatus.Revoked |
                           ChainProblemStatus.NotSignatureValid |
                           ChainProblemStatus.InvalidBasicConstraints;
                       // ChainProblemStatus.OfflineRevocation;


        services.TryAddScoped(_ => new TrustChainValidator(
            problemFlags,
            false,
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
    /// Well-formed Json
    /// </summary>
    [Fact]
    public async Task UdapClientTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4");
        
        Assert.False(disco.IsError, $"\nError: {disco.Error} \nError Type: {disco.ErrorType}\n{disco.Raw}");
        Assert.Equal(HttpStatusCode.OK, disco.HttpStatusCode);
        Assert.NotNull(udapClient.UdapServerMetadata);
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

        var verSupported = disco.UdapVersionsSupported?.ToList();
        Assert.NotNull(verSupported);
        Assert.NotEmpty(verSupported!);
        Assert.Equal("1", verSupported!.Single());
    }


    [Fact]
    public async Task udap_authorization_extensions_supportedTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4");

        var extensions = disco.UdapAuthorizationExtensionsSupported?.ToList();
        Assert.NotNull(extensions);
        Assert.NotEmpty(extensions!);

        var hl7B2B = extensions?.SingleOrDefault(c => c == "hl7-b2b");
        Assert.False(string.IsNullOrEmpty(hl7B2B));
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

        Assert.Contains("hl7-b2b", disco.UdapAuthorizationExtensionsRequired);
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

        var certificationsSupported = disco.UdapCertificationsSupported?.SingleOrDefault(c => c == "http://MyUdapCertification");
        Assert.False(string.IsNullOrEmpty(certificationsSupported));
        var uriCertificationsSupported = new Uri(certificationsSupported!);
        Assert.Equal(new Uri("http://MyUdapCertification"), uriCertificationsSupported);

        certificationsSupported = disco.UdapCertificationsSupported?.SingleOrDefault(c => c == "http://MyUdapCertification2");
        Assert.False(string.IsNullOrEmpty(certificationsSupported));
        uriCertificationsSupported = new Uri(certificationsSupported!);
        Assert.Equal(new Uri("http://MyUdapCertification2"), uriCertificationsSupported);
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

        var certificationsRequired = disco.UdapCertificationsRequired?.SingleOrDefault();
        Assert.False(string.IsNullOrEmpty(certificationsRequired));
        var uriCertificationsRequired = new Uri(certificationsRequired!);
        Assert.Equal(new Uri("http://MyUdapCertification"), uriCertificationsRequired);
    }

    /// <summary>
    /// SOP: Facilitated FHIR Implementation v2.0 — Section 6.11 Discovery #2-3
    /// When queried with ?community=urn:oid:2.16.840.1.113883.3.7204.1.5,
    /// the TEFCA community metadata MUST include the basic-app-certification URI
    /// in both udap_certifications_supported and udap_certifications_required.
    /// </summary>
    [Fact]
    public async Task TefcaCommunity_Certifications_OverrideRootDefaults()
    {
        var httpClient = _fixture.CreateClient();

        var response = await httpClient.GetAsync(
            "fhir/r4/.well-known/udap?community=urn:oid:2.16.840.1.113883.3.7204.1.5");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = await response.Content.ReadFromJsonAsync<JsonDocument>();
        Assert.NotNull(json);

        const string basicAppCert = "https://rce.sequoiaproject.org/udap/profiles/basic-app-certification";

        // TEFCA community must include basic-app-certification in certifications_supported
        var certSupported = json.RootElement
            .GetProperty("udap_certifications_supported")
            .EnumerateArray()
            .Select(e => e.GetString())
            .ToList();

        Assert.Contains(basicAppCert, certSupported);

        // TEFCA community must include basic-app-certification in certifications_required
        var certRequired = json.RootElement
            .GetProperty("udap_certifications_required")
            .EnumerateArray()
            .Select(e => e.GetString())
            .ToList();

        Assert.Contains(basicAppCert, certRequired);

        // TEFCA community should NOT include the root-level test certifications
        Assert.DoesNotContain("http://MyUdapCertification", certSupported);
        Assert.DoesNotContain("http://MyUdapCertification2", certSupported);
    }

    [Fact]
    public async Task grant_types_supportedTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4");

        var grantTypes = disco.GrantTypesSupported?.ToList();
        Assert.NotNull(grantTypes);
        Assert.NotEmpty(grantTypes!);

        Assert.Equal(3, grantTypes!.Count);
        Assert.Contains("authorization_code", grantTypes);
        Assert.Contains("refresh_token", grantTypes);
        Assert.Contains("client_credentials", grantTypes);
    }

    [Fact]
    public async Task scopes_supported_supportedTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4");

        var scopesSupported = disco.ScopesSupported?.ToList();

        Assert.Contains("openid", scopesSupported);
        Assert.Contains("system/*.read", scopesSupported);
        Assert.Contains("user/*.read", scopesSupported);
        Assert.Contains("patient/*.read", scopesSupported);
    }

    [Fact]
    public async Task authorization_endpointTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4");

        var authorizationEndpoint = disco.AuthorizeEndpoint;
        Assert.Equal("https://host.docker.internal:5002/connect/authorize", authorizationEndpoint);
    }

    [Fact]
    public async Task token_endpointTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4");

        var tokenEndpoint = disco.TokenEndpoint;
        Assert.Equal("https://host.docker.internal:5002/connect/token", tokenEndpoint);
    }

    [Fact]
    public async Task registration_endpointTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4");

        var registrationEndpoint = disco.RegistrationEndpoint;
        Assert.Equal("https://host.docker.internal:5002/connect/register", registrationEndpoint);
    }

    [Fact]
    public async Task token_endpoint_auth_methods_supportedTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4");

        var tokenEndpointAuthMethodSupported = disco.TokenEndpointAuthMethodsSupported?.SingleOrDefault();
        Assert.False(string.IsNullOrEmpty(tokenEndpointAuthMethodSupported));
        Assert.Equal("private_key_jwt", tokenEndpointAuthMethodSupported);
    }

    [Fact]
    public async Task token_endpoint_auth_signing_alg_values_supportedTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();
        
        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4");
        
        var registrationSigningAlgValuesSupported = disco.RegistrationEndpointJwtSigningAlgValuesSupported?.ToList();
        Assert.NotNull(registrationSigningAlgValuesSupported);
        Assert.NotEmpty(registrationSigningAlgValuesSupported!);
        Assert.Contains(UdapConstants.SupportedAlgorithm.RS256, registrationSigningAlgValuesSupported);
        Assert.Contains(UdapConstants.SupportedAlgorithm.RS384, registrationSigningAlgValuesSupported);
        Assert.Contains(UdapConstants.SupportedAlgorithm.ES256, registrationSigningAlgValuesSupported);
        Assert.Contains(UdapConstants.SupportedAlgorithm.ES384, registrationSigningAlgValuesSupported);
        Assert.Equal(4, registrationSigningAlgValuesSupported!.Count);
    }

    [Fact]
    public async Task registration_endpoint_jwt_signing_alg_values_supportedTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4");

        var tokenSigningAlgValuesSupported = disco.TokenEndpointAuthSigningAlgValuesSupported?.ToList();
        Assert.NotNull(tokenSigningAlgValuesSupported);
        Assert.NotEmpty(tokenSigningAlgValuesSupported!);
        Assert.Contains(UdapConstants.SupportedAlgorithm.RS256, tokenSigningAlgValuesSupported);
        Assert.Contains(UdapConstants.SupportedAlgorithm.RS384, tokenSigningAlgValuesSupported);
        Assert.Contains(UdapConstants.SupportedAlgorithm.ES256, tokenSigningAlgValuesSupported);
        Assert.Contains(UdapConstants.SupportedAlgorithm.ES384, tokenSigningAlgValuesSupported);
        Assert.Equal(4, tokenSigningAlgValuesSupported!.Count);
    }

    [Fact]
    public async Task signed_metadataTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4");

        var signedMetatData = disco.SignedMetadata;
        Assert.False(string.IsNullOrEmpty(signedMetatData));

        var pattern = @"^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+\/=]*$";
        var regex = new Regex(pattern);
        Assert.True(regex.IsMatch(signedMetatData!), "signed_metadata is not a valid JWT");
    }

    [Fact]
    public async Task signed_metadataContentTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();

        var disco = await udapClient.ValidateResource(_fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4");
        Assert.False(disco.IsError, $"\nError: {disco.Error} \nError Type: {disco.ErrorType}\n{disco.Raw}");

        var jwt = new JwtSecurityToken(disco.SignedMetadata);
        var tokenHeader = jwt.Header;

        var x5CArray = tokenHeader["x5c"] as List<object>;

        // bad keys
        //x5cArray[0] = "MIIFJDCCBAygAwIBAgIIUFnObaPiufEwDQYJKoZIhvcNAQELBQAwgbMxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlTYW4gRGllZ28xEzARBgNVBAoMCkVNUiBEaXJlY3QxPzA9BgNVBAsMNlRlc3QgUEtJIENlcnRpZmljYXRpb24gQXV0aG9yaXR5IChjZXJ0cy5lbXJkaXJlY3QuY29tKTElMCMGA1UEAwwcRU1SIERpcmVjdCBUZXN0IENsaWVudCBTdWJDQTAeFw0yMTAxMTUyMTQ1MTRaFw0yNDAxMTYyMTQ1MTRaMIGlMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTETMBEGA1UECgwKRU1SIERpcmVjdDEzMDEGA1UECwwqVURBUCBUZXN0IENlcnRpZmljYXRlIE5PVCBGT1IgVVNFIFdJVEggUEhJMTcwNQYDVQQDDC5odHRwczovL3N0YWdlLmhlYWx0aHRvZ28ubWU6ODE4MS9maGlyL3I0L3N0YWdlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt9j718Yu8HjoIdSvLTloVLnFLdfdL7T/BylPcIpcKhB7zJvNzZOpq8T/fXhc9b4p6cY6gBPBq1Vnax4zTCAP/te5W6FfoRoKhKqpExuYmgIw0lE8a4UAnHVwPOAvuKS3abGzYfLxxUc4PFXp4HrBx/QWOMqR408GlbSYG0wpeifhMx1VD8TFmU13FmFqgP3cEHjT7RxulfJnPcPPXZ8b5tZIkQMlApJRULVnHEBcICixaRWCJjzzArgoFUydPiAfMZELi80W4n0Wn/WduSYZqwQAosI7AfS3NINd44w8kek1X9WVwX/QtcAVuCXvSFoqoIAa3l4kBCQIHmY9UhltZwIDAQABo4IBRjCCAUIwWQYIKwYBBQUHAQEETTBLMEkGCCsGAQUFBzAChj1odHRwOi8vY2VydHMuZW1yZGlyZWN0LmNvbS9jZXJ0cy9FTVJEaXJlY3RUZXN0Q2xpZW50U3ViQ0EuY3J0MB0GA1UdDgQWBBRZmXqpQzFDSamfvPKiKtjg9gp8cTAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFKOVbWu9K1HN4c/lkG/XJk+/3T7eMEwGA1UdHwRFMEMwQaA/oD2GO2h0dHA6Ly9jZXJ0cy5lbXJkaXJlY3QuY29tL2NybC9FTVJEaXJlY3RUZXN0Q2xpZW50U3ViQ0EuY3JsMA4GA1UdDwEB/wQEAwIHgDA5BgNVHREEMjAwhi5odHRwczovL3N0YWdlLmhlYWx0aHRvZ28ubWU6ODE4MS9maGlyL3I0L3N0YWdlMA0GCSqGSIb3DQEBCwUAA4IBAQAePi+wIAPubt2Fk2jbELZt/bgkc7KTGC5C4sLX25NNYyzvHh0kwmHvgBx3thCv7uOvf/nbmhnk+l3EmgdaB1ZjzcjLMFc7xec9YJWsegzEkR2pzYQp/41cmhTfwNSnXxUSZrBtqInx+mALi9r96lg6RpqQh+DxlToC2vreW7Fy3pFa3DQKFN6j6azYTj5ljqrGprKQRh/iyqRvY+j+BC44Wl+POfBVObwtf71irMuLsSCmMptPGFGTqQdtLYbFjkB4wowiFfEe0PYL+N015iPZA4wimlXbau4XaEvipnIsWxqzT30RbQgrrOw7zN1QjGRURBbdBkMrgLkzmfGxhjuV";

#if NET9_0_OR_GREATER
        var cert = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(x5CArray!.First().ToString()!));
#else
        var cert = new X509Certificate2(Convert.FromBase64String(x5CArray!.First().ToString()!));
#endif

        var tokenHandler = new JwtSecurityTokenHandler();
        
        tokenHandler.ValidateToken(disco.SignedMetadata, new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateLifetime = true,
            IssuerSigningKey = new X509SecurityKey(cert),
            ValidAlgorithms = [tokenHeader.Alg],
            ValidateAudience = false
        }, out _);

        var issClaim = jwt.Payload.Claims.Single(c => c.Type == JwtClaimTypes.Issuer);
        Assert.Equal(ClaimValueTypes.String, issClaim.ValueType);

        // should be the same as the web base url
        Assert.Equal("http://localhost/fhir/r4", issClaim.Value);

        var subjectAltNames = cert.GetSubjectAltNames(n => n.TagNo == (int)X509Extensions.GeneralNameType.URI); //specification (predicate) will filter to only SANs of type uniformResourceIdentifier

        Assert.Contains(issClaim.Value, subjectAltNames.Select(s => s.Item2));

        var subClaim = jwt.Payload.Claims.Single(c => c.Type == JwtClaimTypes.Subject);
        Assert.Equal(ClaimValueTypes.String, subClaim.ValueType);

        Assert.Equal(subClaim.Value, issClaim.Value, StringComparer.OrdinalIgnoreCase);


        var iatClaim = jwt.Payload.Claims.Single(c => c.Type == JwtClaimTypes.IssuedAt);
        Assert.Equal(ClaimValueTypes.Integer64, iatClaim.ValueType);

        var expClaim = jwt.Payload.Claims.Single(c => c.Type == JwtClaimTypes.Expiration);
        Assert.Equal(ClaimValueTypes.Integer64, expClaim.ValueType);

        var iat = int.Parse(iatClaim.Value);
        var exp = int.Parse(expClaim.Value);
        var year = DateTimeOffset.FromUnixTimeSeconds(exp).AddYears(1).ToUnixTimeSeconds();
        Assert.True(iat <= (int)year);
    }
}