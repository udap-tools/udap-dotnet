#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using MartinCostello.Logging.XUnit;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Text.Json;
using Udap.Client;
using Udap.Client.Configuration;
using Udap.Common.Certificates;
using Udap.Common.Metadata;
using Udap.Model;
using Udap.Support.Tests.Client;
using Xunit.Abstractions;

namespace Udap.Common.Tests.Client;


public class UdapClientTests
{
    private readonly ITestOutputHelper _testOutputHelper;
    private readonly IConfigurationRoot _configuration;
    private readonly ServiceProvider _serviceProvider;

    readonly ChainProblemStatus _problemFlags = ChainProblemStatus.NotTimeValid |
                                        ChainProblemStatus.Revoked |
                                        ChainProblemStatus.NotSignatureValid |
                                        ChainProblemStatus.InvalidBasicConstraints;
                                        // ChainProblemStatus.OfflineRevocation; Do not test revocation in unit tests

    public UdapClientTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
        _configuration = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json", false, true)
            .Build();

        _serviceProvider = new ServiceCollection()
            .AddLogging(builder =>
            {
                builder.AddConfiguration(_configuration.GetSection("Logging"));
                builder.AddProvider(new XUnitLoggerProvider(testOutputHelper, new XUnitLoggerOptions()));
                // builder.SetMinimumLevel(LogLevel.Warning); 
            })
            .BuildServiceProvider();
    }

    /// <summary>
    /// Test with just the basics.  Some good comments to see how all the parts fit together
    /// </summary>
    /// <returns></returns>
    [Fact]
    public async Task StandardSuccessTest()
    {
        var (httpClientMock, udapClientDiscoveryValidator, udapClientIOptions, _) = await BuildClientSupport();

        //
        // The actual UdapClient.  There are two examples of using it in the _tests/client folder
        //
        var udapClient = new UdapClient(
             httpClientMock,
             udapClientDiscoveryValidator,
             udapClientIOptions,
             _serviceProvider.GetRequiredService<ILogger<UdapClient>>());


        var disco = await udapClient.ValidateResource("https://fhirlabs.net/fhir/r4", null);

        Assert.False(disco.IsError, $"\nError: {disco.Error} \nError Type: {disco.ErrorType}\n{disco.Raw}");
        Assert.Equal(HttpStatusCode.OK, disco.HttpStatusCode);
        Assert.NotNull(udapClient.UdapServerMetadata);


        //
        // Various properties asserted
        // These tests are also in the Udap.Metadata tests.  Those tests are integration and only cover the Framework version of the current web service.
        // These tests are easier to test against all the current framework versions.  For example currently this test is testing .Net 6, 7 and 8
        // ensuring we get good coverage
        //
        var verSupported = disco.UdapVersionsSupported!.ToList();
        Assert.NotEmpty(verSupported);
        Assert.Equal("1", verSupported.Single());


        var extensions = disco.UdapAuthorizationExtensionsSupported!.ToList();
        Assert.NotEmpty(extensions);
        var hl7B2B = extensions.SingleOrDefault(c => c == "hl7-b2b");
        Assert.False(string.IsNullOrEmpty(hl7B2B));


        Assert.Contains("hl7-b2b", disco.UdapAuthorizationExtensionsRequired!);


        var certificationsSupported = disco.UdapCertificationsSupported!.SingleOrDefault(c => c == "http://MyUdapCertification");
        Assert.False(string.IsNullOrEmpty(certificationsSupported));
        var uriCertificationsSupported = new Uri(certificationsSupported!);
        Assert.Equal(new Uri("http://MyUdapCertification"), uriCertificationsSupported);


        certificationsSupported = disco.UdapCertificationsSupported!.SingleOrDefault(c => c == "http://MyUdapCertification2");
        Assert.False(string.IsNullOrEmpty(certificationsSupported));
        uriCertificationsSupported = new Uri(certificationsSupported!);
        Assert.Equal(new Uri("http://MyUdapCertification2"), uriCertificationsSupported);


        var certificationsRequired = disco.UdapCertificationsRequired!.SingleOrDefault();
        Assert.False(string.IsNullOrEmpty(certificationsRequired));
        var uriCertificationsRequired = new Uri(certificationsRequired!);
        Assert.Equal(new Uri("http://MyUdapCertification"), uriCertificationsRequired);


        var grantTypes = disco.GrantTypesSupported!.ToList();
        Assert.NotEmpty(grantTypes);
        Assert.Equal(3, grantTypes.Count);
        Assert.Contains("authorization_code", grantTypes);
        Assert.Contains("refresh_token", grantTypes);
        Assert.Contains("client_credentials", grantTypes);


        var scopesSupported = disco.ScopesSupported!.ToList();
        Assert.Contains("openid", scopesSupported);
        Assert.Contains("system/*.read", scopesSupported);
        Assert.Contains("user/*.read", scopesSupported);
        Assert.Contains("patient/*.read", scopesSupported);


        var authorizationEndpoint = disco.AuthorizeEndpoint;
        Assert.Equal("https://securedcontrols.net:5001/connect/authorize", authorizationEndpoint);


        var tokenEndpoint = disco.TokenEndpoint;
        Assert.Equal("https://securedcontrols.net:5001/connect/token", tokenEndpoint);


        var registrationEndpoint = disco.RegistrationEndpoint;
        Assert.Equal("https://securedcontrols.net:5001/connect/register", registrationEndpoint);


        var tokenEndpointAuthMethodSupported = disco.TokenEndpointAuthMethodsSupported!.SingleOrDefault();
        Assert.False(string.IsNullOrEmpty(tokenEndpointAuthMethodSupported));
        Assert.Equal("private_key_jwt", tokenEndpointAuthMethodSupported);


        var registrationSigningAlgValuesSupported = disco.RegistrationEndpointJwtSigningAlgValuesSupported!.ToList();
        Assert.NotEmpty(registrationSigningAlgValuesSupported);
        Assert.Contains(UdapConstants.SupportedAlgorithm.RS256, registrationSigningAlgValuesSupported);
        Assert.Contains(UdapConstants.SupportedAlgorithm.RS384, registrationSigningAlgValuesSupported);
        Assert.Contains(UdapConstants.SupportedAlgorithm.ES256, registrationSigningAlgValuesSupported);
        Assert.Contains(UdapConstants.SupportedAlgorithm.ES384, registrationSigningAlgValuesSupported);
        Assert.Equal(4, registrationSigningAlgValuesSupported.Count);



        var tokenSigningAlgValuesSupported = disco.TokenEndpointAuthSigningAlgValuesSupported!.ToList();
        Assert.NotEmpty(tokenSigningAlgValuesSupported);
        Assert.Contains(UdapConstants.SupportedAlgorithm.RS256, tokenSigningAlgValuesSupported);
        Assert.Contains(UdapConstants.SupportedAlgorithm.RS384, tokenSigningAlgValuesSupported);
        Assert.Contains(UdapConstants.SupportedAlgorithm.ES256, tokenSigningAlgValuesSupported);
        Assert.Contains(UdapConstants.SupportedAlgorithm.ES384, tokenSigningAlgValuesSupported);
        Assert.Equal(4, tokenSigningAlgValuesSupported.Count);

        var profilesSupported = disco.UdapProfilesSupported!.ToList();
        Assert.NotEmpty(profilesSupported);
        Assert.Contains(UdapConstants.UdapProfilesSupportedValues.UdapDcr, profilesSupported);
        Assert.Contains(UdapConstants.UdapProfilesSupportedValues.UdapAuthn, profilesSupported);
        Assert.Contains(UdapConstants.UdapProfilesSupportedValues.UdapAuthz, profilesSupported);

        //
        // Checking the SignedMetadata
        //

        var jwt = new JwtSecurityToken(disco.SignedMetadata);
        var tokenHeader = jwt.Header;

        var x5CArray = tokenHeader["x5c"] as List<object>;
    }

    [Fact]
    public async Task ClientSuppliedTrustAnchorStoreSuccessTest()
    {
        var (httpClientMock, udapClientDiscoveryValidator, udapClientIOptions, trustAnchorStore) = await BuildClientSupport();

        var udapClient = new UdapClient(
            httpClientMock,
            udapClientDiscoveryValidator,
            udapClientIOptions,
            _serviceProvider.GetRequiredService<ILogger<UdapClient>>());


        var disco = await udapClient.ValidateResource("https://fhirlabs.net/fhir/r4", trustAnchorStore);

        Assert.False(disco.IsError, $"\nError: {disco.Error} \nError Type: {disco.ErrorType}\n{disco.Raw}");
        Assert.Equal(HttpStatusCode.OK, disco.HttpStatusCode);
        Assert.NotNull(udapClient.UdapServerMetadata);
    }

    [Fact]
    public async Task FullWellKnownAddressTest()
    {
        var (httpClientMock, udapClientDiscoveryValidator, udapClientIOptions, trustAnchorStore) = await BuildClientSupport();

        var udapClient = new UdapClient(
            httpClientMock,
            udapClientDiscoveryValidator,
            udapClientIOptions,
            _serviceProvider.GetRequiredService<ILogger<UdapClient>>());

        var disco = await udapClient.ValidateResource("https://fhirlabs.net/fhir/r4/.well-known/udap", trustAnchorStore);

        Assert.False(disco.IsError, $"\nError: {disco.Error} \nError Type: {disco.ErrorType}\n{disco.Raw}");
        Assert.Equal(HttpStatusCode.OK, disco.HttpStatusCode);
        Assert.NotNull(udapClient.UdapServerMetadata);
    }

    private readonly FakeValidatorDiagnostics _diagnosticsValidator = new FakeValidatorDiagnostics();
    [Fact]
    public async Task MissingUdapMetadatTest()
    {
        var (httpClientMock, udapClientDiscoveryValidator, udapClientIOptions, trustAnchorStore) = await BuildClientSupport();
        //udapClientDiscoveryValidator.ValidateJwtToken(Arg.Any<UdapMetadata>(), Arg.Any<string>()).Returns(Task.FromResult(false));

        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("")
        };
        httpClientMock.SendAsync(Arg.Any<HttpRequestMessage>(), Arg.Any<CancellationToken>()).Returns(Task.FromResult(response));

        var udapClient = new UdapClient(
            httpClientMock,
            udapClientDiscoveryValidator,
            udapClientIOptions,
            _serviceProvider.GetRequiredService<ILogger<UdapClient>>());

        udapClient.Error += _diagnosticsValidator.OnError;
        var disco = await udapClient.ValidateResource("https://fhirlabs.net/fhir/r4", trustAnchorStore);

        Assert.True(disco.IsError);
        Assert.Equal("Missing UDAP Metadata", disco.Error);
    }

    [Fact]
    public async Task IssMatchToSubjectAltNameTest()
    {
        var (httpClientMock, udapClientDiscoveryValidator, udapClientIOptions, trustAnchorStore) = await BuildClientSupport("https://fhirlabs.net/fhir/r4", "udap://Iss.Mismatch.To.SubjAltName/");

        var udapClient = new UdapClient(
            httpClientMock,
            udapClientDiscoveryValidator,
            udapClientIOptions,
            _serviceProvider.GetRequiredService<ILogger<UdapClient>>());

        udapClient.TokenError += _diagnosticsValidator.OnTokenError;
        var disco = await udapClient.ValidateResource("https://fhirlabs.net/fhir/r4", trustAnchorStore, "udap://Iss.Mismatch.To.SubjAltName/");

        Assert.True(disco.IsError, disco.Raw);
        Assert.NotNull(udapClient.UdapServerMetadata);
        Assert.True(_diagnosticsValidator.TokenErrorCalled);
        Assert.Contains(_diagnosticsValidator.ActualErrorMessages, m => m.Contains("Failed JWT Validation"));
        // https://san.mismatch.fhirlabs.net/fhir/r4 is the subject alt used to sign software statement
        Assert.Contains(_diagnosticsValidator.ActualErrorMessages, m => m.Contains("https://san.mismatch.fhirlabs.net/fhir/r4"));
    }

    [Fact]
    public async Task InvalidJwtTokenBadIssMatchToBaseUrlTest()
    {
        var (httpClientMock, udapClientDiscoveryValidator, udapClientIOptions, trustAnchorStore) = await BuildClientSupport("http://fhirlabs.net/IssMismatchToBaseUrl/r4", "udap://Iss.Mismatch.To.BaseUrl/");

        var udapClient = new UdapClient(
            httpClientMock,
            udapClientDiscoveryValidator,
            udapClientIOptions,
            _serviceProvider.GetRequiredService<ILogger<UdapClient>>());

        udapClient.TokenError += _diagnosticsValidator.OnTokenError;
        var disco = await udapClient.ValidateResource("https://fhirlabs.net/fhir/r4", trustAnchorStore, "udap://Iss.Mismatch.To.BaseUrl/");

        Assert.True(disco.IsError, disco.Raw);
        Assert.NotNull(udapClient.UdapServerMetadata);
        Assert.True(_diagnosticsValidator.TokenErrorCalled);
        Assert.Contains(_diagnosticsValidator.ActualErrorMessages, m => m.Contains("JWT iss does not match baseUrl."));
    }

    // [Fact]
    // public async Task GetCommunitiesTest()
    // {
    //     var (httpClientMock, udapClientDiscoveryValidator, udapClientIOptions, trustAnchorStore) = await BuildClientSupport("http://fhirlabs.net/IssMismatchToBaseUrl/r4", "udap://Iss.Mismatch.To.BaseUrl/");
    //     
    //     var client = _fixture.CreateClient();
    //     var response = await client.GetAsync("fhir/r4/.well-known/udap/communities");
    //     response.EnsureSuccessStatusCode();
    //     var communities = await response.Content.ReadFromJsonAsync<List<string>>();
    //     communities.Count.Should().Be(6);
    //     communities.Should().Contain(c => c == "udap://fhirlabs1/");
    //     communities.Should().Contain(c => c == "udap://Provider2");
    //
    //     response = await client.GetAsync("fhir/r4/.well-known/udap/communities/ashtml");
    //     response.EnsureSuccessStatusCode();
    //     var communityHtml = await response.Content.ReadAsStringAsync();
    //     communityHtml.Should().NotBeNullOrWhiteSpace();
    //     communityHtml.Should().Contain("href=\"http://localhost/fhir/r4/.well-known/udap?community=udap://fhirlabs1/\"");
    //     communityHtml.Should().Contain("href=\"http://localhost/fhir/r4/.well-known/udap?community=udap://Provider2\"");
    // }

    private async Task<(
        HttpClient httpClientMock,
        UdapClientDiscoveryValidator udapClientDiscoveryValidator,
        IOptionsMonitor<UdapClientOptions> udapClientIOptions,
        ITrustAnchorStore trustAnchorFileStore)> BuildClientSupport(string baseUrl = "https://fhirlabs.net/fhir/r4", string? community = null)
    {
        //
        // Metadata for describing different UDAP metadata per community
        //
        var file = _configuration["UdapMetadataOptionsFile"] ?? "udap.metadata.options.json";
        var json = File.ReadAllText(file);
        var udapMetadataOptions = JsonSerializer.Deserialize<UdapMetadataOptions>(json);
        var udapMetadataOptionsProviderMock = Substitute.For<IUdapMetadataOptionsProvider>();
        udapMetadataOptionsProviderMock.Value.Returns(udapMetadataOptions);

        _ = new UdapMetadata(udapMetadataOptionsProviderMock.Value)
        {
            // TODO:  Make scope configuration first class in DI
            ScopesSupported = new List<string>
        {
            "openid", "patient/*.read", "user/*.read", "system/*.read", "patient/*.rs", "user/*.rs", "system/*.rs"
        }
        };



        //
        // Certificate store metadata
        //
        var udapFileCertStoreManifest = new UdapFileCertStoreManifest();
        _configuration.GetSection(Constants.UdapFileCertStoreManifestSectionName).Bind(udapFileCertStoreManifest);
        var udapFileCertStoreManifestOptions = Substitute.For<IOptionsMonitor<UdapFileCertStoreManifest>>();
        udapFileCertStoreManifestOptions.CurrentValue.Returns(udapFileCertStoreManifest);

        //
        // IPrivateCertificateStore implementation as a file store
        //
        var privateCertificateStore = new IssuedCertificateStore(udapFileCertStoreManifestOptions, _serviceProvider.GetRequiredService<ILogger<IssuedCertificateStore>>());

        //
        // MetadataBuilder helps build signed UDAP metadata using the previous metadata and IPrivateCertificateStore implementation
        //
        var metaDataBuilder = new UdapMetaDataBuilder<UdapMetadataOptions, UdapMetadata>(
            udapMetadataOptionsProviderMock,
            privateCertificateStore,
            _serviceProvider.GetRequiredService<ILogger<UdapMetaDataBuilder<UdapMetadataOptions, UdapMetadata>>>());
        var signedMetadata = await metaDataBuilder.SignMetaData(baseUrl, community);

        //
        // Mock an HttpClient used by UdapClient.  The mock will return the signed Metadata rather than rely on aa UDAP Metadata service.
        //
        var httpClientMock = Substitute.For<HttpClient>()!;
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(signedMetadata))
        };
        httpClientMock.SendAsync(Arg.Any<HttpRequestMessage>(), Arg.Any<CancellationToken>()).Returns(Task.FromResult(response));

        //
        // TrustChainValidator handle the x509 chain building, policy and validation
        //
        var validator = new TrustChainValidator(_problemFlags, false, _serviceProvider.GetRequiredService<ILogger<TrustChainValidator>>())!;

        //
        // TrustAnchorStore is using an ITrustAnchorStore implemented as a file store.
        //
        var trustAnchorStore = new TrustAnchorFileStore(udapFileCertStoreManifestOptions, _serviceProvider.GetRequiredService<ILogger<TrustAnchorFileStore>>());

        //
        // UdapClientDiscoveryValidator orchestrates JWT validation followed by x509 chain validation used by UdapClient
        //
        var udapClientDiscoveryValidator = Substitute.ForPartsOf<UdapClientDiscoveryValidator>(
            validator,
            _serviceProvider.GetRequiredService<ILogger<UdapClientDiscoveryValidator>>(),
            trustAnchorStore);

        //
        // Options for setting your client name, contacts, logo and HTTP headers.
        //
        var udapClientOptions = new UdapClientOptions();
        var udapClientIOptions = Substitute.For<IOptionsMonitor<UdapClientOptions>>();
        udapClientIOptions.CurrentValue.Returns(udapClientOptions);

        return (httpClientMock, udapClientDiscoveryValidator, udapClientIOptions, trustAnchorStore);
    }

    [Fact]
    public async Task EventDelegation_AllEvents_CanSubscribeAndUnsubscribe()
    {
        var (httpClientMock, udapClientDiscoveryValidator, udapClientIOptions, _) = await BuildClientSupport();

        var udapClient = new UdapClient(
            httpClientMock,
            udapClientDiscoveryValidator,
            udapClientIOptions,
            _serviceProvider.GetRequiredService<ILogger<UdapClient>>());

        Action<X509Certificate2> untrustedListener = _ => { };
        udapClient.Untrusted += untrustedListener;
        udapClient.Untrusted -= untrustedListener;

        Action<ChainElementInfo> problemListener = _ => { };
        udapClient.Problem += problemListener;
        udapClient.Problem -= problemListener;

        Action<X509Certificate2, Exception> errorListener = (_, _) => { };
        udapClient.Error += errorListener;
        udapClient.Error -= errorListener;

        Action<string> tokenErrorListener = _ => { };
        udapClient.TokenError += tokenErrorListener;
        udapClient.TokenError -= tokenErrorListener;
    }

    [Fact]
    public async Task RegisterTieredClient_WithNullMetadata_Throws()
    {
        var (httpClientMock, udapClientDiscoveryValidator, udapClientIOptions, _) = await BuildClientSupport();
        var udapClient = new UdapClient(
            httpClientMock, udapClientDiscoveryValidator, udapClientIOptions,
            _serviceProvider.GetRequiredService<ILogger<UdapClient>>());

        await Assert.ThrowsAsync<Exception>(
            () => udapClient.RegisterTieredClient("https://app.example.com/callback",
                Array.Empty<X509Certificate2>(), "openid"));
    }

    [Fact]
    public async Task RegisterTieredClient_AfterValidation_CallsRegistrationEndpoint()
    {
        var (httpClientMock, udapClientDiscoveryValidator, udapClientIOptions, trustAnchorStore) = await BuildClientSupport();

        var regResponse = new HttpResponseMessage(HttpStatusCode.Created)
        {
            Content = new StringContent("""{"client_id":"new-client"}""",
                System.Text.Encoding.UTF8, "application/json")
        };

        httpClientMock.SendAsync(Arg.Is<HttpRequestMessage>(r => r.Method == HttpMethod.Post), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(regResponse));

        var udapClientOptions = new UdapClientOptions
        {
            ClientName = "Test Client",
            TieredOAuthClientLogo = "https://example.com/logo.png"
        };
        udapClientIOptions.CurrentValue.Returns(udapClientOptions);

        var udapClient = new UdapClient(
            httpClientMock, udapClientDiscoveryValidator, udapClientIOptions,
            _serviceProvider.GetRequiredService<ILogger<UdapClient>>());

        await udapClient.ValidateResource("https://fhirlabs.net/fhir/r4", trustAnchorStore);

        var cert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
        var result = await udapClient.RegisterTieredClient(
            "https://app.example.com/callback",
            new[] { cert }, "openid");

        Assert.NotNull(result);
    }

    [Fact]
    public async Task RegisterAuthCodeClient_AfterValidation_CallsRegistrationEndpoint()
    {
        var (httpClientMock, udapClientDiscoveryValidator, udapClientIOptions, trustAnchorStore) = await BuildClientSupport();

        var regResponse = new HttpResponseMessage(HttpStatusCode.Created)
        {
            Content = new StringContent("""{"client_id":"auth-client"}""",
                System.Text.Encoding.UTF8, "application/json")
        };

        httpClientMock.SendAsync(Arg.Is<HttpRequestMessage>(r => r.Method == HttpMethod.Post), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(regResponse));

        var udapClientOptions = new UdapClientOptions { ClientName = "Test Client" };
        udapClientIOptions.CurrentValue.Returns(udapClientOptions);

        var udapClient = new UdapClient(
            httpClientMock, udapClientDiscoveryValidator, udapClientIOptions,
            _serviceProvider.GetRequiredService<ILogger<UdapClient>>());

        await udapClient.ValidateResource("https://fhirlabs.net/fhir/r4", trustAnchorStore);

        var cert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
        var result = await udapClient.RegisterAuthCodeClient(
            cert, "openid", "https://example.com/logo.png",
            new[] { "https://app.example.com/callback" }, null);

        Assert.NotNull(result);
    }

    [Fact]
    public async Task RegisterClientCredentialsClient_AfterValidation_CallsRegistrationEndpoint()
    {
        var (httpClientMock, udapClientDiscoveryValidator, udapClientIOptions, trustAnchorStore) = await BuildClientSupport();

        var regResponse = new HttpResponseMessage(HttpStatusCode.Created)
        {
            Content = new StringContent("""{"client_id":"cc-client"}""",
                System.Text.Encoding.UTF8, "application/json")
        };

        httpClientMock.SendAsync(Arg.Is<HttpRequestMessage>(r => r.Method == HttpMethod.Post), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(regResponse));

        var udapClientOptions = new UdapClientOptions { ClientName = "Test Client" };
        udapClientIOptions.CurrentValue.Returns(udapClientOptions);

        var udapClient = new UdapClient(
            httpClientMock, udapClientDiscoveryValidator, udapClientIOptions,
            _serviceProvider.GetRequiredService<ILogger<UdapClient>>());

        await udapClient.ValidateResource("https://fhirlabs.net/fhir/r4", trustAnchorStore);

        var cert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
        var result = await udapClient.RegisterClientCredentialsClient(
            cert, "system/*.read", null, null);

        Assert.NotNull(result);
    }

    [Fact]
    public async Task RegisterTieredClient_ErrorResponse_ReturnsDocumentWithError()
    {
        var (httpClientMock, udapClientDiscoveryValidator, udapClientIOptions, trustAnchorStore) = await BuildClientSupport();

        var regResponse = new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new StringContent("""{"error":"invalid_client_metadata","error_description":"bad scope"}""",
                System.Text.Encoding.UTF8, "application/json")
        };

        httpClientMock.SendAsync(Arg.Is<HttpRequestMessage>(r => r.Method == HttpMethod.Post), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(regResponse));

        var udapClientOptions = new UdapClientOptions
        {
            ClientName = "Test Client",
            TieredOAuthClientLogo = "https://example.com/logo.png"
        };
        udapClientIOptions.CurrentValue.Returns(udapClientOptions);

        var udapClient = new UdapClient(
            httpClientMock, udapClientDiscoveryValidator, udapClientIOptions,
            _serviceProvider.GetRequiredService<ILogger<UdapClient>>());

        await udapClient.ValidateResource("https://fhirlabs.net/fhir/r4", trustAnchorStore);

        var cert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
        var result = await udapClient.RegisterTieredClient(
            "https://app.example.com/callback", new[] { cert }, "openid");

        Assert.NotNull(result.GetError());
    }

    [Fact]
    public async Task RegisterTieredClient_PostThrows_CatchesAndRethrows()
    {
        var (httpClientMock, udapClientDiscoveryValidator, udapClientIOptions, trustAnchorStore) = await BuildClientSupport();

        httpClientMock.SendAsync(Arg.Is<HttpRequestMessage>(r => r.Method == HttpMethod.Post), Arg.Any<CancellationToken>())
            .Returns<Task<HttpResponseMessage>>(_ => throw new HttpRequestException("Connection refused"));

        var udapClientOptions = new UdapClientOptions
        {
            ClientName = "Test Client",
            TieredOAuthClientLogo = "https://example.com/logo.png"
        };
        udapClientIOptions.CurrentValue.Returns(udapClientOptions);

        var udapClient = new UdapClient(
            httpClientMock, udapClientDiscoveryValidator, udapClientIOptions,
            _serviceProvider.GetRequiredService<ILogger<UdapClient>>());

        await udapClient.ValidateResource("https://fhirlabs.net/fhir/r4", trustAnchorStore);

        var cert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");

        await Assert.ThrowsAsync<HttpRequestException>(
            () => udapClient.RegisterTieredClient(
                "https://app.example.com/callback", new[] { cert }, "openid"));
    }

    [Fact]
    public async Task RegisterAuthCodeClient_ErrorResponse_ReturnsDocumentWithError()
    {
        var (httpClientMock, udapClientDiscoveryValidator, udapClientIOptions, trustAnchorStore) = await BuildClientSupport();

        var regResponse = new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new StringContent("""{"error":"invalid_client_metadata"}""",
                System.Text.Encoding.UTF8, "application/json")
        };

        httpClientMock.SendAsync(Arg.Is<HttpRequestMessage>(r => r.Method == HttpMethod.Post), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(regResponse));

        var udapClientOptions = new UdapClientOptions { ClientName = "Test Client" };
        udapClientIOptions.CurrentValue.Returns(udapClientOptions);

        var udapClient = new UdapClient(
            httpClientMock, udapClientDiscoveryValidator, udapClientIOptions,
            _serviceProvider.GetRequiredService<ILogger<UdapClient>>());

        await udapClient.ValidateResource("https://fhirlabs.net/fhir/r4", trustAnchorStore);

        var cert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
        var result = await udapClient.RegisterAuthCodeClient(
            cert, "openid", "https://example.com/logo.png",
            new[] { "https://app.example.com/callback" }, null);

        Assert.NotNull(result.GetError());
    }

    [Fact]
    public async Task RegisterAuthCodeClient_PostThrows_CatchesAndRethrows()
    {
        var (httpClientMock, udapClientDiscoveryValidator, udapClientIOptions, trustAnchorStore) = await BuildClientSupport();

        httpClientMock.SendAsync(Arg.Is<HttpRequestMessage>(r => r.Method == HttpMethod.Post), Arg.Any<CancellationToken>())
            .Returns<Task<HttpResponseMessage>>(_ => throw new HttpRequestException("Connection refused"));

        var udapClientOptions = new UdapClientOptions { ClientName = "Test Client" };
        udapClientIOptions.CurrentValue.Returns(udapClientOptions);

        var udapClient = new UdapClient(
            httpClientMock, udapClientDiscoveryValidator, udapClientIOptions,
            _serviceProvider.GetRequiredService<ILogger<UdapClient>>());

        await udapClient.ValidateResource("https://fhirlabs.net/fhir/r4", trustAnchorStore);

        var cert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");

        await Assert.ThrowsAsync<HttpRequestException>(
            () => udapClient.RegisterAuthCodeClient(
                cert, "openid", "https://example.com/logo.png",
                new[] { "https://app.example.com/callback" }, null));
    }

    [Fact]
    public async Task RegisterClientCredentialsClient_ErrorResponse_ReturnsDocumentWithError()
    {
        var (httpClientMock, udapClientDiscoveryValidator, udapClientIOptions, trustAnchorStore) = await BuildClientSupport();

        var regResponse = new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new StringContent("""{"error":"invalid_scope"}""",
                System.Text.Encoding.UTF8, "application/json")
        };

        httpClientMock.SendAsync(Arg.Is<HttpRequestMessage>(r => r.Method == HttpMethod.Post), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(regResponse));

        var udapClientOptions = new UdapClientOptions { ClientName = "Test Client" };
        udapClientIOptions.CurrentValue.Returns(udapClientOptions);

        var udapClient = new UdapClient(
            httpClientMock, udapClientDiscoveryValidator, udapClientIOptions,
            _serviceProvider.GetRequiredService<ILogger<UdapClient>>());

        await udapClient.ValidateResource("https://fhirlabs.net/fhir/r4", trustAnchorStore);

        var cert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
        var result = await udapClient.RegisterClientCredentialsClient(
            cert, "system/*.read", null, null);

        Assert.NotNull(result.GetError());
    }

    [Fact]
    public async Task RegisterClientCredentialsClient_PostThrows_CatchesAndRethrows()
    {
        var (httpClientMock, udapClientDiscoveryValidator, udapClientIOptions, trustAnchorStore) = await BuildClientSupport();

        httpClientMock.SendAsync(Arg.Is<HttpRequestMessage>(r => r.Method == HttpMethod.Post), Arg.Any<CancellationToken>())
            .Returns<Task<HttpResponseMessage>>(_ => throw new HttpRequestException("Connection refused"));

        var udapClientOptions = new UdapClientOptions { ClientName = "Test Client" };
        udapClientIOptions.CurrentValue.Returns(udapClientOptions);

        var udapClient = new UdapClient(
            httpClientMock, udapClientDiscoveryValidator, udapClientIOptions,
            _serviceProvider.GetRequiredService<ILogger<UdapClient>>());

        await udapClient.ValidateResource("https://fhirlabs.net/fhir/r4", trustAnchorStore);

        var cert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");

        await Assert.ThrowsAsync<HttpRequestException>(
            () => udapClient.RegisterClientCredentialsClient(
                cert, "system/*.read", null, null));
    }

    [Fact]
    public async Task ValidateTrustChain_SingleParam_DelegatesToTwoParamOverload()
    {
        var (httpClientMock, udapClientDiscoveryValidator, udapClientIOptions, trustAnchorStore) = await BuildClientSupport();

        var udapClient = new UdapClient(
            httpClientMock, udapClientDiscoveryValidator, udapClientIOptions,
            _serviceProvider.GetRequiredService<ILogger<UdapClient>>());

        var disco = await udapClient.ValidateResource("https://fhirlabs.net/fhir/r4", trustAnchorStore);

        Assert.False(disco.IsError);

        var result = await udapClientDiscoveryValidator.ValidateTrustChain((string?)null);

        Assert.True(result);
    }

    [Fact]
    public async Task ValidateTrustChain_NullPublicCertificate_Throws()
    {
        var validator = new TrustChainValidator(
            _problemFlags, false,
            _serviceProvider.GetRequiredService<ILogger<TrustChainValidator>>());

        var discoveryValidator = new UdapClientDiscoveryValidator(
            validator,
            _serviceProvider.GetRequiredService<ILogger<UdapClientDiscoveryValidator>>());

        await Assert.ThrowsAsync<UnauthorizedAccessException>(
            () => discoveryValidator.ValidateTrustChain(null, null));
    }

    [Fact]
    public async Task ValidateTrustChain_NullStore_ReturnsFalse()
    {
        var (httpClientMock, udapClientDiscoveryValidator, udapClientIOptions, trustAnchorStore) = await BuildClientSupport();

        var udapClient = new UdapClient(
            httpClientMock, udapClientDiscoveryValidator, udapClientIOptions,
            _serviceProvider.GetRequiredService<ILogger<UdapClient>>());

        await udapClient.ValidateResource("https://fhirlabs.net/fhir/r4", trustAnchorStore);

        var result = await udapClientDiscoveryValidator.ValidateTrustChain("non-existent-community", (ITrustAnchorStore?)null);

        Assert.False(result);
    }

    [Fact]
    public async Task ValidateTrustChain_EmptyAnchors_ReturnsFalse()
    {
        var (httpClientMock, udapClientDiscoveryValidator, udapClientIOptions, trustAnchorStore) = await BuildClientSupport();

        var udapClient = new UdapClient(
            httpClientMock, udapClientDiscoveryValidator, udapClientIOptions,
            _serviceProvider.GetRequiredService<ILogger<UdapClient>>());

        await udapClient.ValidateResource("https://fhirlabs.net/fhir/r4", trustAnchorStore);

        var emptyStore = Substitute.For<ITrustAnchorStore>();
        emptyStore.Resolve().Returns(Task.FromResult(emptyStore));
        emptyStore.AnchorCertificates.Returns(new List<Udap.Common.Models.Anchor>());

        var result = await udapClientDiscoveryValidator.ValidateTrustChain(null, emptyStore);

        Assert.False(result);
    }

    [Fact]
    public async Task ValidateTrustChain_ClientSuppliedStore_IsUsed()
    {
        var (httpClientMock, udapClientDiscoveryValidator, udapClientIOptions, trustAnchorStore) = await BuildClientSupport();

        var udapClient = new UdapClient(
            httpClientMock, udapClientDiscoveryValidator, udapClientIOptions,
            _serviceProvider.GetRequiredService<ILogger<UdapClient>>());

        await udapClient.ValidateResource("https://fhirlabs.net/fhir/r4", trustAnchorStore);

        var result = await udapClientDiscoveryValidator.ValidateTrustChain(null, trustAnchorStore);

        Assert.True(result);
    }

    [Fact]
    public async Task ValidateJwtToken_MissingSignedMetadata_ReturnsFalse()
    {
        var validator = new TrustChainValidator(
            _problemFlags, false,
            _serviceProvider.GetRequiredService<ILogger<TrustChainValidator>>());

        var discoveryValidator = new UdapClientDiscoveryValidator(
            validator,
            _serviceProvider.GetRequiredService<ILogger<UdapClientDiscoveryValidator>>());

        string? capturedError = null;
        discoveryValidator.TokenError += msg => capturedError = msg;

        var metadata = new UdapMetadata { SignedMetadata = null };

        await Assert.ThrowsAnyAsync<Exception>(
            () => discoveryValidator.ValidateJwtToken(metadata, "https://fhirlabs.net/fhir/r4"));
    }

    [Fact]
    public async Task ValidateJwtToken_NoX5cHeader_ReturnsFalse()
    {
        var validator = new TrustChainValidator(
            _problemFlags, false,
            _serviceProvider.GetRequiredService<ILogger<TrustChainValidator>>());

        var discoveryValidator = new UdapClientDiscoveryValidator(
            validator,
            _serviceProvider.GetRequiredService<ILogger<UdapClientDiscoveryValidator>>());

        string? capturedError = null;
        discoveryValidator.TokenError += msg => capturedError = msg;

        var handler = new JsonWebTokenHandler();
        var jwtWithoutX5c = handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "https://fhirlabs.net/fhir/r4",
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(new byte[32]), SecurityAlgorithms.HmacSha256)
        });

        var metadata = new UdapMetadata { SignedMetadata = jwtWithoutX5c };

        var result = await discoveryValidator.ValidateJwtToken(metadata, "https://fhirlabs.net/fhir/r4");

        Assert.False(result);
        Assert.NotNull(capturedError);
        Assert.Contains("x5c", capturedError);
    }

    [Fact]
    public async Task ValidateJwtToken_InvalidSignature_ReturnsFalse()
    {
        var (_, udapClientDiscoveryValidator, _, trustAnchorStore) = await BuildClientSupport();

        string? capturedError = null;
        udapClientDiscoveryValidator.TokenError += msg => capturedError = msg;

        var cert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
        using var rsa = cert.GetRSAPrivateKey()!;

        var handler = new JsonWebTokenHandler();
        var jwt = handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "https://fhirlabs.net/fhir/r4",
            Claims = new Dictionary<string, object> { ["sub"] = "https://fhirlabs.net/fhir/r4" },
            SigningCredentials = new SigningCredentials(
                new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256)
            {
                CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
            },
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["x5c"] = new[] { Convert.ToBase64String(cert.RawData) }
            }
        });

        var tamperedJwt = jwt.Substring(0, jwt.LastIndexOf('.')) + ".invalidsignature";

        var metadata = new UdapMetadata { SignedMetadata = tamperedJwt };

        var result = await udapClientDiscoveryValidator.ValidateJwtToken(metadata, "https://fhirlabs.net/fhir/r4");

        Assert.False(result);
        Assert.NotNull(capturedError);
    }

    [Fact]
    public async Task ValidateJwtToken_AlgorithmMismatch_ReturnsFalse()
    {
        var (httpClientMock, udapClientDiscoveryValidator, udapClientIOptions, trustAnchorStore) = await BuildClientSupport();

        var udapClient = new UdapClient(
            httpClientMock, udapClientDiscoveryValidator, udapClientIOptions,
            _serviceProvider.GetRequiredService<ILogger<UdapClient>>());

        var disco = await udapClient.ValidateResource("https://fhirlabs.net/fhir/r4", trustAnchorStore);
        Assert.False(disco.IsError);

        var metadata = udapClient.UdapServerMetadata!;
        metadata.RegistrationEndpointJwtSigningAlgValuesSupported = new List<string> { "ES384" };
        metadata.TokenEndpointAuthSigningAlgValuesSupported = new List<string> { "ES384" };

        string? capturedError = null;
        udapClientDiscoveryValidator.TokenError += msg => capturedError = msg;

        var result = await udapClientDiscoveryValidator.ValidateJwtToken(metadata, "https://fhirlabs.net/fhir/r4");

        Assert.False(result);
        Assert.NotNull(capturedError);
        Assert.Contains("does not match", capturedError);
    }

    [Fact]
    public async Task RemoveCachedIntermediateAsync_WithCache_DelegatesToCache()
    {
        var (httpClientMock, udapClientDiscoveryValidator, udapClientIOptions, _) = await BuildClientSupport();

        var cache = Substitute.For<ICertificateDownloadCache>();
        var udapClient = new UdapClient(
            httpClientMock,
            udapClientDiscoveryValidator,
            udapClientIOptions,
            _serviceProvider.GetRequiredService<ILogger<UdapClient>>(),
            certificateDownloadCache: cache);

        await udapClient.RemoveCachedIntermediateAsync("https://example.com/intermediate.cer");

        await cache.Received(1).RemoveIntermediateAsync("https://example.com/intermediate.cer", Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RemoveCachedCrlAsync_WithCache_DelegatesToCache()
    {
        var (httpClientMock, udapClientDiscoveryValidator, udapClientIOptions, _) = await BuildClientSupport();

        var cache = Substitute.For<ICertificateDownloadCache>();
        var udapClient = new UdapClient(
            httpClientMock,
            udapClientDiscoveryValidator,
            udapClientIOptions,
            _serviceProvider.GetRequiredService<ILogger<UdapClient>>(),
            certificateDownloadCache: cache);

        await udapClient.RemoveCachedCrlAsync("https://example.com/crl.crl");

        await cache.Received(1).RemoveCrlAsync("https://example.com/crl.crl", Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RemoveCachedIntermediateAsync_WithoutCache_ThrowsInvalidOperationException()
    {
        var (httpClientMock, udapClientDiscoveryValidator, udapClientIOptions, _) = await BuildClientSupport();

        var udapClient = new UdapClient(
            httpClientMock,
            udapClientDiscoveryValidator,
            udapClientIOptions,
            _serviceProvider.GetRequiredService<ILogger<UdapClient>>());

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => udapClient.RemoveCachedIntermediateAsync("https://example.com/intermediate.cer"));

        Assert.Contains(nameof(ICertificateDownloadCache), ex.Message);
    }

    [Fact]
    public async Task RemoveCachedCrlAsync_WithoutCache_ThrowsInvalidOperationException()
    {
        var (httpClientMock, udapClientDiscoveryValidator, udapClientIOptions, _) = await BuildClientSupport();

        var udapClient = new UdapClient(
            httpClientMock,
            udapClientDiscoveryValidator,
            udapClientIOptions,
            _serviceProvider.GetRequiredService<ILogger<UdapClient>>());

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => udapClient.RemoveCachedCrlAsync("https://example.com/crl.crl"));

        Assert.Contains(nameof(ICertificateDownloadCache), ex.Message);
    }
}
