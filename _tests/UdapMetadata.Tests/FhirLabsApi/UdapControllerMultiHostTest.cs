#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using Duende.IdentityModel;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using Udap.Client;
using Udap.Client.Configuration;
using Udap.Common;
using Udap.Common.Certificates;
using Udap.Support.Tests.Client;
using Xunit.Abstractions;

namespace UdapMetadata.Tests.FhirLabsApi;

public class UdapControllerMultiHostTest : IClassFixture<ApiForCommunityTestFixture>
{
    private readonly ApiForCommunityTestFixture _fixture;
    private readonly ITestOutputHelper _testOutputHelper;
    private readonly IServiceProvider _serviceProvider;
    private readonly FakeValidatorDiagnostics _diagnosticsValidator = new FakeValidatorDiagnostics();

    private static readonly string[] DomainSegments =
        { "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten" };

    public UdapControllerMultiHostTest(ApiForCommunityTestFixture fixture, ITestOutputHelper testOutputHelper)
    {
        ArgumentNullException.ThrowIfNull(fixture);
        fixture.Output = testOutputHelper;
        _fixture = fixture;
        _testOutputHelper = testOutputHelper;

        var configuration = new ConfigurationBuilder()
            .AddJsonFile("appsettings.FhirLabsApi.json", false, true)
            .Build();

        var services = new ServiceCollection();

        services.AddLogging(logging =>
        {
            logging.ClearProviders();
            logging.AddXUnit(testOutputHelper);
        });

        services.Configure<UdapFileCertStoreManifest>(configuration.GetSection(Constants.UdapFileCertStoreManifestSectionName));
        services.AddSingleton<ITrustAnchorStore>(sp =>
            new TrustAnchorFileStore(
                sp.GetRequiredService<IOptionsMonitor<UdapFileCertStoreManifest>>(),
                Substitute.For<ILogger<TrustAnchorFileStore>>()));

        var problemFlags = ChainProblemStatus.NotTimeValid |
                           ChainProblemStatus.Revoked |
                           ChainProblemStatus.NotSignatureValid |
                           ChainProblemStatus.InvalidBasicConstraints |
                           ChainProblemStatus.UntrustedRoot;

        services.TryAddScoped(_ =>
            new TrustChainValidator(
                problemFlags,
                false,
                _testOutputHelper.ToLogger<TrustChainValidator>()));

        services.AddSingleton<UdapClientDiscoveryValidator>();

        services.AddScoped<IUdapClient>(sp =>
            new UdapClient(_fixture.CreateClient(),
                sp.GetRequiredService<UdapClientDiscoveryValidator>(),
                sp.GetRequiredService<IOptionsMonitor<UdapClientOptions>>(),
                sp.GetRequiredService<ILogger<UdapClient>>()));

        _serviceProvider = services.BuildServiceProvider();
    }

    [Fact]
    public async Task ValidateAllMultiHostDomainsTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();
        udapClient.Problem += _diagnosticsValidator.OnChainProblem;
        udapClient.Untrusted += _diagnosticsValidator.OnUnTrusted;
        udapClient.TokenError += _diagnosticsValidator.OnTokenError;

        var signedMetadataResults = new HashSet<string>();

        foreach (var segment in DomainSegments)
        {
            var baseUrl = $"https://localhost:7016/{segment}/fhir/r4";

            var disco = await udapClient.ValidateResource(baseUrl, "udap://multihost/");

            Assert.False(disco.IsError,
                $"Segment '{segment}': {disco.Error} | {disco.ErrorType} | {string.Join("; ", _diagnosticsValidator.ActualErrorMessages)}");
            Assert.NotNull(udapClient.UdapServerMetadata);
            Assert.False(_diagnosticsValidator.ProblemCalled,
                $"Segment '{segment}': chain problem: {string.Join("; ", _diagnosticsValidator.ActualErrorMessages)}");
            Assert.False(_diagnosticsValidator.UntrustedCalled,
                $"Segment '{segment}': untrusted: {_diagnosticsValidator.UnTrustedCertificate}");
            Assert.False(_diagnosticsValidator.TokenErrorCalled,
                $"Segment '{segment}': token error: {string.Join("; ", _diagnosticsValidator.ActualErrorMessages)}");

            // Verify issuer matches the requested base URL
            var jwt = new JwtSecurityToken(disco.SignedMetadata);
            var issClaim = jwt.Payload.Claims.Single(c => c.Type == JwtClaimTypes.Issuer);
            Assert.Equal(baseUrl, issClaim.Value);

            // Verify subject matches issuer
            var subClaim = jwt.Payload.Claims.Single(c => c.Type == JwtClaimTypes.Subject);
            Assert.Equal(issClaim.Value, subClaim.Value);

            // Verify signing cert SAN matches the base URL
            var x5cArray = jwt.Header["x5c"] as List<object>;
#if NET9_0_OR_GREATER
            var cert = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(x5cArray!.First().ToString()!));
#else
            var cert = new X509Certificate2(Convert.FromBase64String(x5cArray!.First().ToString()!));
#endif
            var subjectAltName = cert.GetNameInfo(X509NameType.UrlName, false);
            Assert.Equal(baseUrl, subjectAltName);

            // Collect signed_metadata to verify they're all different
            signedMetadataResults.Add(disco.SignedMetadata!);

            _testOutputHelper.WriteLine($"Validated: {baseUrl} -> iss={issClaim.Value}, SAN={subjectAltName}");
        }

        // All 10 should have different signed metadata (different certs, different signatures)
        Assert.Equal(DomainSegments.Length, signedMetadataResults.Count);
    }

    [Fact]
    public async Task UnknownDomainReturns404Test()
    {
        var client = _fixture.CreateClient();

        var response = await client.GetAsync(
            "https://localhost:7016/eleven/fhir/r4/.well-known/udap?community=udap://multihost/");

        Assert.Equal(System.Net.HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task DynamicRoute_CommunitiesEndpointTest()
    {
        var client = _fixture.CreateClient();

        var response = await client.GetAsync(
            "https://localhost:7016/one/fhir/r4/.well-known/udap/communities");

        Assert.Equal(System.Net.HttpStatusCode.OK, response.StatusCode);
        var communities = await response.Content.ReadFromJsonAsync<List<string>>();
        Assert.NotNull(communities);
        Assert.Contains("udap://multihost/", communities);
    }

    [Fact]
    public async Task DynamicRoute_CommunitiesAsHtmlEndpointTest()
    {
        var client = _fixture.CreateClient();

        var response = await client.GetAsync(
            "https://localhost:7016/five/fhir/r4/.well-known/udap/communities/ashtml");

        Assert.Equal(System.Net.HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);
        var html = await response.Content.ReadAsStringAsync();
        Assert.Contains("udap://multihost/", html);
    }

    [Fact]
    public async Task DynamicRoute_OptionsRetursCorsHeadersTest()
    {
        var client = _fixture.CreateClient();

        var request = new HttpRequestMessage(HttpMethod.Options,
            "https://localhost:7016/two/fhir/r4/.well-known/udap");
        var response = await client.SendAsync(request);

        Assert.Equal(System.Net.HttpStatusCode.NoContent, response.StatusCode);
        response.Headers.TryGetValues("Access-Control-Allow-Origin", out var origin);
        Assert.Contains("*", origin);
        response.Headers.TryGetValues("Access-Control-Allow-Methods", out var methods);
        Assert.Contains("GET, OPTIONS", methods);
    }

    [Fact]
    public async Task DynamicRoute_OptionsCommunitiesTest()
    {
        var client = _fixture.CreateClient();

        var request = new HttpRequestMessage(HttpMethod.Options,
            "https://localhost:7016/three/fhir/r4/.well-known/udap/communities");
        var response = await client.SendAsync(request);

        Assert.Equal(System.Net.HttpStatusCode.NoContent, response.StatusCode);
        response.Headers.TryGetValues("Access-Control-Allow-Origin", out var origin);
        Assert.Contains("*", origin);
    }

    [Fact]
    public async Task DynamicRoute_OptionsCommunitiesAsHtmlTest()
    {
        var client = _fixture.CreateClient();

        var request = new HttpRequestMessage(HttpMethod.Options,
            "https://localhost:7016/four/fhir/r4/.well-known/udap/communities/ashtml");
        var response = await client.SendAsync(request);

        Assert.Equal(System.Net.HttpStatusCode.NoContent, response.StatusCode);
        response.Headers.TryGetValues("Access-Control-Allow-Origin", out var origin);
        Assert.Contains("*", origin);
    }

    [Fact]
    public async Task UnknownCommunityReturns404Test()
    {
        var client = _fixture.CreateClient();

        var response = await client.GetAsync(
            "https://localhost:7016/one/fhir/r4/.well-known/udap?community=udap://nonexistent/");

        Assert.Equal(System.Net.HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task DynamicRoute_UnsupportedMethodPassesThroughTest()
    {
        var client = _fixture.CreateClient();

        var response = await client.PostAsync(
            "https://localhost:7016/one/fhir/r4/.well-known/udap", null);

        // POST is not handled by the middleware — passes through to next middleware
        Assert.NotEqual(System.Net.HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task DynamicRoute_UnsupportedMethodOnCommunitiesPassesThroughTest()
    {
        var client = _fixture.CreateClient();

        var response = await client.PostAsync(
            "https://localhost:7016/one/fhir/r4/.well-known/udap/communities", null);

        Assert.NotEqual(System.Net.HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task DynamicRoute_UnsupportedMethodOnCommunitiesAsHtmlPassesThroughTest()
    {
        var client = _fixture.CreateClient();

        var response = await client.PostAsync(
            "https://localhost:7016/one/fhir/r4/.well-known/udap/communities/ashtml", null);

        Assert.NotEqual(System.Net.HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task DynamicRoute_NonUdapPathPassesThroughTest()
    {
        var client = _fixture.CreateClient();

        var response = await client.GetAsync("https://localhost:7016/some/other/path");

        // Should not be handled by the UDAP middleware - passes through to next middleware
        Assert.NotEqual(System.Net.HttpStatusCode.OK, response.StatusCode);
    }
}
