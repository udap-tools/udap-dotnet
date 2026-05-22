#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Duende.IdentityModel;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using Udap.Client;
using Udap.Client.Configuration;
using Udap.Common;
using Udap.Common.Certificates;
using Udap.Common.Models;
using Udap.Support.Tests.Client;
using Xunit.Abstractions;
using static UdapMetadata.Tests.FhirLabsApi.UdapControllerCommunityTest;
using fhirLabsProgram = FhirLabsApi.Program;
#pragma warning disable xUnit1004


namespace UdapMetadata.Tests.FhirLabsApi;

public class ApiForCommunityTestFixture : WebApplicationFactory<fhirLabsProgram>
{
    public ITestOutputHelper? Output { get; set; }
    public string Community = "http://localhost";
    
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


public class UdapControllerCommunityTest : IClassFixture<ApiForCommunityTestFixture>
{
    private readonly ApiForCommunityTestFixture _fixture;
    private readonly ITestOutputHelper _testOutputHelper;
    private readonly IServiceProvider _serviceProvider;
    private readonly FakeValidatorDiagnostics _diagnosticsValidator = new FakeValidatorDiagnostics();

    public UdapControllerCommunityTest(ApiForCommunityTestFixture fixture, ITestOutputHelper testOutputHelper)
    {
        ArgumentNullException.ThrowIfNull(fixture);
        fixture.Output = testOutputHelper;
        _fixture = fixture;
        _testOutputHelper = testOutputHelper;


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
                           ChainProblemStatus.InvalidBasicConstraints |
                           ChainProblemStatus.UntrustedRoot;
                           // ChainProblemStatus.OfflineRevocation;


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

        //
        // Use this method in an application
        //
        //services.AddHttpClient<IUdapClient, UdapClient>();

        _serviceProvider = services.BuildServiceProvider();
    }

    [Fact]
    public async Task GetCommunitiesTest()
    {
        var client = _fixture.CreateClient();
        var response = await client.GetAsync("fhir/r4/.well-known/udap/communities");
        response.EnsureSuccessStatusCode();
        var communities = await response.Content.ReadFromJsonAsync<List<string>>();
        Assert.Equal(8, communities!.Count);
        Assert.Contains("udap://fhirlabs1/", communities);
        Assert.Contains("udap://Provider2", communities);

        response = await client.GetAsync("fhir/r4/.well-known/udap/communities/ashtml");
        response.EnsureSuccessStatusCode();
        var communityHtml = await response.Content.ReadAsStringAsync();
        Assert.False(string.IsNullOrWhiteSpace(communityHtml));
        Assert.Contains("href=\"http://localhost/fhir/r4/.well-known/udap?community=udap://fhirlabs1/\"", communityHtml);
        Assert.Contains("href=\"http://localhost/fhir/r4/.well-known/udap?community=udap://Provider2\"", communityHtml);
    }


    [Fact]
    public async Task ValidateChainTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();
        udapClient.Problem += _diagnosticsValidator.OnChainProblem;

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4",
            "udap://Provider2");

        Assert.False(disco.IsError, $"\nError: {disco.Error} \nError Type: {disco.ErrorType}\n{disco.Raw}");
        Assert.NotNull(udapClient.UdapServerMetadata);
        Assert.False(_diagnosticsValidator.ProblemCalled);

        disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4",
            "udap://Provider2");

        Assert.False(disco.IsError, $"\nError: {disco.Error} \nError Type: {disco.ErrorType}\n{disco.Raw}");
        Assert.NotNull(udapClient.UdapServerMetadata);
        Assert.False(_diagnosticsValidator.ProblemCalled);
    }

    [Fact]
    public async Task ValidateChainWithCommunityInUrlTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();
        udapClient.Problem += _diagnosticsValidator.OnChainProblem;

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4/.well-known/udap?community=udap://Provider2");

        Assert.False(disco.IsError, $"\nError: {disco.Error} \nError Type: {disco.ErrorType}\n{disco.Raw}");
        Assert.NotNull(udapClient.UdapServerMetadata);
        Assert.False(_diagnosticsValidator.ProblemCalled);

        disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4",
            "udap://Provider2");

        Assert.False(disco.IsError, $"\nError: {disco.Error} \nError Type: {disco.ErrorType}\n{disco.Raw}");
        Assert.NotNull(udapClient.UdapServerMetadata);
        Assert.False(_diagnosticsValidator.ProblemCalled);
    }

    [Fact]
    public async Task ValidateChainEcdsaTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();
        udapClient.Problem += _diagnosticsValidator.OnChainProblem;

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4",
            "udap://ECDSA/");

        Assert.False(disco.IsError, $"\nError: {disco.Error} \nError Type: {disco.ErrorType}\n{disco.Raw}");
        Assert.NotNull(udapClient.UdapServerMetadata);
        Assert.False(_diagnosticsValidator.ProblemCalled);

        var disco2 = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4",
            "udap://ECDSA/");

        Assert.NotEqual(disco.Raw, disco2.Raw);

        Assert.False(disco2.IsError, $"\nError: {disco2.Error} \nError Type: {disco2.ErrorType}\n{disco2.Raw}");
        Assert.NotNull(udapClient.UdapServerMetadata);
        Assert.False(_diagnosticsValidator.ProblemCalled);
    }


    [Fact]
    public async Task InvalidJwtTokentBadIssMatchToSubjectAltNameTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();
        udapClient.Problem += _diagnosticsValidator.OnChainProblem;
        udapClient.TokenError += _diagnosticsValidator.OnTokenError;
        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4",
            "udap://IssMismatchToSubjAltName/");

        Assert.True(disco.IsError, disco.Raw);
        Assert.NotNull(udapClient.UdapServerMetadata);
        Assert.True(_diagnosticsValidator.TokenErrorCalled);
        Assert.Contains(_diagnosticsValidator.ActualErrorMessages, m => m.Contains("Failed JWT Validation"));
        // http://localhost/fhir/r99 is the subject alt used to sign software statement
        Assert.Contains(_diagnosticsValidator.ActualErrorMessages, m => m.Contains("http://localhost/fhir/r99"));
    }

    [Fact]
    public async Task InvalidJwtTokentBadIssMatchToBaseUrlTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();
        udapClient.Problem += _diagnosticsValidator.OnChainProblem;
        udapClient.TokenError += _diagnosticsValidator.OnTokenError;
        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4",
            "udap://IssMismatchToBaseUrl/");

        Assert.True(disco.IsError, disco.Raw);
        Assert.NotNull(udapClient.UdapServerMetadata);
        Assert.True(_diagnosticsValidator.TokenErrorCalled);
        Assert.Contains(_diagnosticsValidator.ActualErrorMessages, m => m.Contains("JWT iss does not match baseUrl."));
    }


    [Fact]
    public async Task MissingCommunityChainTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();
        udapClient.Problem += _diagnosticsValidator.OnChainProblem;

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4",
            "udap://weatherapi/"); // The udap://weatherapi/ community is not supported by the FhirLabsApi web server. 

        Assert.True(disco.IsError, disco.Raw);
        Assert.Null(udapClient.UdapServerMetadata);
        Assert.False(_diagnosticsValidator.ProblemCalled);
    }

    [Fact]
    public async Task UntrustedChainTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();
        udapClient.Problem += _diagnosticsValidator.OnChainProblem;
        udapClient.Error += _diagnosticsValidator.OnError;
        udapClient.Untrusted += _diagnosticsValidator.OnUnTrusted;

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4",
            "udap://Untrusted/"); // the client community picked from the UdapMetadata.Tests appsettings.json is different from the FhirLabsApi server community

        Assert.True(disco.IsError, disco.Raw);
        Assert.NotNull(udapClient.UdapServerMetadata);
        Assert.True(_diagnosticsValidator.UntrustedCalled);
        Assert.Equal("CN=localhost3, OU=fhirlabs.net, O=Fhir Coding, L=Portland, S=Oregon, C=US", _diagnosticsValidator.UnTrustedCertificate);
        Assert.False(_diagnosticsValidator.ProblemCalled);
        Assert.False(_diagnosticsValidator.ErrorCalled);
    }


    /// <summary>
    /// Special test to check <see cref="TrustChainValidator"/> notification events.
    /// In this case assert a IUdapClient can register for the Problem events.
    /// </summary>
    /// <returns></returns>
    [Fact]
    public async Task ValidateChainOffLineRevocationTest2()
    {
        //
        // This are is for client Dependency injection and Configuration
        //<TrustChainValidator>
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
            logging.AddXUnit(_testOutputHelper);
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
                       ChainProblemStatus.InvalidBasicConstraints |
                       ChainProblemStatus.OfflineRevocation |
                       ChainProblemStatus.PartialChain |
                       ChainProblemStatus.UntrustedRoot;


        services.TryAddScoped(_ =>
            new TrustChainValidator(
                problemFlags,
                true, // enable revocation checking - expect offline/CRL failure
                _testOutputHelper.ToLogger<TrustChainValidator>()));
        services.AddSingleton<UdapClientDiscoveryValidator>();

        services.AddScoped<IUdapClient>(sp =>
            new UdapClient(_fixture.CreateClient(),
                sp.GetRequiredService<UdapClientDiscoveryValidator>(),
                sp.GetRequiredService<IOptionsMonitor<UdapClientOptions>>(),
                sp.GetRequiredService<ILogger<UdapClient>>()));

        var serviceProvider = services.BuildServiceProvider();

        var udapClient = serviceProvider.GetRequiredService<IUdapClient>();
        udapClient.Problem += _diagnosticsValidator.OnChainProblem;

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4",
            "udap://Provider2");

        Assert.True(disco.IsError, $"\nError: {disco.Error} \nError Type: {disco.ErrorType}\n{disco.Raw}");
        Assert.NotNull(udapClient.UdapServerMetadata);

        Assert.Contains(_diagnosticsValidator.ActualErrorMessages, m =>
                m.Contains("OfflineRevocation") || m.Contains("CrlNotFound") || m.Contains("CrlFetchFailed"));
    }


    [Fact(Skip = "Swagger friction with net7 and non default pathBase.  Save for another day.  Maybe put behind Yarp and/or follow through on this PR: https://github.com/brianpos/fhir-net-web-api/pull/13")] //Swagger
    public async Task OpenApiTest()
    {
        var response = await _fixture.CreateClient().GetAsync($"fhir/r4/Swagger/Index.html");

        System.Diagnostics.Trace.WriteLine(response.ToString());

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var contentType = response.Content.Headers.ContentType;
        Assert.NotNull(contentType);
        Assert.Equal("text/html", contentType!.MediaType);

        var result = await response.Content.ReadAsStringAsync();
        Assert.Contains("./swagger-ui.css", result);

        //
        // TODO
        // This last part doesn't actually catch failures.  I would need to render the html
        // some how to finish the test.
        // To make this fail just change one of the helper methods in udapController from
        // private to public.


        Assert.DoesNotContain("Failed to load API definition", result);
    }

    [Fact]
    public async Task signed_metatdataContentTest()
    {

        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();
        udapClient.Problem += _diagnosticsValidator.OnChainProblem;

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4",
            "udap://Provider2");

        Assert.False(disco.IsError, $"\nError: {disco.Error} \nError Type: {disco.ErrorType}\n{disco.Raw}");
        Assert.NotNull(udapClient.UdapServerMetadata);
        Assert.False(_diagnosticsValidator.ProblemCalled);

        //
        // this should all happen in udapClient.ValidateResource()
        //
        var jwt = new JwtSecurityToken(disco.SignedMetadata);

        var issClaim = jwt.Payload.Claims.Single(c => c.Type == JwtClaimTypes.Issuer);
        Assert.Equal(ClaimValueTypes.String, issClaim.ValueType);

        // should be the same as the web base url, but this would be localhost
        Assert.Equal("http://localhost/fhir/r4", issClaim.Value);

        var tokenHeader = jwt.Header;
        var x5CArray = tokenHeader["x5c"] as List<object>;
#if NET9_0_OR_GREATER
        var cert = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(x5CArray!.First().ToString()!));
#else
        var cert = new X509Certificate2(Convert.FromBase64String(x5CArray!.First().ToString()!));
#endif
        var subjectAltName = cert.GetNameInfo(X509NameType.UrlName, false);
        Assert.Equal(issClaim.Value, subjectAltName);

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

public class UdapControllerCommunityCertificateResolverTests : IClassFixture<ApiForCommunityTestFixture>
{
    private readonly ApiForCommunityTestFixture _fixture;
    private readonly ITestOutputHelper _testOutputHelper;
    private readonly FakeValidatorDiagnostics _diagnosticsValidator = new FakeValidatorDiagnostics();

    public UdapControllerCommunityCertificateResolverTests(ApiForCommunityTestFixture fixture,
        ITestOutputHelper testOutputHelper)
    {
        ArgumentNullException.ThrowIfNull(fixture);
        fixture.Output = testOutputHelper;
        _fixture = fixture;
        _testOutputHelper = testOutputHelper;


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
    }




    [Fact]
public async Task ValidateChainWithMyAnchorAndIntermediateTest()
{

    //
    // This are is for client Dependency injection and Configuration
    //<TrustChainValidator>
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
        logging.AddXUnit(_testOutputHelper);
    });

    // UDAP CertStore
    services.Configure<UdapFileCertStoreManifest>(configuration.GetSection(Constants.UdapFileCertStoreManifestSectionName));
    services.AddSingleton<ITrustAnchorStore>(sp =>
        new TrustAnchorMemoryStore()
        {
            AnchorCertificates = new HashSet<Anchor>
            {
#if NET9_0_OR_GREATER
                new Anchor(X509CertificateLoader.LoadCertificateFromFile("./CertStore/anchors/caLocalhostCert2.cer"))
#else
                new Anchor(new X509Certificate2("./CertStore/anchors/caLocalhostCert2.cer"))
#endif
                {
                    //TODO:  Implement a ICertificateResolver, injected into TrustChainValidator to follow AIA extensions, resolving intermediate certificates
                    Intermediates =
                    [
#if NET9_0_OR_GREATER
                        new Intermediate(X509CertificateLoader.LoadCertificateFromFile("./CertStore/intermediates/intermediateLocalhostCert2.cer"))
#else
                        new Intermediate(new X509Certificate2("./CertStore/intermediates/intermediateLocalhostCert2.cer"))
#endif
                    ]
                }
            }
        });

    var problemFlags = ChainProblemStatus.NotTimeValid |
                       ChainProblemStatus.Revoked |
                       ChainProblemStatus.NotSignatureValid |
                       ChainProblemStatus.InvalidBasicConstraints |
                       ChainProblemStatus.UntrustedRoot;
                    // ChainProblemStatus.OfflineRevocation;


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

    var serviceProvider = services.BuildServiceProvider();

    var udapClient = serviceProvider.GetRequiredService<IUdapClient>();
    udapClient.Problem += _diagnosticsValidator.OnChainProblem;

    var disco = await udapClient.ValidateResource(
        _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4",
        "udap://Provider2");

    Assert.False(disco.IsError, $"\nError: {disco.Error} \nError Type: {disco.ErrorType}\n{disco.Raw}");
    Assert.NotNull(udapClient.UdapServerMetadata);
    Assert.False(_diagnosticsValidator.ProblemCalled);
}

[Fact]
public async Task ValidateChainWithMyAnchorTest()
{
        //
        // This is for client Dependency injection and Configuration
        //<TrustChainValidator>
        var configuration = new ConfigurationBuilder().Build();

        //
        // Important to test UdapClient with DI because we want to take advantage of DotNet DI and the HttpClientFactory
        //
        var services = new ServiceCollection();

        services.AddLogging(logging =>
        {
            logging.ClearProviders();
            logging.AddXUnit(_testOutputHelper);
        });

        // UDAP CertStore
        services.Configure<UdapFileCertStoreManifest>(configuration.GetSection(Constants.UdapFileCertStoreManifestSectionName));
        services.AddSingleton<ITrustAnchorStore>(sp =>
            new TrustAnchorMemoryStore()
            {
                AnchorCertificates = new HashSet<Anchor>
                {
#if NET9_0_OR_GREATER
                    new Anchor(X509CertificateLoader.LoadCertificateFromFile("./CertStore/anchors/caLocalhostCert2.cer"))
#else
                    new Anchor(new X509Certificate2("./CertStore/anchors/caLocalhostCert2.cer"))
#endif
                    // No intermediate and no way to load it because this test cert has no AIA extension to follow.
                    // ************* DRAGONS ***********************
                    // Watch out for the intermediate getting cached now that I have Udap.Certificate.Server running for integration work.
                    // The integration also allows the intermediate* certs to be loaded into your personal intermediate store in Windows
                    // ************* DRAGONS ***********************
                }
            });

        var problemFlags = ChainProblemStatus.NotTimeValid |
                           ChainProblemStatus.Revoked |
                           ChainProblemStatus.NotSignatureValid |
                           ChainProblemStatus.InvalidBasicConstraints |
                           ChainProblemStatus.OfflineRevocation |
                           ChainProblemStatus.PartialChain |
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

        var serviceProvider = services.BuildServiceProvider();

        var udapClient = serviceProvider.GetRequiredService<IUdapClient>();
    udapClient.Untrusted += _diagnosticsValidator.OnUnTrusted;

    var disco = await udapClient.ValidateResource(
        _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4",
        "udap://Provider2");

    Assert.True(disco.IsError, disco.Raw);
    Assert.NotNull(udapClient.UdapServerMetadata);
    Assert.True(_diagnosticsValidator.UntrustedCalled);
}

/// <summary>
/// Notice the community and TrustAnchorMemoryStore are different
/// </summary>
/// <returns></returns>
[Fact]
public async Task ValidateChainWithMyAnchorAndIntermediateFailTest()
{
        //
        // This are is for client Dependency injection and Configuration
        //<TrustChainValidator>
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
            logging.AddXUnit(_testOutputHelper);
        });

        // UDAP CertStore
        services.Configure<UdapFileCertStoreManifest>(configuration.GetSection(Constants.UdapFileCertStoreManifestSectionName));
        services.AddSingleton<ITrustAnchorStore>(sp =>
            new TrustAnchorMemoryStore()
            {
                AnchorCertificates = new HashSet<Anchor>
                {
#if NET9_0_OR_GREATER
                    new Anchor(X509CertificateLoader.LoadCertificateFromFile("./CertStore/anchors/caLocalhostCert.cer"), "udap://Provider2")
                    {
                        Intermediates =
                        [
                            new Intermediate(X509CertificateLoader.LoadCertificateFromFile("./CertStore/intermediates/intermediateLocalhostCert.cer"))
                        ]
                    }
#else
                    new Anchor(new X509Certificate2("./CertStore/anchors/caLocalhostCert.cer"), "udap://Provider2")
                    {
                        Intermediates =
                        [
                            new Intermediate(new X509Certificate2("./CertStore/intermediates/intermediateLocalhostCert.cer"))
                        ]
                    }
#endif
                }
            });

        var problemFlags = ChainProblemStatus.NotTimeValid |
                           ChainProblemStatus.Revoked |
                           ChainProblemStatus.NotSignatureValid |
                           ChainProblemStatus.InvalidBasicConstraints |
                           ChainProblemStatus.UntrustedRoot;
                        // ChainProblemStatus.OfflineRevocation;


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

        var serviceProvider = services.BuildServiceProvider();

        var udapClient = serviceProvider.GetRequiredService<IUdapClient>();
    udapClient.Problem += _diagnosticsValidator.OnChainProblem;
    udapClient.Untrusted += _diagnosticsValidator.OnUnTrusted;

    var disco = await udapClient.ValidateResource(
        _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4",
        "udap://Provider2");

    Assert.True(disco.IsError, disco.Raw);
    Assert.NotNull(udapClient.UdapServerMetadata);
    Assert.False(_diagnosticsValidator.ProblemCalled);
    Assert.True(_diagnosticsValidator.UntrustedCalled);
    Assert.Equal("CN=IdProvider2, OU=fhirlabs.net, O=Fhir Coding, L=Portland, S=Oregon, C=US", _diagnosticsValidator.UnTrustedCertificate);
}

/// <summary>
/// Notice the community and TrustAnchorMemoryStore are different
/// </summary>
/// <returns></returns>
[Fact]
public async Task ValidateChainWithMyAnchorFailTest()
{
        //
        // This are is for client Dependency injection and Configuration
        //<TrustChainValidator>
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
            logging.AddXUnit(_testOutputHelper);
        });

        // UDAP CertStore
        services.Configure<UdapFileCertStoreManifest>(configuration.GetSection(Constants.UdapFileCertStoreManifestSectionName));
        services.AddSingleton<ITrustAnchorStore>(sp =>
            new TrustAnchorMemoryStore()
            {
                AnchorCertificates = new HashSet<Anchor>
                {
#if NET9_0_OR_GREATER
                    new Anchor(X509CertificateLoader.LoadCertificateFromFile("./CertStore/anchors/caLocalhostCert.cer"))
#else
                    new Anchor(new X509Certificate2("./CertStore/anchors/caLocalhostCert.cer"))
#endif
                }
            });

        var problemFlags = ChainProblemStatus.NotTimeValid |
                           ChainProblemStatus.Revoked |
                           ChainProblemStatus.NotSignatureValid |
                           ChainProblemStatus.InvalidBasicConstraints |
                           ChainProblemStatus.UntrustedRoot;
                        // ChainProblemStatus.OfflineRevocation;


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

        var serviceProvider = services.BuildServiceProvider();

        var udapClient = serviceProvider.GetRequiredService<IUdapClient>();
    udapClient.Problem += _diagnosticsValidator.OnChainProblem;
    udapClient.Untrusted += _diagnosticsValidator.OnUnTrusted;

    var disco = await udapClient.ValidateResource(
        _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4",
        "udap://Provider2");

    Assert.True(disco.IsError, disco.Raw);
    Assert.NotNull(udapClient.UdapServerMetadata);
    Assert.False(_diagnosticsValidator.ProblemCalled);
    Assert.True(_diagnosticsValidator.UntrustedCalled);
    Assert.Equal("CN=IdProvider2, OU=fhirlabs.net, O=Fhir Coding, L=Portland, S=Oregon, C=US", _diagnosticsValidator.UnTrustedCertificate);


}
}
