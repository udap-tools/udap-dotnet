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
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
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
using Moq;
using Udap.Client.Client;
using Udap.Client.Configuration;
using Udap.Common;
using Udap.Common.Certificates;
using Udap.Common.Models;
using Xunit.Abstractions;
using static UdapMetadata.Tests.FhirLabsApi.UdapControllerCommunityTest;
using fhirLabsProgram = FhirLabsApi.Program;


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
    private IServiceProvider _serviceProvider;
    private readonly FakeValidatorDiagnostics _diagnosticsValidator = new FakeValidatorDiagnostics();

    public UdapControllerCommunityTest(ApiForCommunityTestFixture fixture, ITestOutputHelper testOutputHelper)
    {
        if (fixture == null) throw new ArgumentNullException(nameof(fixture));
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
                           X509ChainStatusFlags.UntrustedRoot |
                           // X509ChainStatusFlags.OfflineRevocation |
                           X509ChainStatusFlags.CtlNotSignatureValid;
                           // X509ChainStatusFlags.RevocationStatusUnknown;


        services.TryAddScoped(_ =>
            new TrustChainValidator(
                new X509ChainPolicy()
                {
                    DisableCertificateDownloads = true,
                    UrlRetrievalTimeout = TimeSpan.FromMicroseconds(1),
                }, 
                problemFlags,
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
    public async Task ValidateChainTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();
        udapClient.Problem += _diagnosticsValidator.OnChainProblem;

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4",
            "udap://Provider2");

        disco.IsError.Should().BeFalse($"\nError: {disco.Error} \nError Type: {disco.ErrorType}\n{disco.Raw}");
        Assert.NotNull(udapClient.UdapServerMetaData);
        _diagnosticsValidator.ProblemCalled.Should().BeFalse();

        disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4",
            "udap://Provider2");

        disco.IsError.Should().BeFalse($"\nError: {disco.Error} \nError Type: {disco.ErrorType}\n{disco.Raw}");
        Assert.NotNull(udapClient.UdapServerMetaData);
        _diagnosticsValidator.ProblemCalled.Should().BeFalse();
    }

    [Fact]
    public async Task ValidateChainEcdsaTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();
        udapClient.Problem += _diagnosticsValidator.OnChainProblem;

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4",
            "udap://ECDSA/");

        disco.IsError.Should().BeFalse($"\nError: {disco.Error} \nError Type: {disco.ErrorType}\n{disco.Raw}");
        Assert.NotNull(udapClient.UdapServerMetaData);
        _diagnosticsValidator.ProblemCalled.Should().BeFalse();

        var disco2 = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4",
            "udap://ECDSA/");

        disco.Raw.Should().NotBe(disco2.Raw);

        disco2.IsError.Should().BeFalse($"\nError: {disco2.Error} \nError Type: {disco2.ErrorType}\n{disco2.Raw}");
        Assert.NotNull(udapClient.UdapServerMetaData);
        _diagnosticsValidator.ProblemCalled.Should().BeFalse();
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

        disco.IsError.Should().BeTrue(disco.Raw);
        Assert.NotNull(udapClient.UdapServerMetaData);
        _diagnosticsValidator.TokenErrorCalled.Should().BeTrue();
        _diagnosticsValidator.ActualErrorMessages.Any(m => m.Contains("Failed JWT Validation")).Should().BeTrue();
        // http://localhost/fhir/r99 is the subject alt used to sign software statement
        _diagnosticsValidator.ActualErrorMessages.Any(m => m.Contains("http://localhost/fhir/r99")).Should().BeTrue();
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

        disco.IsError.Should().BeTrue(disco.Raw);
        Assert.NotNull(udapClient.UdapServerMetaData);
        _diagnosticsValidator.TokenErrorCalled.Should().BeTrue();
        _diagnosticsValidator.ActualErrorMessages.Any(m => m.Contains("JWT iss does not match baseUrl.")).Should().BeTrue();
    }


    [Fact]
    public async Task MissingCommunityChainTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();
        udapClient.Problem += _diagnosticsValidator.OnChainProblem;

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4",
            "udap://weatherapi/"); // The udap://weatherapi/ community is not supported by the FhirLabsApi web server. 

        disco.IsError.Should().BeTrue(disco.Raw);
        udapClient.UdapServerMetaData.Should().BeNull();
        _diagnosticsValidator.ProblemCalled.Should().BeFalse();
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

        disco.IsError.Should().BeTrue(disco.Raw);
        udapClient.UdapServerMetaData.Should().NotBeNull();
         _diagnosticsValidator.UntrustedCalled.Should().BeTrue();
        _diagnosticsValidator.UnTrustedCertificate.Should().Be("CN=localhost3, OU=fhirlabs.net, O=Fhir Coding, L=Portland, S=Oregon, C=US");
        _diagnosticsValidator.ProblemCalled.Should().BeFalse();
        _diagnosticsValidator.ErrorCalled.Should().BeFalse();
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
                       X509ChainStatusFlags.OfflineRevocation |
                       X509ChainStatusFlags.CtlNotSignatureValid |
                       X509ChainStatusFlags.RevocationStatusUnknown |
                       X509ChainStatusFlags.PartialChain |
                       X509ChainStatusFlags.UntrustedRoot;


        services.TryAddScoped(_ =>
            new TrustChainValidator(
                new X509ChainPolicy()
                {
                    DisableCertificateDownloads = true,
                    UrlRetrievalTimeout = TimeSpan.FromMicroseconds(1),
                }, 
                problemFlags,
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

        disco.IsError.Should().BeTrue($"\nError: {disco.Error} \nError Type: {disco.ErrorType}\n{disco.Raw}");
        Assert.NotNull(udapClient.UdapServerMetaData);

        _diagnosticsValidator.ActualErrorMessages.Any(m =>
                m.Contains("OfflineRevocation"))
            .Should().BeTrue();
    }


    [Fact(Skip = "Swagger friction with net7 and non default pathBase.  Save for another day.  Maybe put behind Yarp and/or follow through on this PR: https://github.com/brianpos/fhir-net-web-api/pull/13")] //Swagger
    public async Task OpenApiTest()
    {
        var response = await _fixture.CreateClient().GetAsync($"fhir/r4/Swagger/Index.html");

        System.Diagnostics.Trace.WriteLine(response.ToString());

        response.StatusCode.Should().Be(HttpStatusCode.OK, "Should be status ok");
        var contentType = response.Content.Headers.ContentType;
        contentType.Should().NotBeNull(); 
        contentType!.MediaType.Should().Be("text/html", "Should be status ok");

        var result = await response.Content.ReadAsStringAsync();
        result
            .Should()
            .Contain(
                "./swagger-ui.css",
                "Does not seem to be the standard swagger ui html");

        //
        // TODO
        // This last part doesn't actually catch failures.  I would need to render the html 
        // some how to finish the test.
        // To make this fail just change one of the helper methods in udapController from
        // private to public.


        result
            .Should()
            .NotContain(
                "Failed to load API definition",
                "Swagger UI Failed to load.");
    }

    [Fact]
    public async Task signed_metatdataContentTest()
    {

        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();
        udapClient.Problem += _diagnosticsValidator.OnChainProblem;

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4",
            "udap://Provider2");

        disco.IsError.Should().BeFalse($"\nError: {disco.Error} \nError Type: {disco.ErrorType}\n{disco.Raw}");
        Assert.NotNull(udapClient.UdapServerMetaData);
        _diagnosticsValidator.ProblemCalled.Should().BeFalse();

        //
        // this should all happen in udapClient.ValidateResource()
        //
        var jwt = new JwtSecurityToken(disco.SignedMetadata);
        
        var issClaim = jwt.Payload.Claims.Single(c => c.Type == JwtClaimTypes.Issuer);
        issClaim.ValueType.Should().Be(ClaimValueTypes.String);

        // should be the same as the web base url, but this would be localhost
        issClaim.Value.Should().Be("http://localhost/fhir/r4");

        var tokenHeader = jwt.Header;
        var x5CArray = tokenHeader["x5c"] as List<object>;
        var cert = new X509Certificate2(Convert.FromBase64String(x5CArray!.First().ToString()!));
        var subjectAltName = cert.GetNameInfo(X509NameType.UrlName, false);
        subjectAltName.Should().Be(issClaim.Value,
            $"iss: {issClaim.Value} does not match Subject Alternative Name extension");

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
  
    public class FakeValidatorDiagnostics
    {
        public bool ProblemCalled;
        public bool ErrorCalled;
        public bool UntrustedCalled;
        public bool TokenErrorCalled;

        public string UnTrustedCertificate = string.Empty;

        private readonly List<string> _actualErrorMessages = new List<string>();
        public List<string> ActualErrorMessages
        {
            get { return _actualErrorMessages; }
        }

        public void OnChainProblem(X509ChainElement chainElement)
        {
            foreach (var chainElementStatus in chainElement.ChainElementStatus
                         .Where(s => (s.Status & TrustChainValidator.DefaultProblemFlags) != 0))
            {
                var problem = $"Trust ERROR ({chainElementStatus.Status}){chainElementStatus.StatusInformation}, {chainElement.Certificate}";
                _actualErrorMessages.Add(problem);
                ProblemCalled = true;
            }
        }
        
        public void OnError(X509Certificate2 certificate, Exception exception)
        {
            _actualErrorMessages.Add($"Failed validating certificate: {certificate.SubjectName.Name} \n {exception.Message}");
            ErrorCalled = true;
        }

        public void OnUnTrusted(X509Certificate2 certificate)
        {
            UnTrustedCertificate = certificate.SubjectName.Name;
            _actualErrorMessages.Add($"Untrusted validating certificate: {certificate.SubjectName.Name}");
            UntrustedCalled = true;
        }

        public void OnTokenError(string message)
        {
            _actualErrorMessages.Add($"Failed JWT Validation: {message}");
            TokenErrorCalled = true;
        }
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
        if (fixture == null) throw new ArgumentNullException(nameof(fixture));
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
    services.Configure<UdapFileCertStoreManifest>(configuration.GetSection(Constants.UDAP_FILE_STORE_MANIFEST));
    services.AddSingleton<ITrustAnchorStore>(sp =>
        new TrustAnchorMemoryStore()
        {
            AnchorCertificates = new HashSet<Anchor>
            {
                new Anchor(new X509Certificate2("./CertStore/anchors/caLocalhostCert2.cer"))
                {
                    //TODO:  Implement a ICertificateResolver, injected into TrustChainValidator to follow AIA extensions, resolving intermediate certificates
                    Intermediates = new List<Intermediate>
                    {
                        new Intermediate(new X509Certificate2("./CertStore/intermediates/intermediateLocalhostCert2.cer"))
                    }
                }
            }
        });

    var problemFlags = X509ChainStatusFlags.NotTimeValid |
                       X509ChainStatusFlags.Revoked |
                       X509ChainStatusFlags.NotSignatureValid |
                       X509ChainStatusFlags.InvalidBasicConstraints |
                       X509ChainStatusFlags.CtlNotTimeValid |
                       X509ChainStatusFlags.UntrustedRoot |
                    // X509ChainStatusFlags.OfflineRevocation |
                       X509ChainStatusFlags.CtlNotSignatureValid;
                    // X509ChainStatusFlags.RevocationStatusUnknown;


        services.TryAddScoped(_ =>
        new TrustChainValidator(new X509ChainPolicy()
            {
                DisableCertificateDownloads = true,
                UrlRetrievalTimeout = TimeSpan.FromMicroseconds(1),
            }, 
            problemFlags,
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

    disco.IsError.Should().BeFalse($"\nError: {disco.Error} \nError Type: {disco.ErrorType}\n{disco.Raw}");
    Assert.NotNull(udapClient.UdapServerMetaData);
    _diagnosticsValidator.ProblemCalled.Should().BeFalse();
}

[Fact]
public async Task ValidateChainWithMyAnchorTest()
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
        services.Configure<UdapFileCertStoreManifest>(configuration.GetSection(Constants.UDAP_FILE_STORE_MANIFEST));
        services.AddSingleton<ITrustAnchorStore>(sp =>
            new TrustAnchorMemoryStore()
            {
                AnchorCertificates = new HashSet<Anchor>
                {
                    new Anchor(new X509Certificate2("./CertStore/anchors/caLocalhostCert2.cer"))
                    // No intermediate and no way to load it because this test cert has no AIA extension to follow.
                    // ************* DRAGONS ***********************
                    // Watch out for the intermediate getting cached now that I have Udap.Certificate.Server running for integration work.
                    // The integration also allows the intermediate* certs to be loaded into your personal intermediate store in Windows
                    // ************* DRAGONS ***********************
                }
            });

        var problemFlags = X509ChainStatusFlags.NotTimeValid |
                           X509ChainStatusFlags.Revoked |
                           X509ChainStatusFlags.NotSignatureValid |
                           X509ChainStatusFlags.InvalidBasicConstraints |
                           X509ChainStatusFlags.CtlNotTimeValid |
                           X509ChainStatusFlags.OfflineRevocation |
                           X509ChainStatusFlags.CtlNotSignatureValid |
                           X509ChainStatusFlags.RevocationStatusUnknown |
                           X509ChainStatusFlags.PartialChain |
                           X509ChainStatusFlags.UntrustedRoot;


        services.TryAddScoped(_ =>
            new TrustChainValidator(new X509ChainPolicy()
                {
                    DisableCertificateDownloads = true,
                    UrlRetrievalTimeout = TimeSpan.FromMicroseconds(1),
                }, 
                problemFlags,
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

    disco.IsError.Should().BeTrue(disco.Raw);
    Assert.NotNull(udapClient.UdapServerMetaData);
    _diagnosticsValidator.UntrustedCalled.Should().BeTrue();
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
        services.Configure<UdapFileCertStoreManifest>(configuration.GetSection(Constants.UDAP_FILE_STORE_MANIFEST));
        services.AddSingleton<ITrustAnchorStore>(sp =>
            new TrustAnchorMemoryStore()
            {
                AnchorCertificates = new HashSet<Anchor>
                {
                    new Anchor(new X509Certificate2("./CertStore/anchors/caLocalhostCert.cer"))
                    {
                        Community = "udap://Provider2",
                        Intermediates = new List<Intermediate>
                        {
                            new Intermediate(new X509Certificate2("./CertStore/intermediates/intermediateLocalhostCert.cer"))
                        }
                    }
                }
            });

        var problemFlags = X509ChainStatusFlags.NotTimeValid |
                           X509ChainStatusFlags.Revoked |
                           X509ChainStatusFlags.NotSignatureValid |
                           X509ChainStatusFlags.InvalidBasicConstraints |
                           X509ChainStatusFlags.CtlNotTimeValid |
                           X509ChainStatusFlags.UntrustedRoot |
                        // X509ChainStatusFlags.OfflineRevocation |
                           X509ChainStatusFlags.CtlNotSignatureValid;
                        // X509ChainStatusFlags.RevocationStatusUnknown;


        services.TryAddScoped(_ =>
            new TrustChainValidator(
                new X509ChainPolicy()
                {
                    DisableCertificateDownloads = true,
                    UrlRetrievalTimeout = TimeSpan.FromMicroseconds(1),
                }, 
                problemFlags,
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

    disco.IsError.Should().BeTrue(disco.Raw);
    Assert.NotNull(udapClient.UdapServerMetaData);
    _diagnosticsValidator.ProblemCalled.Should().BeFalse();
    _diagnosticsValidator.UntrustedCalled.Should().BeTrue();
    _diagnosticsValidator.UnTrustedCertificate.Should().Be("CN=IdProvider2, OU=fhirlabs.net, O=Fhir Coding, L=Portland, S=Oregon, C=US");
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
        services.Configure<UdapFileCertStoreManifest>(configuration.GetSection(Constants.UDAP_FILE_STORE_MANIFEST));
        services.AddSingleton<ITrustAnchorStore>(sp =>
            new TrustAnchorMemoryStore()
            {
                AnchorCertificates = new HashSet<Anchor>
                {
                    new Anchor(new X509Certificate2("./CertStore/anchors/caLocalhostCert.cer"))
                }
            });

        var problemFlags = X509ChainStatusFlags.NotTimeValid |
                           X509ChainStatusFlags.Revoked |
                           X509ChainStatusFlags.NotSignatureValid |
                           X509ChainStatusFlags.InvalidBasicConstraints |
                           X509ChainStatusFlags.CtlNotTimeValid |
                           X509ChainStatusFlags.UntrustedRoot |
                        // X509ChainStatusFlags.OfflineRevocation |
                           X509ChainStatusFlags.CtlNotSignatureValid;
                        // X509ChainStatusFlags.RevocationStatusUnknown;


        services.TryAddScoped(_ =>
            new TrustChainValidator(new X509ChainPolicy()
                {
                    DisableCertificateDownloads = true,
                    UrlRetrievalTimeout = TimeSpan.FromMicroseconds(1),
                }, 
                problemFlags,
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

    disco.IsError.Should().BeTrue(disco.Raw);
    Assert.NotNull(udapClient.UdapServerMetaData);
    _diagnosticsValidator.ProblemCalled.Should().BeFalse();
    _diagnosticsValidator.UntrustedCalled.Should().BeTrue();
    _diagnosticsValidator.UnTrustedCertificate.Should().Be("CN=IdProvider2, OU=fhirlabs.net, O=Fhir Coding, L=Portland, S=Oregon, C=US");


}
}
