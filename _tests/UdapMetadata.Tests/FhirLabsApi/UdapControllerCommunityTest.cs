#region (c) 2022 Joseph Shook. All rights reserved.
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
using System.Text.Json;
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
using Udap.Common;
using Udap.Common.Certificates;
using Udap.Util.Extensions;
using Xunit.Abstractions;
using Xunit.Sdk;
using fhirLabsProgram = FhirLabsApi.Program;


namespace UdapMetadata.Tests.FhirLabsApi;

public class ApiForCommunityTestFixture : WebApplicationFactory<fhirLabsProgram>
{
    public ITestOutputHelper? Output { get; set; }
    private Udap.Model.UdapMetadata? _wellKnownUdap;
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
    private readonly FakeChainValidatorDiagnostics _diagnosticsChainValidator = new FakeChainValidatorDiagnostics();

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
        services.Configure<UdapFileCertStoreManifest>(configuration.GetSection("UdapFileCertStoreManifest"));
        services.AddSingleton<ICertificateStore>(sp =>
            new FileCertificateStore(
                sp.GetRequiredService<IOptionsMonitor<UdapFileCertStoreManifest>>(),
                new Mock<ILogger<FileCertificateStore>>().Object,
                "FhirLabsApi")); //Note: FhirLabsApi is the key to pick the correct data from appsettings.json

        var problemFlags = X509ChainStatusFlags.NotTimeValid |
                           X509ChainStatusFlags.Revoked |
                           X509ChainStatusFlags.NotSignatureValid |
                           X509ChainStatusFlags.InvalidBasicConstraints |
                           X509ChainStatusFlags.CtlNotTimeValid |
                           // X509ChainStatusFlags.OfflineRevocation |
                           X509ChainStatusFlags.CtlNotSignatureValid;
        // X509ChainStatusFlags.RevocationStatusUnknown;


        services.TryAddSingleton<TrustChainValidator>(sp => new TrustChainValidator(new X509ChainPolicy(), problemFlags, _testOutputHelper.ToLogger<TrustChainValidator>()));

        services.AddScoped<IUdapClient>(sp =>
            new UdapClient(_fixture.CreateClient(),
                sp.GetRequiredService<TrustChainValidator>(),
                sp.GetRequiredService<ICertificateStore>(),
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
        udapClient.Problem += _diagnosticsChainValidator.OnChainProblem;

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4",
            "udap://fhirlabs2/");

        disco.IsError.Should().BeFalse($"\nError: {disco.Error} \nError Type: {disco.ErrorType}\n{disco.Raw}");
        Assert.NotNull(udapClient.UdapServerMetaData);
        _diagnosticsChainValidator.Called.Should().BeFalse();
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
            logging.AddXUnit(_testOutputHelper);
        });

        // UDAP CertStore
        services.Configure<UdapFileCertStoreManifest>(configuration.GetSection("UdapFileCertStoreManifest"));
        services.AddSingleton<ICertificateStore>(sp =>
            new FileCertificateStore(
                sp.GetRequiredService<IOptionsMonitor<UdapFileCertStoreManifest>>(),
                new Mock<ILogger<FileCertificateStore>>().Object,
                "FhirLabsApi"));

        var problemFlags = X509ChainStatusFlags.NotTimeValid |
                       X509ChainStatusFlags.Revoked |
                       X509ChainStatusFlags.NotSignatureValid |
                       X509ChainStatusFlags.InvalidBasicConstraints |
                       X509ChainStatusFlags.CtlNotTimeValid |
                       X509ChainStatusFlags.OfflineRevocation |
                       X509ChainStatusFlags.CtlNotSignatureValid |
                       X509ChainStatusFlags.RevocationStatusUnknown |
                       X509ChainStatusFlags.PartialChain;


        services.TryAddSingleton<TrustChainValidator>(sp => new TrustChainValidator(new X509ChainPolicy(), problemFlags, _testOutputHelper.ToLogger<TrustChainValidator>()));

        services.AddScoped<IUdapClient>(sp =>
            new UdapClient(_fixture.CreateClient(),
                sp.GetRequiredService<TrustChainValidator>(),
                sp.GetRequiredService<ICertificateStore>(),
                sp.GetRequiredService<ILogger<UdapClient>>()));
        
        var serviceProvider = services.BuildServiceProvider();

        var udapClient = serviceProvider.GetRequiredService<IUdapClient>();
        udapClient.Problem += _diagnosticsChainValidator.OnChainProblem;

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4",
            "udap://fhirlabs2/");

        disco.IsError.Should().BeTrue($"\nError: {disco.Error} \nError Type: {disco.ErrorType}\n{disco.Raw}");
        Assert.NotNull(udapClient.UdapServerMetaData);

        _diagnosticsChainValidator.ActualErrorMessages.Any(m =>
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
        udapClient.Problem += _diagnosticsChainValidator.OnChainProblem;

        var disco = await udapClient.ValidateResource(
            _fixture.CreateClient().BaseAddress?.AbsoluteUri + "fhir/r4",
            "udap://fhirlabs2/");

        disco.IsError.Should().BeFalse($"\nError: {disco.Error} \nError Type: {disco.ErrorType}\n{disco.Raw}");
        Assert.NotNull(udapClient.UdapServerMetaData);
        _diagnosticsChainValidator.Called.Should().BeFalse();

        //
        // this should all happen in udapClient.ValidateResource()
        //
        var jwt = new JwtSecurityToken(disco.SignedMetadata);
        
        var issClaim = jwt.Payload.Claims.Single(c => c.Type == JwtClaimTypes.Issuer);
        issClaim.ValueType.Should().Be(ClaimValueTypes.String);

        // should be the same as the web base url, but this would be localhost
        issClaim.Value.Should().Be("http://localhost/fhir/r4");

        var tokenHeader = jwt.Header;
        var x5CArray = JsonSerializer.Deserialize<string[]>(tokenHeader.X5c);
        var cert = new X509Certificate2(Convert.FromBase64String(x5CArray!.First()));
        var subjectAltName = cert.GetNameInfo(X509NameType.UrlName, false);
        subjectAltName.Should().Be(issClaim.Value,
            $"iss: {issClaim.Value} does not match Subject Alternative Name extension");

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
  
    public class FakeChainValidatorDiagnostics
    {
        public bool Called;

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
                Called = true;
            }
        }
    }
}
