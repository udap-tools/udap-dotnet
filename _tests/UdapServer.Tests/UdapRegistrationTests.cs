#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Duende.IdentityServer.EntityFramework.DbContexts;
using FluentAssertions;
using Hl7.Fhir.Model;
using IdentityModel;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Udap.Client.Client.Extensions;
using Udap.Common.Certificates;
using Udap.Model;
using Udap.Model.Registration;
using Udap.Model.Statement;
using Udap.Server.DbContexts;
using Xunit.Abstractions;
using Task = System.Threading.Tasks.Task;

namespace UdapServer.Tests;

public class UdapApiTestFixture : WebApplicationFactory<Udap.Auth.Server.Program>
{
    public ITestOutputHelper? Output { get; set; }
    public IUdapDbAdminContext UdapDbAdminContext { get; set; } = null!;

    private ServiceProvider _serviceProvider = null!;
    private IServiceScope _serviceScope = null!;


    public UdapApiTestFixture()
    {
        SeedData.EnsureSeedData("Data Source=./Udap.Idp.db;", new Mock<Serilog.ILogger>().Object).GetAwaiter().GetResult();
    }

    protected override IHost CreateHost(IHostBuilder builder)
    {
        Environment.SetEnvironmentVariable("ASPNETCORE_URLS", "http://localhost");
        //Similar to pushing to the cloud where the docker image runs as localhost:8080 but we want to inform Udap.Idp
        //that it is some other https url for settings like aud, register and other metadata published settings.
        Environment.SetEnvironmentVariable("UdapIdpBaseUrl", "http://localhost");
        Environment.SetEnvironmentVariable("provider", "Sqlite");
        builder.UseEnvironment("Development");
        
        builder.ConfigureServices(services =>
        {
            services.AddSingleton<IHostLifetime, NoopHostLifetime>();

            //
            // Fix-up TrustChainValidator to ignore certificate revocation
            //
            var descriptor = services.SingleOrDefault(d => d.ServiceType == typeof(TrustChainValidator));
            

            if (descriptor != null)
            {
                Console.WriteLine($"Removing {descriptor}");
                services.Remove(descriptor);
            }
            else
            {
                Console.WriteLine("Nothing to remove???");
            }

            services.AddSingleton(new TrustChainValidator(
                new X509ChainPolicy
                {
                    VerificationFlags = X509VerificationFlags.IgnoreWrongUsage,
                    RevocationFlag = X509RevocationFlag.ExcludeRoot,
                    RevocationMode = X509RevocationMode.NoCheck // This is the change unit testing with no revocation endpoint to host the revocation list.
                },
                Output!.ToLogger<TrustChainValidator>()));

            _serviceProvider = services.BuildServiceProvider();
            _serviceScope = _serviceProvider.GetRequiredService<IServiceScopeFactory>().CreateScope();
            UdapDbAdminContext = _serviceScope.ServiceProvider.GetRequiredService<IUdapDbAdminContext>();
        });

        var overrideSettings = new Dictionary<string, string>
        {
            { "ConnectionStrings:DefaultConnection", "Data Source=Udap.Idp.db;" },
            { "ServerSettings:ServerSupport", "UDAP"},
            { "ServerSettings:LogoRequired", "false"}

        };

        var sb = new StringBuilder();
        
        foreach (var resName in ModelInfo.SupportedResources)
        {
            sb.Append(' ').Append($"user/{resName}.*");
            sb.Append(' ').Append($"user/{resName}.read");
        }
        
        overrideSettings.Add("ServerSettings:DefaultUserScopes", sb.ToString().TrimStart());

        sb = new StringBuilder();

        foreach (var resName in ModelInfo.SupportedResources)
        {
            sb.Append(' ').Append($"system/{resName}.*");
            sb.Append(' ').Append($"system/{resName}.read");
        }

        overrideSettings.Add("ServerSettings:DefaultSystemScopes", sb.ToString().TrimStart());

        

        builder.ConfigureHostConfiguration(b => b.AddInMemoryCollection(overrideSettings!));
        
        builder.ConfigureLogging(logging =>
        {
            logging.ClearProviders();
            logging.AddXUnit(Output!);
        });
        
        var app = base.CreateHost(builder);

        return app;
    }

    /// <inheritdoc />
    public override async ValueTask DisposeAsync()
    {
        _serviceScope.Dispose();
        await _serviceProvider.DisposeAsync();
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseSetting("skipRateLimiting", null);

        //
        // Linux needs to know how to find appsettings file in web api under test.
        // Still works with Windows but what a pain.  This feels fragile
        // TODO: 
        //
        //This is not working for linux tests like it did in other projects.
        builder.UseSetting("contentRoot", "../../../../../examples/Udap.Auth.Server/");
    }
}

/// <summary>
/// Full Web tests.  Using <see cref="Udap.Idp"/> web server.
/// </summary>
[Collection("Udap.Auth.Server")]
public class UdapServerRegistrationTests : IClassFixture<UdapApiTestFixture>
{
    private UdapApiTestFixture _fixture;
    private readonly ITestOutputHelper _testOutputHelper;

    public UdapServerRegistrationTests(UdapApiTestFixture fixture, ITestOutputHelper testOutputHelper)
    {
        if (fixture == null) throw new ArgumentNullException(nameof(fixture));
        fixture.Output = testOutputHelper;
        _fixture = fixture;
        _testOutputHelper = testOutputHelper;
    }

    [Fact]
    public async Task RegistrationSuccess_authorization_code_Test()
    {
        using var client = _fixture.CreateClient();
        await ResetClientInDatabase();

        var disco = await client.GetUdapDiscoveryDocument();

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");
        // var discoJsonFormatted =
        //     JsonSerializer.Serialize(disco.Json, new JsonSerializerOptions { WriteIndented = true });
        // _testOutputHelper.WriteLine(discoJsonFormatted);
        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint!);

        var cert = Path.Combine("CertStore/issued",
            "weatherApiClientLocalhostCert1.pfx");

        _testOutputHelper.WriteLine($"Path to Cert: {cert}");
        var clientCert = new X509Certificate2(cert, "udap-test");
        var now = DateTime.UtcNow;
        var jwtId = CryptoRandom.CreateUniqueId();
        //
        // Could use JwtPayload.  But because we have a typed object, UdapDynamicClientRegistrationDocument
        // I have it implementing IDictionary<string,object> so the JsonExtensions.SerializeToJson method
        // can prepare it the same way JwtPayLoad is essentially implemented, but light weight
        // and specific to this Udap Dynamic Registration.
        //

        var document = new UdapDynamicClientRegistrationDocument
        {
            Issuer = "http://localhost/",
            Subject = "http://localhost/",
            Audience = "http://localhost/connect/register",
            Expiration = EpochTime.GetIntDate(now.AddMinutes(1).ToUniversalTime()),
            IssuedAt = EpochTime.GetIntDate(now.ToUniversalTime()),
            JwtId = jwtId,
            ClientName = "udapTestClient",
            Contacts = new HashSet<string> { "FhirJoe@BridgeTown.lab", "FhirJoe@test.lab" },
            GrantTypes = new HashSet<string> { "authorization_code", "refresh_token" },
            ResponseTypes = new HashSet<string> { "code" },
            RedirectUris = new List<string>(){ "http://localhost/signin-oidc" },
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "user/Patient.*"
        };

        document.Add("Extra", "Stuff" as string);

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();
        
        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        var response =
            await client.PostAsJsonAsync(reg,
                requestBody); //TODO on server side fail for Certifications empty collection

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.StatusCode.Should().Be(HttpStatusCode.Created);

        // var documentAsJson = JsonSerializer.Serialize(document);
        // var result = await response.Content.ReadAsStringAsync();
        // _testOutputHelper.WriteLine(result);
        // result.Should().BeEquivalentTo(documentAsJson);

        var responseUdapDocument =
            await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();

        responseUdapDocument.Should().NotBeNull();
        responseUdapDocument!.ClientId.Should().NotBeNullOrEmpty();
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(responseUdapDocument,
            new JsonSerializerOptions { WriteIndented = true }));

        //
        // Assertions according to
        // https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.1
        //
        responseUdapDocument.SoftwareStatement.Should().Be(signedSoftwareStatement);
        responseUdapDocument.ClientName.Should().Be(document.ClientName);
        responseUdapDocument.Issuer.Should().Be(document.Issuer);

        ((JsonElement)responseUdapDocument["Extra"]).GetString().Should().Be(document["Extra"].ToString());


        using var scope = _fixture.Services.GetRequiredService<IServiceScopeFactory>().CreateScope();
        var udapContext = scope.ServiceProvider.GetRequiredService<UdapDbContext>();
        
        var clientEntity = await udapContext.Clients
            .Include(c => c.RedirectUris)
            .SingleAsync(c => c.ClientId == responseUdapDocument.ClientId);

        clientEntity.RequirePkce.Should().BeFalse();

        clientEntity.RedirectUris.Single().RedirectUri.Should().Be("http://localhost/signin-oidc");
        clientEntity.AllowOfflineAccess.Should().BeTrue();
    }
    
    [Fact]
    public async Task RegistrationSuccessTest()
    {
        using var client = _fixture.CreateClient();
        await ResetClientInDatabase();

        var disco = await client.GetUdapDiscoveryDocument();

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");
        // var discoJsonFormatted =
        //     JsonSerializer.Serialize(disco.Json, new JsonSerializerOptions { WriteIndented = true });
        // _testOutputHelper.WriteLine(discoJsonFormatted);
        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint!);

        var cert = Path.Combine("CertStore/issued", "weatherApiClientLocalhostCert1.pfx");

        _testOutputHelper.WriteLine($"Path to Cert: {cert}");
        var clientCert = new X509Certificate2(cert, "udap-test");
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
            GrantTypes = new HashSet<string> { "client_credentials" },
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue
        };

        document.Add("Extra", "Stuff" as string);

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        var response =
            await client.PostAsJsonAsync(reg,
                requestBody); //TODO on server side fail for Certifications empty collection

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.StatusCode.Should().Be(HttpStatusCode.Created);

        // var documentAsJson = JsonSerializer.Serialize(document);
        // var result = await response.Content.ReadAsStringAsync();
        // _testOutputHelper.WriteLine(result);
        // result.Should().BeEquivalentTo(documentAsJson);

        var responseUdapDocument =
            await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();

        responseUdapDocument.Should().NotBeNull();
        responseUdapDocument!.ClientId.Should().NotBeNullOrEmpty();
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(responseUdapDocument,
            new JsonSerializerOptions { WriteIndented = true }));

        //
        // Assertions according to
        // https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.1
        //
        responseUdapDocument.SoftwareStatement.Should().Be(signedSoftwareStatement);
        responseUdapDocument.ClientName.Should().Be(document.ClientName);
        responseUdapDocument.Issuer.Should().Be(document.Issuer);

        ((JsonElement)responseUdapDocument["Extra"]).GetString().Should().Be(document["Extra"].ToString());


        using var scope = _fixture.Services.GetRequiredService<IServiceScopeFactory>().CreateScope();
        var udapContext = scope.ServiceProvider.GetRequiredService<ConfigurationDbContext>();

        var clientEntity = await udapContext.Clients
            .Include(c => c.AllowedScopes)
            .SingleAsync(c => c.ClientId == responseUdapDocument.ClientId);
            
        clientEntity.RequirePkce.Should().BeTrue();

        clientEntity.AllowedScopes.Count.Should().Be(ModelInfo.SupportedResources.Count * 2);
        clientEntity.AllowOfflineAccess.Should().BeFalse();
    }

    [Fact]
    public async Task RegistrationMissingx5cHeaderTest()
    {
        // var clientPolicyStore = _fixture.Services.GetService<IIpPolicyStore>();
        //
        //
        using var client = _fixture.CreateClient();
        var disco = await client.GetUdapDiscoveryDocument();

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");
        // var discoJsonFormatted =
        //     JsonSerializer.Serialize(disco.Json, new JsonSerializerOptions { WriteIndented = true });
        // _testOutputHelper.WriteLine(discoJsonFormatted);
        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint!);

        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "weatherApiClientLocalhostCert1.pfx");

        var clientCert = new X509Certificate2(cert, "udap-test");
        var now = DateTime.UtcNow;
        var jwtId = CryptoRandom.CreateUniqueId();
        
        var document = new UdapDynamicClientRegistrationDocument
        {
            Issuer = "https://weatherapi.lab:5021/fhir",
            Subject = "https://weatherapi.lab:5021/fhir",
            Audience = "https://weatherapi.lab:5021/connect/register",
            Expiration = EpochTime.GetIntDate(now.AddMinutes(1).ToUniversalTime()),
            IssuedAt = EpochTime.GetIntDate(now.ToUniversalTime()),
            JwtId = jwtId,
            ClientName = "udapTestClient",
            Contacts = new HashSet<string> { "FhirJoe@BridgeTown.lab", "FhirJoe@test.lab" },
            GrantTypes = new HashSet<string> { "client_credentials" },
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "system/Patient.* system/Practitioner.read"
        };

        document.Add("Extra", "Stuff" as string);

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        var response = await client.PostAsJsonAsync(reg, requestBody); 

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        
        var errorResponse =
            await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();
        
        errorResponse.Should().NotBeNull();
        errorResponse!.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement);
    }

    //invalid_software_statement
    [Fact]
    public async Task RegistrationInvalidSoftwareStatement_Signature_Test()
    {
        using var client = _fixture.CreateClient();
        var disco = await client.GetUdapDiscoveryDocument();

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");
       
        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint!);

        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "weatherApiClientLocalhostCert1.pfx");

        var clientCert = new X509Certificate2(cert, "udap-test");
        var now = DateTime.UtcNow;
        var jwtId = CryptoRandom.CreateUniqueId();
       
        var document = new UdapDynamicClientRegistrationDocument
        {
            Issuer = "http://localhost/",
            Subject = "http://localhost/",
            Audience = "https://localhost:5002/connect/register",
            Expiration = EpochTime.GetIntDate(now.AddMinutes(1).ToUniversalTime()),
            IssuedAt = EpochTime.GetIntDate(now.ToUniversalTime()),
            JwtId = jwtId,
            ClientName = "udapTestClient",
            Contacts = new HashSet<string> { "FhirJoe@BridgeTown.lab", "FhirJoe@test.lab" },
            GrantTypes = new HashSet<string> { "client_credentials" },
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "system/Patient.* system/Practitioner.read"
        };

        document.Add("Extra", "Stuff" as string);

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement + "Invalid",
            UdapConstants.UdapVersionsSupportedValue
        );

        var response = await client.PostAsJsonAsync(reg, requestBody);

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var errorResponse =
            await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();

        errorResponse.Should().NotBeNull();
        errorResponse!.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement);
    }

    //invalid_software_statement
    [Fact]
    public async Task RegisrationInvalidSotwareStatement_issMatchesUriName_Test()
    {
        using var client = _fixture.CreateClient();
        var disco = await client.GetUdapDiscoveryDocument();

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");

        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint!);

        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "weatherApiClientLocalhostCert1.pfx");

        var clientCert = new X509Certificate2(cert, "udap-test");
        var now = DateTime.UtcNow;
        var jwtId = CryptoRandom.CreateUniqueId();

        var document = new UdapDynamicClientRegistrationDocument
        {
            Issuer = "http://localhost:9999/",
            Subject = "http://localhost/",
            Audience = "https://localhost:5002/connect/register",
            Expiration = EpochTime.GetIntDate(now.AddMinutes(1).ToUniversalTime()),
            IssuedAt = EpochTime.GetIntDate(now.ToUniversalTime()),
            JwtId = jwtId,
            ClientName = "udapTestClient",
            Contacts = new HashSet<string> { "FhirJoe@BridgeTown.lab", "FhirJoe@test.lab" },
            GrantTypes = new HashSet<string> { "client_credentials" },
            
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "system/Patient.* system/Practitioner.read"
        };

        document.Add("Extra", "Stuff" as string);

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        var response = await client.PostAsJsonAsync(reg, requestBody);

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var errorResponse =
            await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();

        errorResponse.Should().NotBeNull();
        errorResponse!.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement);
    }

    //invalid_software_statement
    [Fact]
    public async Task RegisrationInvalidSotwareStatement_issMissing_Test()
    {
        using var client = _fixture.CreateClient();
        var disco = await client.GetUdapDiscoveryDocument();

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");

        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint!);

        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "weatherApiClientLocalhostCert1.pfx");

        var clientCert = new X509Certificate2(cert, "udap-test");
        var now = DateTime.UtcNow;
        var jwtId = CryptoRandom.CreateUniqueId();

        var document = new UdapDynamicClientRegistrationDocument
        {
            // Issuer = "http://localhost/",
            Subject = "http://localhost/",
            Audience = "https://localhost:5002/connect/register",
            Expiration = EpochTime.GetIntDate(now.AddMinutes(1).ToUniversalTime()),
            IssuedAt = EpochTime.GetIntDate(now.ToUniversalTime()),
            JwtId = jwtId,
            ClientName = "udapTestClient",
            Contacts = new HashSet<string> { "FhirJoe@BridgeTown.lab", "FhirJoe@test.lab" },
            GrantTypes = new HashSet<string> { "client_credentials" },
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "system/Patient.* system/Practitioner.read"
        };

        document.Add("Extra", "Stuff" as string);

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        var response = await client.PostAsJsonAsync(reg, requestBody);

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var errorResponse =
            await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();

        errorResponse.Should().NotBeNull();
        errorResponse!.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement);
    }

    //invalid_software_statement
    [Fact]
    public async Task RegisrationInvalidSotwareStatement_subMissing_Test()
    {
        using var client = _fixture.CreateClient();
        var disco = await client.GetUdapDiscoveryDocument();

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");

        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint!);

        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "weatherApiClientLocalhostCert1.pfx");

        var clientCert = new X509Certificate2(cert, "udap-test");
        var now = DateTime.UtcNow;
        var jwtId = CryptoRandom.CreateUniqueId();

        var document = new UdapDynamicClientRegistrationDocument
        {
            Issuer = "http://localhost/",
            // Subject = "http://localhost/",
            Audience = "https://localhost:5002/connect/register",
            Expiration = EpochTime.GetIntDate(now.AddMinutes(1).ToUniversalTime()),
            IssuedAt = EpochTime.GetIntDate(now.ToUniversalTime()),
            JwtId = jwtId,
            ClientName = "udapTestClient",
            Contacts = new HashSet<string> { "FhirJoe@BridgeTown.lab", "FhirJoe@test.lab" },
            GrantTypes = new HashSet<string> { "client_credentials" },
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "system/Patient.* system/Practitioner.read"
        };

        document.Add("Extra", "Stuff" as string);

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        var response = await client.PostAsJsonAsync(reg, requestBody);

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var errorResponse =
            await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();

        errorResponse.Should().NotBeNull();
        errorResponse!.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement);
        errorResponse.ErrorDescription.Should().Be(UdapDynamicClientRegistrationErrorDescriptions.SubIsMissing);
    }


    //invalid_software_statement
    [Fact]
    public async Task RegisrationInvalidSotwareStatement_subNotEqualtoIss_Test()
    {
        using var client = _fixture.CreateClient();
        var disco = await client.GetUdapDiscoveryDocument();

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");

        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint!);

        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "weatherApiClientLocalhostCert1.pfx");

        var clientCert = new X509Certificate2(cert, "udap-test");
        var now = DateTime.UtcNow;
        var jwtId = CryptoRandom.CreateUniqueId();

        var document = new UdapDynamicClientRegistrationDocument
        {
            Issuer = "http://localhost/",
            Subject = "http://localhost:9999/",
            Audience = "https://localhost:5002/connect/register",
            Expiration = EpochTime.GetIntDate(now.AddMinutes(1).ToUniversalTime()),
            IssuedAt = EpochTime.GetIntDate(now.ToUniversalTime()),
            JwtId = jwtId,
            ClientName = "udapTestClient",
            Contacts = new HashSet<string> { "FhirJoe@BridgeTown.lab", "FhirJoe@test.lab" },
            GrantTypes = new HashSet<string> { "client_credentials" },
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "system/Patient.* system/Practitioner.read"
        };

        document.Add("Extra", "Stuff" as string);

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        var response = await client.PostAsJsonAsync(reg, requestBody);

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var errorResponse =
            await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();

        errorResponse.Should().NotBeNull();
        errorResponse!.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement);
        errorResponse.ErrorDescription.Should().Be(UdapDynamicClientRegistrationErrorDescriptions.SubNotEqualToIss);
    }

    //invalid_software_statement
    [Fact]
    public async Task RegisrationInvalidSotwareStatement_audMissing_Test()
    {
        using var client = _fixture.CreateClient();
        var disco = await client.GetUdapDiscoveryDocument();

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");

        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint!);

        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "weatherApiClientLocalhostCert1.pfx");

        var clientCert = new X509Certificate2(cert, "udap-test");
        var now = DateTime.UtcNow;
        var jwtId = CryptoRandom.CreateUniqueId();

        var document = new UdapDynamicClientRegistrationDocument
        {
            Issuer = "http://localhost/",
            Subject = "http://localhost/",
            // Audience = "https://localhost:5002/connect/register",
            Expiration = EpochTime.GetIntDate(now.AddMinutes(1).ToUniversalTime()),
            IssuedAt = EpochTime.GetIntDate(now.ToUniversalTime()),
            JwtId = jwtId,
            ClientName = "udapTestClient",
            Contacts = new HashSet<string> { "FhirJoe@BridgeTown.lab", "FhirJoe@test.lab" },
            GrantTypes = new HashSet<string> { "client_credentials" },
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "system/Patient.* system/Practitioner.read"
        };

        document.Add("Extra", "Stuff" as string);

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        var response = await client.PostAsJsonAsync(reg, requestBody);

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var errorResponse =
            await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();

        errorResponse.Should().NotBeNull();
        errorResponse!.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement);
        errorResponse.ErrorDescription.Should().Be($"{UdapDynamicClientRegistrationErrorDescriptions.InvalidAud}: ");
    }

    //invalid_software_statement
    [Fact]
    public async Task RegisrationInvalidSotwareStatement_audEqualsRegistrationEndpoint_Test()
    {
        using var client = _fixture.CreateClient();
        var disco = await client.GetUdapDiscoveryDocument();

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");

        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint!);

        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "weatherApiClientLocalhostCert1.pfx");

        var clientCert = new X509Certificate2(cert, "udap-test");
        var now = DateTime.UtcNow;
        var jwtId = CryptoRandom.CreateUniqueId();

        var document = new UdapDynamicClientRegistrationDocument
        {
            Issuer = "http://localhost/",
            Subject = "http://localhost/",
            Audience = "https://localhost:5002/connect/register",
            Expiration = EpochTime.GetIntDate(now.AddMinutes(1).ToUniversalTime()),
            IssuedAt = EpochTime.GetIntDate(now.ToUniversalTime()),
            JwtId = jwtId,
            ClientName = "udapTestClient",
            Contacts = new HashSet<string> { "FhirJoe@BridgeTown.lab", "FhirJoe@test.lab" },
            GrantTypes = new HashSet<string> { "client_credentials" },
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "system/Patient.* system/Practitioner.read"
        };

        document.Add("Extra", "Stuff" as string);

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        var response = await client.PostAsJsonAsync(reg, requestBody);

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var errorResponse =
            await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();

        errorResponse.Should().NotBeNull();
        errorResponse!.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement);
        errorResponse.ErrorDescription.Should().Be($"{UdapDynamicClientRegistrationErrorDescriptions.InvalidMatchAud}");
    }

    //invalid_software_statement
    [Fact]
    public async Task RegisrationInvalidSotwareStatement_expMissing_Test()
    {
        using var client = _fixture.CreateClient();
        var disco = await client.GetUdapDiscoveryDocument();

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");

        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint!);

        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "weatherApiClientLocalhostCert1.pfx");

        var clientCert = new X509Certificate2(cert, "udap-test");
        var now = DateTime.UtcNow;
        var jwtId = CryptoRandom.CreateUniqueId();

        var document = new UdapDynamicClientRegistrationDocument
        {
            Issuer = "http://localhost/",
            Subject = "http://localhost/",
            Audience = "https://localhost:5002/connect/register",
            // Expiration = EpochTime.GetIntDate(now.AddMinutes(1).ToUniversalTime()),
            IssuedAt = EpochTime.GetIntDate(now.ToUniversalTime()),
            JwtId = jwtId,
            ClientName = "udapTestClient",
            Contacts = new HashSet<string> { "FhirJoe@BridgeTown.lab", "FhirJoe@test.lab" },
            GrantTypes = new HashSet<string> { "client_credentials" },
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "system/Patient.* system/Practitioner.read"
        };

        document.Add("Extra", "Stuff" as string);

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        var response = await client.PostAsJsonAsync(reg, requestBody);

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var errorResponse =
            await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();

        errorResponse.Should().NotBeNull();
        errorResponse!.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement);
        errorResponse.ErrorDescription.Should().Be($"{UdapDynamicClientRegistrationErrorDescriptions.ExpMissing}");
    }

    //invalid_software_statement
    [Fact]
    public async Task RegisrationInvalidSotwareStatement_expExpired_Test()
    {
        using var client = _fixture.CreateClient();
        var disco = await client.GetUdapDiscoveryDocument();

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");

        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint!);

        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "weatherApiClientLocalhostCert1.pfx");

        var clientCert = new X509Certificate2(cert, "udap-test");
        var now = DateTime.UtcNow;
        var jwtId = CryptoRandom.CreateUniqueId();

        var document = new UdapDynamicClientRegistrationDocument
        {
            Issuer = "http://localhost/",
            Subject = "http://localhost/",
            Audience = "https://localhost:5002/connect/register",
            Expiration = EpochTime.GetIntDate(now.AddMinutes(-5).ToUniversalTime()),
            IssuedAt = EpochTime.GetIntDate(now.ToUniversalTime()),
            JwtId = jwtId,
            ClientName = "udapTestClient",
            Contacts = new HashSet<string> { "FhirJoe@BridgeTown.lab", "FhirJoe@test.lab" },
            GrantTypes = new HashSet<string> { "client_credentials" },
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "system/Patient.* system/Practitioner.read"
        };

        document.Add("Extra", "Stuff" as string);

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        var response = await client.PostAsJsonAsync(reg, requestBody);

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var errorResponse =
            await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();

        errorResponse.Should().NotBeNull();
        errorResponse!.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement);
        errorResponse.ErrorDescription.Should().Contain($"{UdapDynamicClientRegistrationErrorDescriptions.ExpExpired}");
    }

    //invalid_software_statement
    [Fact]
    public async Task RegisrationInvalidSotwareStatement_iatMissing_Test()
    {
        using var client = _fixture.CreateClient();
        var disco = await client.GetUdapDiscoveryDocument();

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");

        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint!);

        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "weatherApiClientLocalhostCert1.pfx");

        var clientCert = new X509Certificate2(cert, "udap-test");
        var now = DateTime.UtcNow;
        var jwtId = CryptoRandom.CreateUniqueId();

        var document = new UdapDynamicClientRegistrationDocument
        {
            Issuer = "http://localhost/",
            Subject = "http://localhost/",
            Audience = "https://localhost/connect/register",
            Expiration = EpochTime.GetIntDate(now.AddMinutes(1).ToUniversalTime()),
            //IssuedAt = EpochTime.GetIntDate(now.ToUniversalTime()),
            JwtId = jwtId,
            ClientName = "udapTestClient",
            Contacts = new HashSet<string> { "FhirJoe@BridgeTown.lab", "FhirJoe@test.lab" },
            GrantTypes = new HashSet<string> { "client_credentials" },
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "system/Patient.* system/Practitioner.read"
        };

        document.Add("Extra", "Stuff" as string);

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        var response = await client.PostAsJsonAsync(reg, requestBody);

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var errorResponse =
            await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();

        errorResponse.Should().NotBeNull();
        errorResponse!.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement);
        errorResponse.ErrorDescription.Should().Be($"{UdapDynamicClientRegistrationErrorDescriptions.IssuedAtMissing}");
    }

    //invalid_client_metadata
    [Fact]
    public async Task RegistrationInvalidClientMetadata_clientName_Missing_Test()
    {
        using var client = _fixture.CreateClient();
        var disco = await client.GetUdapDiscoveryDocument();

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");

        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint!);

        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "weatherApiClientLocalhostCert1.pfx");

        var clientCert = new X509Certificate2(cert, "udap-test");
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
            // ClientName = "udapTestClient",
            Contacts = new HashSet<string> { "FhirJoe@BridgeTown.lab", "FhirJoe@test.lab" },
            GrantTypes = new HashSet<string> { "client_credentials" },
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "system/Patient.* system/Practitioner.read"
        };

        document.Add("Extra", "Stuff" as string);

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        var response = await client.PostAsJsonAsync(reg, requestBody);

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var errorResponse =
            await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();

        errorResponse.Should().NotBeNull();
        errorResponse!.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidClientMetadata);
        errorResponse.ErrorDescription.Should().Be($"{UdapDynamicClientRegistrationErrorDescriptions.ClientNameMissing}");
    }

    //invalid_client_metadata
    //
    // Remember and empty grant_types is a cancel registration
    // http://hl7.org/fhir/us/udap-security/registration.html#modifying-and-cancelling-registrations
    // But a missing grant_types is an error
    //
    [Fact]
    public async Task RegisrationInvalidClientMetadata_grant_types_Missing_Test()
    {
        using var client = _fixture.CreateClient();
        var disco = await client.GetUdapDiscoveryDocument();

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");

        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint!);

        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "weatherApiClientLocalhostCert1.pfx");

        var clientCert = new X509Certificate2(cert, "udap-test");
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
            // GrantTypes = new HashSet<string> { "client_credentials" },
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "system/Patient.* system/Practitioner.read"
        };

        document.Add("Extra", "Stuff" as string);

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        var response = await client.PostAsJsonAsync(reg, requestBody);

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var errorResponse =
            await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();

        errorResponse.Should().NotBeNull();
        errorResponse!.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidClientMetadata);
        errorResponse.ErrorDescription.Should().Be($"{UdapDynamicClientRegistrationErrorDescriptions.GrantTypeMissing}");
    }

    //invalid_client_metadata
    [Fact]
    public async Task RegisrationInvalidClientMetadata_responseTypes_Missing_Test()
    {
        using var client = _fixture.CreateClient();
        var disco = await client.GetUdapDiscoveryDocument();

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");

        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint!);

        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "weatherApiClientLocalhostCert1.pfx");

        var clientCert = new X509Certificate2(cert, "udap-test");
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
            RedirectUris = new List<string> { new Uri($"https://client.fhirlabs.net/redirect/{Guid.NewGuid()}").AbsoluteUri },
        };

        document.Add("Extra", "Stuff" as string);

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        var response = await client.PostAsJsonAsync(reg, requestBody);

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var errorResponse =
            await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();

        errorResponse.Should().NotBeNull();
        errorResponse!.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidClientMetadata);
        errorResponse.ErrorDescription.Should().Be($"{UdapDynamicClientRegistrationErrorDescriptions.ResponseTypesMissing}");
    }

    //invalid_client_metadata
    [Fact]
    public async Task RegisrationInvalidClientMetadata_tokenEndpointAuthMethodMissing_Test()
    {
        using var client = _fixture.CreateClient();
        var disco = await client.GetUdapDiscoveryDocument();

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");

        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint!);

        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "weatherApiClientLocalhostCert1.pfx");

        var clientCert = new X509Certificate2(cert, "udap-test");
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
            GrantTypes = new HashSet<string> { "client_credentials" },
            //TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "system/Patient.* system/Practitioner.read"
        };

        document.Add("Extra", "Stuff" as string);

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        var response = await client.PostAsJsonAsync(reg, requestBody);

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var errorResponse =
            await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();

        errorResponse.Should().NotBeNull();
        errorResponse!.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidClientMetadata);
        errorResponse.ErrorDescription.Should().Be($"{UdapDynamicClientRegistrationErrorDescriptions.TokenEndpointAuthMethodMissing}");
    }

    private async Task ResetClientInDatabase()
    {
        foreach (var dbClient in _fixture.UdapDbAdminContext.Clients)
        {
            _fixture.UdapDbAdminContext.Clients.Remove(dbClient);
        }

        await _fixture.UdapDbAdminContext.SaveChangesAsync();
    }
}