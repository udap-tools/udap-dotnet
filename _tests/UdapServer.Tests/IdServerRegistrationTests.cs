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
using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using FluentAssertions;
using IdentityModel;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Udap.Client.Client.Extensions;
using Udap.Client.Client.Messages;
using Udap.Common;
using Udap.Common.Certificates;
using Udap.Common.Registration;
using Udap.Idp;
using Xunit.Abstractions;

namespace UdapServer.Tests;

public class ApiTestFixture : WebApplicationFactory<Program>
{
    public ITestOutputHelper? Output { get; set; }

    // this test harness's AppSettings
    public IConfigurationRoot TestConfig { get; set; }

    public ApiTestFixture()
    {
        SeedData.EnsureSeedData("Data Source=Udap.Idp.db;", new Mock<Serilog.ILogger>().Object);

        TestConfig = new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .Build();
    }

    protected override IHost CreateHost(IHostBuilder builder)
    {
        // ClientOptions.BaseAddress = new Uri("https://udap.idp.securedcontrols.net:5002");
        // Environment.SetEnvironmentVariable("ASPNETCORE_URLS", "https://udap.idp.securedcontrols.net:5002");
        // Environment.SetEnvironmentVariable("ASPNETCORE_HTTPS_PORT", "5001");
        Environment.SetEnvironmentVariable("ASPNETCORE_URLS", "http://localhost");
        Environment.SetEnvironmentVariable("provider", "Sqlite");
        builder.UseEnvironment("Development");
        
        builder.ConfigureServices(services =>
        {
            //
            // Fix-up TrustChainValidator to ignore certificate revocation
            //
            var descriptor = services.SingleOrDefault(d => d.ServiceType == typeof(TrustChainValidator));

            if (descriptor != null)
            {
                services.Remove(descriptor);
            }

            services.AddSingleton(new TrustChainValidator(
                new X509ChainPolicy
                {
                    VerificationFlags = X509VerificationFlags.IgnoreWrongUsage,
                    RevocationFlag = X509RevocationFlag.ExcludeRoot,
                    RevocationMode = X509RevocationMode.NoCheck // This is the change unit testing with no revocation endpoint to host the revocation list.
                },
                Output.ToLogger<TrustChainValidator>()));

        });

        var overRideConnectionString = new Dictionary<string, string>();
        overRideConnectionString.Add("ConnectionStrings:DefaultConnection", "Data Source=Udap.Idp.db;");

        builder.ConfigureHostConfiguration(b => b.AddInMemoryCollection(overRideConnectionString));
        
        builder.ConfigureLogging(logging =>
        {
            logging.ClearProviders();
            logging.AddXUnit(Output);
        });
        
        var app = base.CreateHost(builder);

        return app;
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
        //builder.UseSetting("contentRoot", "../../../../../examples/Udap.Idp");
    }
}

/// <summary>
/// Full Web tests.  Using <see cref="Udap.Idp"/> web server.
/// </summary>
public class IdServerRegistrationTests : IClassFixture<ApiTestFixture>
{
    private ApiTestFixture _fixture;
    private readonly ITestOutputHelper _testOutputHelper;

    public IdServerRegistrationTests(ApiTestFixture fixture, ITestOutputHelper testOutputHelper)
    {
        if (fixture == null) throw new ArgumentNullException(nameof(fixture));
        fixture.Output = testOutputHelper;
        _fixture = fixture;
        _testOutputHelper = testOutputHelper;
    }

    [Fact]
    public async Task RegisrationSuccessTest()
    {
        // var clientPolicyStore = _fixture.Services.GetService<IIpPolicyStore>();
        //
        //
        using var client = _fixture.CreateClient();
        var disco = await client.GetUdapDiscoveryDocumentForTaskAsync();

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");
        // var discoJsonFormatted =
        //     JsonSerializer.Serialize(disco.Json, new JsonSerializerOptions { WriteIndented = true });
        // _testOutputHelper.WriteLine(discoJsonFormatted);
        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint);

        var cert = Path.Combine("CertStore/issued",
            "weatherApiClientLocalhostCert.pfx");

        _testOutputHelper.WriteLine($"Path to Cert: {cert}");
        var clientCert = new X509Certificate2(cert, "udap-test");
        var securityKey = new X509SecurityKey(clientCert);
        var signingCredentials = new SigningCredentials(securityKey, UdapConstants.SupportedAlgorithm.RS256);

        var now = DateTime.UtcNow;

        var pem = Convert.ToBase64String(clientCert.Export(X509ContentType.Cert));
        var jwtHeader = new JwtHeader
        {
            { "alg", signingCredentials.Algorithm },
            { "x5c", new[] { pem } }
        };

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
            Audience = "https://localhost/connect/register",
            Expiration = EpochTime.GetIntDate(now.AddMinutes(1).ToUniversalTime()),
            IssuedAt = EpochTime.GetIntDate(now.ToUniversalTime()),
            JwtId = jwtId,
            ClientName = "udapTestClient",
            Contacts = new HashSet<string> { "FhirJoe@BridgeTown.lab", "FhirJoe@test.lab" },
            GrantTypes = new HashSet<string> { "client_credentials" },
            ResponseTypes = new HashSet<string> { "authorization_code" },
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "system/Patient.* system/Practitioner.read"
        };

        document.Add("Extra", "Stuff" as string);

        var encodedHeader = jwtHeader.Base64UrlEncode();
        var encodedPayload = document.Base64UrlEncode();
        var encodedSignature =
            JwtTokenUtilities.CreateEncodedSignature(string.Concat(encodedHeader, ".", encodedPayload),
                signingCredentials);
        var signedSoftwareStatement = string.Concat(encodedHeader, ".", encodedPayload, ".", encodedSignature);
        // _testOutputHelper.WriteLine(signedSoftwareStatement);

        var requestBody = new UdapRegisterRequest
        {
            SoftwareStatement = signedSoftwareStatement,
            Udap = UdapConstants.UdapVersionsSupportedValue
        };

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
        responseUdapDocument.ClientId.Should().NotBeNullOrEmpty();
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
    }

    [Fact]
    public async Task RegisrationMissingX5cHeaderTest()
    {
        // var clientPolicyStore = _fixture.Services.GetService<IIpPolicyStore>();
        //
        //
        using var client = _fixture.CreateClient();
        var disco = await client.GetUdapDiscoveryDocumentForTaskAsync();

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");
        // var discoJsonFormatted =
        //     JsonSerializer.Serialize(disco.Json, new JsonSerializerOptions { WriteIndented = true });
        // _testOutputHelper.WriteLine(discoJsonFormatted);
        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint);

        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "weatherApiClientLocalhostCert.pfx");

        var clientCert = new X509Certificate2(cert, "udap-test");
        var securityKey = new X509SecurityKey(clientCert);
        var signingCredentials = new SigningCredentials(securityKey, UdapConstants.SupportedAlgorithm.RS256);

        var now = DateTime.UtcNow;

        var pem = Convert.ToBase64String(clientCert.Export(X509ContentType.Cert));
        var jwtHeader = new JwtHeader
        {
            { "alg", signingCredentials.Algorithm },
            // { "x5c", new[] { pem } }
        };

        var jwtId = CryptoRandom.CreateUniqueId();
        //
        // Could use JwtPayload.  But because we have a typed object, UdapDynamicClientRegistrationDocument
        // I have it implementing IDictionary<string,object> so the JsonExtensions.SerializeToJson method
        // can prepare it the same way JwtPayLoad is essentially implemented, but light weight
        // and specific to this Udap Dynamic Registration.
        //

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
            ResponseTypes = new HashSet<string> { "authorization_code" },
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "system/Patient.* system/Practitioner.read"
        };

        document.Add("Extra", "Stuff" as string);

        var encodedHeader = jwtHeader.Base64UrlEncode();
        var encodedPayload = document.Base64UrlEncode();
        var encodedSignature =
            JwtTokenUtilities.CreateEncodedSignature(string.Concat(encodedHeader, ".", encodedPayload),
                signingCredentials);
        var signedSoftwareStatement = string.Concat(encodedHeader, ".", encodedPayload, ".", encodedSignature);
        // _testOutputHelper.WriteLine(signedSoftwareStatement);

        var requestBody = new UdapRegisterRequest
        {
            SoftwareStatement = signedSoftwareStatement,
            Udap = UdapConstants.UdapVersionsSupportedValue
        };

        var response = await client.PostAsJsonAsync(reg, requestBody); 

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        
        var errorResponse =
            await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();
        
        errorResponse.Should().NotBeNull();
        errorResponse.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement);
    }

    //invalid_software_statement
    [Fact]
    public async Task RegisrationInvalidSotwareStatement_Signature_Test()
    {
        using var client = _fixture.CreateClient();
        var disco = await client.GetUdapDiscoveryDocumentForTaskAsync();

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");
       
        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint);

        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "weatherApiClientLocalhostCert.pfx");

        var clientCert = new X509Certificate2(cert, "udap-test");
        var securityKey = new X509SecurityKey(clientCert);
        var signingCredentials = new SigningCredentials(securityKey, UdapConstants.SupportedAlgorithm.RS256);

        var now = DateTime.UtcNow;

        var pem = Convert.ToBase64String(clientCert.Export(X509ContentType.Cert));
        var jwtHeader = new JwtHeader
        {
            { "alg", signingCredentials.Algorithm },
            { "x5c", new[] { pem } }
        };

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
            ResponseTypes = new HashSet<string> { "authorization_code" },
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "system/Patient.* system/Practitioner.read"
        };

        document.Add("Extra", "Stuff" as string);

        var encodedHeader = jwtHeader.Base64UrlEncode();
        var encodedPayload = document.Base64UrlEncode();
        var encodedSignature =
            JwtTokenUtilities.CreateEncodedSignature(string.Concat(encodedHeader, ".", encodedPayload),
                signingCredentials);
        var signedSoftwareStatement = string.Concat(encodedHeader, ".", encodedPayload, ".", encodedSignature);
        // _testOutputHelper.WriteLine(signedSoftwareStatement);

        var requestBody = new UdapRegisterRequest
        {
            SoftwareStatement = (signedSoftwareStatement + "Invalid"),
            Udap = UdapConstants.UdapVersionsSupportedValue
        };

        var response = await client.PostAsJsonAsync(reg, requestBody);

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var errorResponse =
            await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();

        errorResponse.Should().NotBeNull();
        errorResponse.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement);
    }

    //invalid_software_statement
    [Fact]
    public async Task RegisrationInvalidSotwareStatement_issMatchesUriName_Test()
    {
        using var client = _fixture.CreateClient();
        var disco = await client.GetUdapDiscoveryDocumentForTaskAsync();

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");

        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint);

        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "weatherApiClientLocalhostCert.pfx");

        var clientCert = new X509Certificate2(cert, "udap-test");
        var securityKey = new X509SecurityKey(clientCert);
        var signingCredentials = new SigningCredentials(securityKey, UdapConstants.SupportedAlgorithm.RS256);

        var now = DateTime.UtcNow;

        var pem = Convert.ToBase64String(clientCert.Export(X509ContentType.Cert));
        var jwtHeader = new JwtHeader
        {
            { "alg", signingCredentials.Algorithm },
            { "x5c", new[] { pem } }
        };

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
            ResponseTypes = new HashSet<string> { "authorization_code" },
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "system/Patient.* system/Practitioner.read"
        };

        document.Add("Extra", "Stuff" as string);

        var encodedHeader = jwtHeader.Base64UrlEncode();
        var encodedPayload = document.Base64UrlEncode();
        var encodedSignature =
            JwtTokenUtilities.CreateEncodedSignature(string.Concat(encodedHeader, ".", encodedPayload),
                signingCredentials);
        var signedSoftwareStatement = string.Concat(encodedHeader, ".", encodedPayload, ".", encodedSignature);
        // _testOutputHelper.WriteLine(signedSoftwareStatement);

        var requestBody = new UdapRegisterRequest
        {
            SoftwareStatement = (signedSoftwareStatement),
            Udap = UdapConstants.UdapVersionsSupportedValue
        };

        var response = await client.PostAsJsonAsync(reg, requestBody);

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var errorResponse =
            await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();

        errorResponse.Should().NotBeNull();
        errorResponse.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement);
    }

    //invalid_software_statement
    [Fact]
    public async Task RegisrationInvalidSotwareStatement_issMissing_Test()
    {
        using var client = _fixture.CreateClient();
        var disco = await client.GetUdapDiscoveryDocumentForTaskAsync();

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");

        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint);

        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "weatherApiClientLocalhostCert.pfx");

        var clientCert = new X509Certificate2(cert, "udap-test");
        var securityKey = new X509SecurityKey(clientCert);
        var signingCredentials = new SigningCredentials(securityKey, UdapConstants.SupportedAlgorithm.RS256);

        var now = DateTime.UtcNow;

        var pem = Convert.ToBase64String(clientCert.Export(X509ContentType.Cert));
        var jwtHeader = new JwtHeader
        {
            { "alg", signingCredentials.Algorithm },
            { "x5c", new[] { pem } }
        };

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
            ResponseTypes = new HashSet<string> { "authorization_code" },
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "system/Patient.* system/Practitioner.read"
        };

        document.Add("Extra", "Stuff" as string);

        var encodedHeader = jwtHeader.Base64UrlEncode();
        var encodedPayload = document.Base64UrlEncode();
        var encodedSignature =
            JwtTokenUtilities.CreateEncodedSignature(string.Concat(encodedHeader, ".", encodedPayload),
                signingCredentials);
        var signedSoftwareStatement = string.Concat(encodedHeader, ".", encodedPayload, ".", encodedSignature);
        // _testOutputHelper.WriteLine(signedSoftwareStatement);

        var requestBody = new UdapRegisterRequest
        {
            SoftwareStatement = (signedSoftwareStatement),
            Udap = UdapConstants.UdapVersionsSupportedValue
        };

        var response = await client.PostAsJsonAsync(reg, requestBody);

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var errorResponse =
            await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();

        errorResponse.Should().NotBeNull();
        errorResponse.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement);
    }

    //invalid_software_statement
    [Fact]
    public async Task RegisrationInvalidSotwareStatement_subMissing_Test()
    {
        using var client = _fixture.CreateClient();
        var disco = await client.GetUdapDiscoveryDocumentForTaskAsync();

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");

        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint);

        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "weatherApiClientLocalhostCert.pfx");

        var clientCert = new X509Certificate2(cert, "udap-test");
        var securityKey = new X509SecurityKey(clientCert);
        var signingCredentials = new SigningCredentials(securityKey, UdapConstants.SupportedAlgorithm.RS256);

        var now = DateTime.UtcNow;

        var pem = Convert.ToBase64String(clientCert.Export(X509ContentType.Cert));
        var jwtHeader = new JwtHeader
        {
            { "alg", signingCredentials.Algorithm },
            { "x5c", new[] { pem } }
        };

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
            ResponseTypes = new HashSet<string> { "authorization_code" },
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "system/Patient.* system/Practitioner.read"
        };

        document.Add("Extra", "Stuff" as string);

        var encodedHeader = jwtHeader.Base64UrlEncode();
        var encodedPayload = document.Base64UrlEncode();
        var encodedSignature =
            JwtTokenUtilities.CreateEncodedSignature(string.Concat(encodedHeader, ".", encodedPayload),
                signingCredentials);
        var signedSoftwareStatement = string.Concat(encodedHeader, ".", encodedPayload, ".", encodedSignature);
        // _testOutputHelper.WriteLine(signedSoftwareStatement);

        var requestBody = new UdapRegisterRequest
        {
            SoftwareStatement = (signedSoftwareStatement),
            Udap = UdapConstants.UdapVersionsSupportedValue
        };

        var response = await client.PostAsJsonAsync(reg, requestBody);

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var errorResponse =
            await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();

        errorResponse.Should().NotBeNull();
        errorResponse.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement);
        errorResponse.ErrorDescription.Should().Be(UdapDynamicClientRegistrationErrorDescriptions.SubIsMissing);
    }


    //invalid_software_statement
    [Fact]
    public async Task RegisrationInvalidSotwareStatement_subNotEqualtoIss_Test()
    {
        using var client = _fixture.CreateClient();
        var disco = await client.GetUdapDiscoveryDocumentForTaskAsync();

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");

        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint);

        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "weatherApiClientLocalhostCert.pfx");

        var clientCert = new X509Certificate2(cert, "udap-test");
        var securityKey = new X509SecurityKey(clientCert);
        var signingCredentials = new SigningCredentials(securityKey, UdapConstants.SupportedAlgorithm.RS256);

        var now = DateTime.UtcNow;

        var pem = Convert.ToBase64String(clientCert.Export(X509ContentType.Cert));
        var jwtHeader = new JwtHeader
        {
            { "alg", signingCredentials.Algorithm },
            { "x5c", new[] { pem } }
        };

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
            ResponseTypes = new HashSet<string> { "authorization_code" },
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "system/Patient.* system/Practitioner.read"
        };

        document.Add("Extra", "Stuff" as string);

        var encodedHeader = jwtHeader.Base64UrlEncode();
        var encodedPayload = document.Base64UrlEncode();
        var encodedSignature =
            JwtTokenUtilities.CreateEncodedSignature(string.Concat(encodedHeader, ".", encodedPayload),
                signingCredentials);
        var signedSoftwareStatement = string.Concat(encodedHeader, ".", encodedPayload, ".", encodedSignature);
        // _testOutputHelper.WriteLine(signedSoftwareStatement);

        var requestBody = new UdapRegisterRequest
        {
            SoftwareStatement = (signedSoftwareStatement),
            Udap = UdapConstants.UdapVersionsSupportedValue
        };

        var response = await client.PostAsJsonAsync(reg, requestBody);

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var errorResponse =
            await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();

        errorResponse.Should().NotBeNull();
        errorResponse.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement);
        errorResponse.ErrorDescription.Should().Be(UdapDynamicClientRegistrationErrorDescriptions.SubNotEqualToIss);
    }

    //invalid_software_statement
    [Fact]
    public async Task RegisrationInvalidSotwareStatement_audMissing_Test()
    {
        using var client = _fixture.CreateClient();
        var disco = await client.GetUdapDiscoveryDocumentForTaskAsync();

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");

        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint);

        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "weatherApiClientLocalhostCert.pfx");

        var clientCert = new X509Certificate2(cert, "udap-test");
        var securityKey = new X509SecurityKey(clientCert);
        var signingCredentials = new SigningCredentials(securityKey, UdapConstants.SupportedAlgorithm.RS256);

        var now = DateTime.UtcNow;

        var pem = Convert.ToBase64String(clientCert.Export(X509ContentType.Cert));
        var jwtHeader = new JwtHeader
        {
            { "alg", signingCredentials.Algorithm },
            { "x5c", new[] { pem } }
        };

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
            ResponseTypes = new HashSet<string> { "authorization_code" },
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "system/Patient.* system/Practitioner.read"
        };

        document.Add("Extra", "Stuff" as string);

        var encodedHeader = jwtHeader.Base64UrlEncode();
        var encodedPayload = document.Base64UrlEncode();
        var encodedSignature =
            JwtTokenUtilities.CreateEncodedSignature(string.Concat(encodedHeader, ".", encodedPayload),
                signingCredentials);
        var signedSoftwareStatement = string.Concat(encodedHeader, ".", encodedPayload, ".", encodedSignature);
        // _testOutputHelper.WriteLine(signedSoftwareStatement);

        var requestBody = new UdapRegisterRequest
        {
            SoftwareStatement = (signedSoftwareStatement),
            Udap = UdapConstants.UdapVersionsSupportedValue
        };

        var response = await client.PostAsJsonAsync(reg, requestBody);

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var errorResponse =
            await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();

        errorResponse.Should().NotBeNull();
        errorResponse.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement);
        errorResponse.ErrorDescription.Should().Be($"{UdapDynamicClientRegistrationErrorDescriptions.InvalidAud}: ");
    }

    //invalid_software_statement
    [Fact]
    public async Task RegisrationInvalidSotwareStatement_audEqualsRegistrationEndpoint_Test()
    {
        using var client = _fixture.CreateClient();
        var disco = await client.GetUdapDiscoveryDocumentForTaskAsync();

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");

        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint);

        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "weatherApiClientLocalhostCert.pfx");

        var clientCert = new X509Certificate2(cert, "udap-test");
        var securityKey = new X509SecurityKey(clientCert);
        var signingCredentials = new SigningCredentials(securityKey, UdapConstants.SupportedAlgorithm.RS256);

        var now = DateTime.UtcNow;

        var pem = Convert.ToBase64String(clientCert.Export(X509ContentType.Cert));
        var jwtHeader = new JwtHeader
        {
            { "alg", signingCredentials.Algorithm },
            { "x5c", new[] { pem } }
        };

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
            ResponseTypes = new HashSet<string> { "authorization_code" },
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "system/Patient.* system/Practitioner.read"
        };

        document.Add("Extra", "Stuff" as string);

        var encodedHeader = jwtHeader.Base64UrlEncode();
        var encodedPayload = document.Base64UrlEncode();
        var encodedSignature =
            JwtTokenUtilities.CreateEncodedSignature(string.Concat(encodedHeader, ".", encodedPayload),
                signingCredentials);
        var signedSoftwareStatement = string.Concat(encodedHeader, ".", encodedPayload, ".", encodedSignature);
        // _testOutputHelper.WriteLine(signedSoftwareStatement);

        var requestBody = new UdapRegisterRequest
        {
            SoftwareStatement = (signedSoftwareStatement),
            Udap = UdapConstants.UdapVersionsSupportedValue
        };

        var response = await client.PostAsJsonAsync(reg, requestBody);

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var errorResponse =
            await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();

        errorResponse.Should().NotBeNull();
        errorResponse.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement);
        errorResponse.ErrorDescription.Should().Be($"{UdapDynamicClientRegistrationErrorDescriptions.InvalidMatchAud}");
    }

    //invalid_software_statement
    [Fact]
    public async Task RegisrationInvalidSotwareStatement_expMissing_Test()
    {
        using var client = _fixture.CreateClient();
        var disco = await client.GetUdapDiscoveryDocumentForTaskAsync();

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");

        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint);

        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "weatherApiClientLocalhostCert.pfx");

        var clientCert = new X509Certificate2(cert, "udap-test");
        var securityKey = new X509SecurityKey(clientCert);
        var signingCredentials = new SigningCredentials(securityKey, UdapConstants.SupportedAlgorithm.RS256);

        var now = DateTime.UtcNow;

        var pem = Convert.ToBase64String(clientCert.Export(X509ContentType.Cert));
        var jwtHeader = new JwtHeader
        {
            { "alg", signingCredentials.Algorithm },
            { "x5c", new[] { pem } }
        };

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
            ResponseTypes = new HashSet<string> { "authorization_code" },
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "system/Patient.* system/Practitioner.read"
        };

        document.Add("Extra", "Stuff" as string);

        var encodedHeader = jwtHeader.Base64UrlEncode();
        var encodedPayload = document.Base64UrlEncode();
        var encodedSignature =
            JwtTokenUtilities.CreateEncodedSignature(string.Concat(encodedHeader, ".", encodedPayload),
                signingCredentials);
        var signedSoftwareStatement = string.Concat(encodedHeader, ".", encodedPayload, ".", encodedSignature);
        // _testOutputHelper.WriteLine(signedSoftwareStatement);

        var requestBody = new UdapRegisterRequest
        {
            SoftwareStatement = (signedSoftwareStatement),
            Udap = UdapConstants.UdapVersionsSupportedValue
        };

        var response = await client.PostAsJsonAsync(reg, requestBody);

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var errorResponse =
            await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();

        errorResponse.Should().NotBeNull();
        errorResponse.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement);
        errorResponse.ErrorDescription.Should().Be($"{UdapDynamicClientRegistrationErrorDescriptions.ExpMissing}");
    }

    //invalid_software_statement
    [Fact]
    public async Task RegisrationInvalidSotwareStatement_expExpired_Test()
    {
        using var client = _fixture.CreateClient();
        var disco = await client.GetUdapDiscoveryDocumentForTaskAsync();

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");

        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint);

        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "weatherApiClientLocalhostCert.pfx");

        var clientCert = new X509Certificate2(cert, "udap-test");
        var securityKey = new X509SecurityKey(clientCert);
        var signingCredentials = new SigningCredentials(securityKey, UdapConstants.SupportedAlgorithm.RS256);

        var now = DateTime.UtcNow;

        var pem = Convert.ToBase64String(clientCert.Export(X509ContentType.Cert));
        var jwtHeader = new JwtHeader
        {
            { "alg", signingCredentials.Algorithm },
            { "x5c", new[] { pem } }
        };

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
            ResponseTypes = new HashSet<string> { "authorization_code" },
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "system/Patient.* system/Practitioner.read"
        };

        document.Add("Extra", "Stuff" as string);

        var encodedHeader = jwtHeader.Base64UrlEncode();
        var encodedPayload = document.Base64UrlEncode();
        var encodedSignature =
            JwtTokenUtilities.CreateEncodedSignature(string.Concat(encodedHeader, ".", encodedPayload),
                signingCredentials);
        var signedSoftwareStatement = string.Concat(encodedHeader, ".", encodedPayload, ".", encodedSignature);
        // _testOutputHelper.WriteLine(signedSoftwareStatement);

        var requestBody = new UdapRegisterRequest
        {
            SoftwareStatement = (signedSoftwareStatement),
            Udap = UdapConstants.UdapVersionsSupportedValue
        };

        var response = await client.PostAsJsonAsync(reg, requestBody);

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var errorResponse =
            await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();

        errorResponse.Should().NotBeNull();
        errorResponse.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement);
        errorResponse.ErrorDescription.Should().Contain($"{UdapDynamicClientRegistrationErrorDescriptions.ExpExpired}");
    }

    //invalid_software_statement
    [Fact]
    public async Task RegisrationInvalidSotwareStatement_iatMissing_Test()
    {
        using var client = _fixture.CreateClient();
        var disco = await client.GetUdapDiscoveryDocumentForTaskAsync();

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");

        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint);

        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "weatherApiClientLocalhostCert.pfx");

        var clientCert = new X509Certificate2(cert, "udap-test");
        var securityKey = new X509SecurityKey(clientCert);
        var signingCredentials = new SigningCredentials(securityKey, UdapConstants.SupportedAlgorithm.RS256);

        var now = DateTime.UtcNow;

        var pem = Convert.ToBase64String(clientCert.Export(X509ContentType.Cert));
        var jwtHeader = new JwtHeader
        {
            { "alg", signingCredentials.Algorithm },
            { "x5c", new[] { pem } }
        };

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
            ResponseTypes = new HashSet<string> { "authorization_code" },
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "system/Patient.* system/Practitioner.read"
        };

        document.Add("Extra", "Stuff" as string);

        var encodedHeader = jwtHeader.Base64UrlEncode();
        var encodedPayload = document.Base64UrlEncode();
        var encodedSignature =
            JwtTokenUtilities.CreateEncodedSignature(string.Concat(encodedHeader, ".", encodedPayload),
                signingCredentials);
        var signedSoftwareStatement = string.Concat(encodedHeader, ".", encodedPayload, ".", encodedSignature);
        // _testOutputHelper.WriteLine(signedSoftwareStatement);

        var requestBody = new UdapRegisterRequest
        {
            SoftwareStatement = (signedSoftwareStatement),
            Udap = UdapConstants.UdapVersionsSupportedValue
        };

        var response = await client.PostAsJsonAsync(reg, requestBody);

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var errorResponse =
            await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();

        errorResponse.Should().NotBeNull();
        errorResponse.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement);
        errorResponse.ErrorDescription.Should().Be($"{UdapDynamicClientRegistrationErrorDescriptions.IssuedAtMissing}");
    }

    //invalid_software_statement
    [Fact]
    public async Task RegisrationInvalidSotwareStatement_clientNameMissing_Test()
    {
        using var client = _fixture.CreateClient();
        var disco = await client.GetUdapDiscoveryDocumentForTaskAsync();

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");

        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint);

        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "weatherApiClientLocalhostCert.pfx");

        var clientCert = new X509Certificate2(cert, "udap-test");
        var securityKey = new X509SecurityKey(clientCert);
        var signingCredentials = new SigningCredentials(securityKey, UdapConstants.SupportedAlgorithm.RS256);

        var now = DateTime.UtcNow;

        var pem = Convert.ToBase64String(clientCert.Export(X509ContentType.Cert));
        var jwtHeader = new JwtHeader
        {
            { "alg", signingCredentials.Algorithm },
            { "x5c", new[] { pem } }
        };

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
            ResponseTypes = new HashSet<string> { "authorization_code" },
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "system/Patient.* system/Practitioner.read"
        };

        document.Add("Extra", "Stuff" as string);

        var encodedHeader = jwtHeader.Base64UrlEncode();
        var encodedPayload = document.Base64UrlEncode();
        var encodedSignature =
            JwtTokenUtilities.CreateEncodedSignature(string.Concat(encodedHeader, ".", encodedPayload),
                signingCredentials);
        var signedSoftwareStatement = string.Concat(encodedHeader, ".", encodedPayload, ".", encodedSignature);
        // _testOutputHelper.WriteLine(signedSoftwareStatement);

        var requestBody = new UdapRegisterRequest
        {
            SoftwareStatement = (signedSoftwareStatement),
            Udap = UdapConstants.UdapVersionsSupportedValue
        };

        var response = await client.PostAsJsonAsync(reg, requestBody);

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var errorResponse =
            await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();

        errorResponse.Should().NotBeNull();
        errorResponse.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidClientMetadata);
        errorResponse.ErrorDescription.Should().Be($"{UdapDynamicClientRegistrationErrorDescriptions.ClientNameMissing}");
    }

    //invalid_software_statement
    [Fact]
    public async Task RegisrationInvalidSotwareStatement_responseTypesMissing_Test()
    {
        using var client = _fixture.CreateClient();
        var disco = await client.GetUdapDiscoveryDocumentForTaskAsync();

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");

        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint);

        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "weatherApiClientLocalhostCert.pfx");

        var clientCert = new X509Certificate2(cert, "udap-test");
        var securityKey = new X509SecurityKey(clientCert);
        var signingCredentials = new SigningCredentials(securityKey, UdapConstants.SupportedAlgorithm.RS256);

        var now = DateTime.UtcNow;

        var pem = Convert.ToBase64String(clientCert.Export(X509ContentType.Cert));
        var jwtHeader = new JwtHeader
        {
            { "alg", signingCredentials.Algorithm },
            { "x5c", new[] { pem } }
        };

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
            //ResponseTypes = new HashSet<string> { "code" },
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "user/Patient.* user/Practitioner.read",  
            RedirectUris = new List<string> { new Uri($"https://client.fhirlabs.net/redirect/{Guid.NewGuid()}").AbsoluteUri },
        };

        document.Add("Extra", "Stuff" as string);

        var encodedHeader = jwtHeader.Base64UrlEncode();
        var encodedPayload = document.Base64UrlEncode();
        var encodedSignature =
            JwtTokenUtilities.CreateEncodedSignature(string.Concat(encodedHeader, ".", encodedPayload),
                signingCredentials);
        var signedSoftwareStatement = string.Concat(encodedHeader, ".", encodedPayload, ".", encodedSignature);
        // _testOutputHelper.WriteLine(signedSoftwareStatement);

        var requestBody = new UdapRegisterRequest
        {
            SoftwareStatement = (signedSoftwareStatement),
            Udap = UdapConstants.UdapVersionsSupportedValue
        };

        var response = await client.PostAsJsonAsync(reg, requestBody);

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var errorResponse =
            await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();

        errorResponse.Should().NotBeNull();
        errorResponse.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidClientMetadata);
        errorResponse.ErrorDescription.Should().Be($"{UdapDynamicClientRegistrationErrorDescriptions.ResponseTypesMissing}");
    }

    //invalid_software_statement
    [Fact]
    public async Task RegisrationInvalidSotwareStatement_tokenEndpointAuthMethodMissing_Test()
    {
        using var client = _fixture.CreateClient();
        var disco = await client.GetUdapDiscoveryDocumentForTaskAsync();

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");

        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint);

        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "weatherApiClientLocalhostCert.pfx");

        var clientCert = new X509Certificate2(cert, "udap-test");
        var securityKey = new X509SecurityKey(clientCert);
        var signingCredentials = new SigningCredentials(securityKey, UdapConstants.SupportedAlgorithm.RS256);

        var now = DateTime.UtcNow;

        var pem = Convert.ToBase64String(clientCert.Export(X509ContentType.Cert));
        var jwtHeader = new JwtHeader
        {
            { "alg", signingCredentials.Algorithm },
            { "x5c", new[] { pem } }
        };

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
            ResponseTypes = new HashSet<string> { "authorization_code" },
            //TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "system/Patient.* system/Practitioner.read"
        };

        document.Add("Extra", "Stuff" as string);

        var encodedHeader = jwtHeader.Base64UrlEncode();
        var encodedPayload = document.Base64UrlEncode();
        var encodedSignature =
            JwtTokenUtilities.CreateEncodedSignature(string.Concat(encodedHeader, ".", encodedPayload),
                signingCredentials);
        var signedSoftwareStatement = string.Concat(encodedHeader, ".", encodedPayload, ".", encodedSignature);
        // _testOutputHelper.WriteLine(signedSoftwareStatement);

        var requestBody = new UdapRegisterRequest
        {
            SoftwareStatement = (signedSoftwareStatement),
            Udap = UdapConstants.UdapVersionsSupportedValue
        };

        var response = await client.PostAsJsonAsync(reg, requestBody);

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var errorResponse =
            await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();

        errorResponse.Should().NotBeNull();
        errorResponse.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidClientMetadata);
        errorResponse.ErrorDescription.Should().Be($"{UdapDynamicClientRegistrationErrorDescriptions.TokenEndpointAuthMethodMissing}");
    }
}