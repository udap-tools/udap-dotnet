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
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using AspNetCoreRateLimit;
using Duende.IdentityServer.EntityFramework.Entities;
using FluentAssertions;
using FluentAssertions.Common;
using IdentityModel;
using IdentityModel.Client;
using Microsoft.AspNetCore;
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
using Udap.Common.Extensions;
using Udap.Idp;
using Udap.Metadata.Server;
using Udap.Server.Registration;
using Xunit.Abstractions;
using static System.Formats.Asn1.AsnWriter;
using static IdentityModel.OidcConstants;

namespace UdapServer.Tests;

public class ApiTestFixture : WebApplicationFactory<Program>
{
    public ITestOutputHelper? Output { get; set; }

    // this test harness's AppSettings
    public IConfigurationRoot TestConfig { get; set; }

    public ApiTestFixture()
    {
        //
        // Migrate and seed database
        // Database (Sqlite) will be in the bin\debug(release)\net60 folder.
        //
        // var processStartInfo = new ProcessStartInfo
        // {
        //     Arguments = "/seed",
        //     FileName = $"Udap.Idp.exe",
        //     UseShellExecute = false,
        //     CreateNoWindow = false,
        //     RedirectStandardOutput = true,
        //     RedirectStandardError = true
        // };
        //
        // var process = new Process();
        // process.StartInfo = processStartInfo;
        // process.Start();
        //
        // process.WaitForExit();
        // process.ExitCode.ToString();

        SeedData.EnsureSeedData("Data Source=../Udap.Idp.db;", new Mock<Serilog.ILogger>().Object);

        TestConfig = new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json")
            .Build();
    }

    protected override IHost CreateHost(IHostBuilder builder)
    {
        // ClientOptions.BaseAddress = new Uri("https://udap.idp.securedcontrols.net:5002");
        // Environment.SetEnvironmentVariable("ASPNETCORE_URLS", "https://udap.idp.securedcontrols.net:5002");
        // Environment.SetEnvironmentVariable("ASPNETCORE_HTTPS_PORT", "5001");
        Environment.SetEnvironmentVariable("ASPNETCORE_URLS", "http://localhost");
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
    public async Task RegisrationSuccessWeatherApiTest()
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

        var response =
            await client.PostAsJsonAsync(reg,
                requestBody); //TODO on server side fail for Certifications Null collection

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

    [Fact(Skip = "xxx")]
    public async Task RegisrationSuccess_HealthToGo_Test()
    {
        using var client = new HttpClient();
        var disco = await client.GetUdapDiscoveryDocumentForTaskAsync(new UdapDiscoveryDocumentRequest()
        {
            Address = "https://stage.healthtogo.me:8181/fhir/r4/stage",
            Policy = new Udap.Client.Client.DiscoveryPolicy
            {
                ValidateIssuerName = false, // No issuer name in UDAP Metadata of FHIR Server.
                ValidateEndpoints = false // Authority endpoints are not hosted on same domain as Identity Provider.
            }
        });

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");
        var discoJsonFormatted =
            JsonSerializer.Serialize(disco.Json, new JsonSerializerOptions { WriteIndented = true });
        // _testOutputHelper.WriteLine(discoJsonFormatted);
        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint);


        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "udap-sandbox-surescripts.p12");
        var clientCert = new X509Certificate2(cert, "8nww8nni");
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
        // can prepare it the same way JwtPayLoad is essentially implemented, but more light weight
        // and specific to this Udap Dynamic Registration.
        //

        var document = new UdapDynamicClientRegistrationDocument
        {
            Issuer = "https://fhirlabs.net:7016/fhir/r4",
            Subject = "https://fhirlabs.net:7016/fhir/r4",
            Audience = regEndpoint,
            Expiration = EpochTime.GetIntDate(now.AddMinutes(5).ToUniversalTime()),
            IssuedAt = EpochTime.GetIntDate(now.ToUniversalTime()),
            JwtId = jwtId,
            ClientName = "udapTestClient",
            Contacts = new HashSet<string> { "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com" },
            GrantTypes = new HashSet<string> { "client_credentials" },
            // ResponseTypes = new HashSet<string> { "authorization_code" },  TODO: Add tests.  This should not be here when grantTypes contains client_credentials
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "system/Patient.* system/Practitioner.read"
        };


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
            Certifications = new string[0],
            Udap = UdapConstants.UdapVersionsSupportedValue
        };

        var response = await client.PostAsJsonAsync(reg, requestBody);

        response.StatusCode.Should().Be(HttpStatusCode.Created);

        var documentAsJson = JsonSerializer.Serialize(document);
        var result = await response.Content.ReadAsStringAsync();
        // _testOutputHelper.WriteLine(result);
        // result.Should().BeEquivalentTo(documentAsJson);
    }


    [Fact(Skip = "xx")]
    public async Task RegisrationSuccess_NationalDirectory_Test()
    {

        using var client = new HttpClient();
        var disco = await client.GetUdapDiscoveryDocumentForTaskAsync(new UdapDiscoveryDocumentRequest()
        {
            Address = "https://national-directory.meteorapp.com",
            Policy = new Udap.Client.Client.DiscoveryPolicy
            {
                ValidateIssuerName = false, // No issuer name in UDAP Metadata of FHIR Server.
                ValidateEndpoints = false // Authority endpoints are not hosted on same domain as Identity Provider.
            }
        });

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");
        var discoJsonFormatted =
            JsonSerializer.Serialize(disco.Json, new JsonSerializerOptions { WriteIndented = true });
        // _testOutputHelper.WriteLine(discoJsonFormatted);
        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint);


        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "udap-sandbox-surescripts.p12");
        var clientCert = new X509Certificate2(cert, "8nww8nni");
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
        // can prepare it the same way JwtPayLoad is essentially implemented, but more light weight
        // and specific to this Udap Dynamic Registration.
        //

        var document = new UdapDynamicClientRegistrationDocument
        {
            Issuer = "https://fhirlabs.net:7016/fhir/r4",
            Subject = "https://fhirlabs.net:7016/fhir/r4",
            Audience = regEndpoint,
            Expiration = EpochTime.GetIntDate(now.AddMinutes(5).ToUniversalTime()),
            IssuedAt = EpochTime.GetIntDate(now.ToUniversalTime()),
            JwtId = jwtId,
            ClientName = "udapTestClient",
            Contacts = new HashSet<string> { "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com" },
            GrantTypes = new HashSet<string> { "client_credentials" },
            // ResponseTypes = new HashSet<string> { "authorization_code" },  TODO: Add tests.  This should not be here when grantTypes contains client_credentials
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "system/Patient.* system/Practitioner.read"
        };


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
            Certifications = new string[0],
            Udap = UdapConstants.UdapVersionsSupportedValue
        };

        _testOutputHelper.WriteLine(JsonSerializer.Serialize(requestBody));

        return;
        // var response = await client.PostAsJsonAsync(reg, requestBody);
        //
        //
        // // response.StatusCode.Should().Be(HttpStatusCode.Created);
        //
        // var documentAsJson = JsonSerializer.Serialize(document);
        // var result = await response.Content.ReadAsStringAsync();
        // // _testOutputHelper.WriteLine(result);
        // result.Should().BeEquivalentTo(documentAsJson);
    }


    [Fact(Skip = "xx")]
    public async Task RegisrationSuccess_ForEvernorth_Test()
    {
        using var client = new HttpClient();
        var disco = await client.GetUdapDiscoveryDocumentForTaskAsync(new UdapDiscoveryDocumentRequest()
        {
            Address = "https://udap.fast.poolnook.me",
            Policy = new Udap.Client.Client.DiscoveryPolicy
            {
                ValidateIssuerName = false, // No issuer name in UDAP Metadata of FHIR Server.
                ValidateEndpoints = false // Authority endpoints are not hosted on same domain as Identity Provider.
            }
        });

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");
        var discoJsonFormatted =
            JsonSerializer.Serialize(disco.Json, new JsonSerializerOptions { WriteIndented = true });
        // _testOutputHelper.WriteLine(discoJsonFormatted);
        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint);


        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "udap-sandbox-surescripts.p12");
        var clientCert = new X509Certificate2(cert, "8nww8nni");
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
        // can prepare it the same way JwtPayLoad is essentially implemented, but more light weight
        // and specific to this Udap Dynamic Registration.
        //

        var document = new UdapDynamicClientRegistrationDocument
        {
            Issuer = "https://fhirlabs.net:7016/fhir/r4",
            Subject = "https://fhirlabs.net:7016/fhir/r4",
            Audience = regEndpoint,
            Expiration = EpochTime.GetIntDate(now.AddMinutes(5).ToUniversalTime()),
            IssuedAt = EpochTime.GetIntDate(now.ToUniversalTime()),
            JwtId = jwtId,
            ClientName = "udapTestClient",
            Contacts = new HashSet<string> { "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com" },
            GrantTypes = new HashSet<string> { "client_credentials" },
            // ResponseTypes = new HashSet<string> { "authorization_code" },  TODO: Add tests.  This should not be here when grantTypes contains client_credentials
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "system/Patient.* system/Practitioner.read"
        };


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
            Certifications = new string[0],
            Udap = UdapConstants.UdapVersionsSupportedValue
        };

        // _testOutputHelper.WriteLine(JsonSerializer.Serialize(requestBody));


        var response = await client.PostAsJsonAsync(reg, requestBody);


        // response.StatusCode.Should().Be(HttpStatusCode.Created);

        var documentAsJson = JsonSerializer.Serialize(document);
        var result = await response.Content.ReadAsStringAsync();
        // _testOutputHelper.WriteLine(result);
        // result.Should().BeEquivalentTo(documentAsJson);
    }


    [Fact]
    public async Task RegisrationSuccess_FhirLabs_Test()
    {
        var handler = new HttpClientHandler();
        //
        // Interesting discussion if you are into this sort of stuff
        // https://github.com/dotnet/runtime/issues/39835
        //
        handler.ServerCertificateCustomValidationCallback = (message, cert, chain, _) =>
        {
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(new X509Certificate2("CertStore/roots/SureFhirLabs_CA.cer"));
            chain.ChainPolicy.ExtraStore.Add(new X509Certificate2("CertStore/anchors/SureFhirLabs_Anchor.cer"));
            return chain.Build(cert);
        };

        using var fhirLabsClient = new HttpClient(handler);

        var disco = await fhirLabsClient.GetUdapDiscoveryDocumentForTaskAsync(new UdapDiscoveryDocumentRequest()
        {
            Address = "https://fhirlabs.net:7016/fhir/r4",
            Policy = new Udap.Client.Client.DiscoveryPolicy
            {
                ValidateIssuerName = false, // No issuer name in UDAP Metadata of FHIR Server.
                ValidateEndpoints = false // Authority endpoints are not hosted on same domain as Identity Provider.
            }
        });

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");
        var discoJsonFormatted =
            JsonSerializer.Serialize(disco.Json, new JsonSerializerOptions { WriteIndented = true });
        // _testOutputHelper.WriteLine(discoJsonFormatted);
        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint);

        // Get signed payload and compare registration_endpoint


        var metadata = JsonSerializer.Deserialize<UdapMetadata>(disco.Json);
        var jwt = new JwtSecurityToken(metadata.SignedMetadata);
        var tokenHeader = jwt.Header;


        // var tokenHandler = new JwtSecurityTokenHandler();

        // Update JwtSecurityToken to JsonWebTokenHandler
        // See: https://stackoverflow.com/questions/60455167/why-we-have-two-classes-for-jwt-tokens-jwtsecuritytokenhandler-vs-jsonwebtokenha
        // See: https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/945
        //
        var tokenHandler = new JsonWebTokenHandler();

        var x5CArray = JsonNode.Parse(tokenHeader.X5c)?.AsArray();
        var publicCert = new X509Certificate2(Convert.FromBase64String(x5CArray.First().ToString()));

        var validatedToken = tokenHandler.ValidateToken(metadata.SignedMetadata, new TokenValidationParameters
            {
                RequireSignedTokens = true,
                ValidateIssuer = true,
                ValidIssuers = new[]
                {
                    "https://fhirlabs.net:7016/fhir/r4"
                }, //With ValidateIssuer = true issuer is validated against this list.  Docs are not clear on this, thus this example.
                ValidateAudience = false, // No aud for UDAP metadata
                ValidateLifetime = true,
                IssuerSigningKey = new X509SecurityKey(publicCert),
                ValidAlgorithms = new[] { tokenHeader.Alg }, //must match signing algorithm
            } // , out SecurityToken validatedToken
        );

        jwt.Payload.Claims
            .Single(c => c.Type == UdapConstants.Discovery.RegistrationEndpoint)
            .Value.Should().Be(regEndpoint);

        var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");

        var manifest = _fixture.TestConfig.GetSection("UdapFileCertStoreManifest").Get<UdapFileCertStoreManifest>();

        var password = manifest.ResourceServers.Single(s => s.Name == "FhirLabsApi").Communities
            .Single(c => c.Name == "udap://surefhir.labs")
            .IssuedCerts.First().Password;



        var clientCert = new X509Certificate2(cert, password);
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
        // can prepare it the same way JwtPayLoad is essentially implemented, but more light weight
        // and specific to this Udap Dynamic Registration.
        //

        var document = new UdapDynamicClientRegistrationDocument
        {
            Issuer = "https://fhirlabs.net:7016/fhir/r4",
            Subject = "https://fhirlabs.net:7016/fhir/r4",
            Audience = regEndpoint,
            Expiration = EpochTime.GetIntDate(now.AddMinutes(5).ToUniversalTime()),
            IssuedAt = EpochTime.GetIntDate(now.ToUniversalTime()),
            JwtId = jwtId,
            ClientName = "udapTestClient",
            Contacts = new HashSet<string> { "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com" },
            GrantTypes = new HashSet<string> { "client_credentials" },
            // ResponseTypes = new HashSet<string> { "authorization_code" },  TODO: Add tests.  This should not be here when grantTypes contains client_credentials
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "system/Patient.* system/Practitioner.read"
        };
        

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
            // Certifications = new string[0],
            Udap = UdapConstants.UdapVersionsSupportedValue
        };

        // _testOutputHelper.WriteLine(JsonSerializer.Serialize(requestBody, new JsonSerializerOptions(){DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull}));

        // return;

        using var idpClient = new HttpClient(); // New client.  The existing HttpClient chains up to a CustomTrustStore 
        var response = await idpClient.PostAsJsonAsync(reg, requestBody);


        response.StatusCode.Should().Be(HttpStatusCode.Created);

        // var documentAsJson = JsonSerializer.Serialize(document);
        var result = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        // _testOutputHelper.WriteLine(JsonSerializer.Serialize(result));
        // result.Should().BeEquivalentTo(documentAsJson);

        // _testOutputHelper.WriteLine(result.ClientId);


        //
        //
        //  B2B section.  Obtain an Access Token
        //
        //

        var idpDisco = await idpClient.GetDiscoveryDocumentAsync("https://localhost:5002");

        idpDisco.IsError.Should().BeFalse(idpDisco.Error);
        



        //
        // Get Access Token
        //

        var jwtPayload = new JwtPayload(
            result.ClientId,
            disco.TokenEndpoint, //The FHIR Authorization Server's token endpoint URL
            new List<Claim>()
            {
                new Claim(JwtClaimTypes.Subject, result.ClientId),
                new Claim(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId()),
                new Claim(UdapConstants.JwtClaimTypes.Extensions, BuildHl7B2BExtensions() ) //see http://hl7.org/fhir/us/udap-security/b2b.html#constructing-authentication-token
            },
            now.ToUniversalTime(),
            now.AddMinutes(5).ToUniversalTime()
            );

        //
        // All of this is the same as above, during registration
        //
        jwtHeader = new JwtHeader
        {
            { "alg", signingCredentials.Algorithm },
            { "x5c", new[] { pem } }
        };

        signingCredentials = new SigningCredentials(securityKey, UdapConstants.SupportedAlgorithm.RS256);
        encodedHeader = jwtHeader.Base64UrlEncode();
        var encodedClientAssertion = jwtPayload.Base64UrlEncode();
        encodedSignature = JwtTokenUtilities.CreateEncodedSignature(string.Concat(encodedHeader, ".", encodedClientAssertion), signingCredentials);

        var clientAssertion = string.Concat(encodedHeader, ".", encodedClientAssertion, ".", encodedSignature);
        
        var clientRequest = new UdapClientCredentialsTokenRequest
        {
            Address = disco.TokenEndpoint,
            //ClientId = result.ClientId, we use Implicit ClientId in the iss claim
            ClientAssertion = new ClientAssertion()
            {
                Type = OidcConstants.ClientAssertionTypes.JwtBearer,
                Value = clientAssertion
            },
            Udap = UdapConstants.UdapVersionsSupportedValue
        };
        
        var tokenResponse = await idpClient.RequestClientCredentialsTokenAsync(clientRequest);

        _testOutputHelper.WriteLine(JsonSerializer.Serialize(tokenResponse));

        fhirLabsClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(TokenRequestTypes.Bearer, tokenResponse.AccessToken);
        var patientResponse = fhirLabsClient.GetAsync("https://fhirlabs.net:7016/fhir/r4/Patient");

        patientResponse.Result.EnsureSuccessStatusCode();
        _testOutputHelper.WriteLine(await patientResponse.Result.Content.ReadAsStringAsync());

    }

    private string BuildHl7B2BExtensions()
    {
        return "{\"version\": \"1\", \"subject_name\": \"todo.  more work to do here\"}";
    }
}