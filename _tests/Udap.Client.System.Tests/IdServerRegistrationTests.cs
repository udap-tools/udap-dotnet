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
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using FluentAssertions;
using IdentityModel;
using IdentityModel.Client;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Udap.Client.Client.Extensions;
using Udap.Client.Client.Messages;
using Udap.Common;
using Udap.Model;
using Udap.Model.Access;
using Udap.Model.Registration;
using Udap.Model.Statement;
using Udap.Util.Extensions;
using Xunit.Abstractions;
using static IdentityModel.OidcConstants;

namespace Udap.Client.System.Tests;

public class TestFixture
{
    public IConfigurationRoot TestConfig { get; set; }
    public UdapFileCertStoreManifest Manifest { get; set; }

    public TestFixture()
    {
        // SeedData.EnsureSeedData(
        //     "Data Source=host.docker.internal;Initial Catalog=Udap.Idp.db;User ID=udap_user;Password=udap_password1;TrustServerCertificate=True;", 
        //     new Mock<Serilog.ILogger>().Object);

        TestConfig = new ConfigurationBuilder()
            .AddUserSecrets<IdServerRegistrationTests>()
            .Build();

        Manifest = TestConfig.GetSection(Common.Constants.UDAP_FILE_STORE_MANIFEST).Get<UdapFileCertStoreManifest>()!;
    }
}

/// <summary>
/// Full Web tests.  Using Udap.Idp web server.
/// </summary>
public class IdServerRegistrationTests : IClassFixture<TestFixture>
{
    private readonly TestFixture _fixture;
    private readonly ITestOutputHelper _testOutputHelper;

    public IdServerRegistrationTests(TestFixture fixture, ITestOutputHelper testOutputHelper)
    {
        _fixture = fixture;
        _testOutputHelper = testOutputHelper;
    }

    [Fact]
    public async Task RegistrationSuccess_HealthToGo_Test()
    {
        using var fhirClient = new HttpClient();
        var disco = await fhirClient.GetUdapDiscoveryDocument(new UdapDiscoveryDocumentRequest()
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
        
        
        // Get signed payload and compare registration_endpoint
        var metadata = disco.Json.Deserialize<UdapMetadata>();
        metadata.Should().NotBeNull();

        var tokenHandler = new JsonWebTokenHandler();
        var jwt = tokenHandler.ReadJsonWebToken(metadata!.SignedMetadata);
        var publicCert = jwt?.GetPublicCertificate();

        var validatedToken = await tokenHandler.ValidateTokenAsync(metadata.SignedMetadata, new TokenValidationParameters
        {
            RequireSignedTokens = true,
            ValidateIssuer = true,
            ValidIssuers = new[]
            {
                "https://stage.healthtogo.me:8181/fhir/r4/stage"
            }, //With ValidateIssuer = true issuer is validated against this list.  Docs are not clear on this, thus this example.
            ValidateAudience = false, // No aud for UDAP metadata
            ValidateLifetime = true,
            IssuerSigningKey = new X509SecurityKey(publicCert),
            ValidAlgorithms = new[] { jwt!.GetHeaderValue<string>(Microsoft.IdentityModel.JsonWebTokens.JwtHeaderParameterNames.Alg) }, //must match signing algorithm
        });

        validatedToken.IsValid.Should().BeTrue(validatedToken.Exception?.Message);

        jwt.GetPayloadValue<string>(UdapConstants.Discovery.RegistrationEndpoint)
            .Should().Be(disco.RegistrationEndpoint);
        
        var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "udap-sandbox-surescripts.p12");

        var clientCert = new X509Certificate2(
            cert,
            _fixture.Manifest.Communities
                .Where(c => c.Name == "https://stage.healthtogo.me:8181").Single().IssuedCerts.First().Password);

        var now = DateTime.UtcNow;
        
        var document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithAudience(disco.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId() // This can be left off for HealthToGo where MEDITECH requires it and checks for replay attacks.
            .WithClientName("dotnet system test client")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Practitioner.read")
            .Build();

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build(UdapConstants.SupportedAlgorithm.RS384);

        // _testOutputHelper.WriteLine(signedSoftwareStatement);

        var requestBody = new UdapRegisterRequest
        (
           signedSoftwareStatement,
           UdapConstants.UdapVersionsSupportedValue,
           certifications: Array.Empty<string>()
        );

        var response = await fhirClient.PostAsJsonAsync(disco.RegistrationEndpoint, requestBody);

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        // var documentAsJson = JsonSerializer.Serialize(document);
        var result = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        _testOutputHelper.WriteLine("Client Registration Response::");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(result));
        _testOutputHelper.WriteLine("");
        // result.Should().BeEquivalentTo(documentAsJson);


        // _testOutputHelper.WriteLine(result.ClientId);


        //
        //
        //  B2B section.  Obtain an Access Token
        //
        //
        //_testOutputHelper.WriteLine($"Authorization Endpoint:: {result.Audience}");
        // var idpDisco = await fhirClient.GetDiscoveryDocumentAsync(disco.AuthorizeEndpoint);
        //
        // idpDisco.IsError.Should().BeFalse(idpDisco.Error);




        //
        // Get Access Token
        //

        var jwtPayload = new JwtPayLoadExtension(
            result!.ClientId,
            disco.TokenEndpoint, //The FHIR Authorization Server's token endpoint URL
            new List<Claim>()
            {
                new Claim(JwtClaimTypes.Subject, result.ClientId!),
                //TODO: this is required according to spec.  I was missing it.  We also need to assert this in IdentityServer.
                new Claim(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(),  ClaimValueTypes.Integer64),
                new Claim(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId()),
                new Claim(UdapConstants.JwtClaimTypes.Extensions, BuildHl7B2BExtensions() ) //see http://hl7.org/fhir/us/udap-security/b2b.html#constructing-authentication-token
            },
            now.ToUniversalTime(),
            now.AddMinutes(5).ToUniversalTime()
            );

        var clientAssertion =
            SignedSoftwareStatementBuilder<JwtPayLoadExtension>
                .Create(clientCert, jwtPayload)
                .Build(UdapConstants.SupportedAlgorithm.RS384);

        var clientRequest = new UdapClientCredentialsTokenRequest
        {
            Address = disco.TokenEndpoint,
            //ClientId = result.ClientId, we use Implicit ClientId in the iss claim
            ClientAssertion = new ClientAssertion()
            {
                Type = ClientAssertionTypes.JwtBearer,
                Value = clientAssertion
            },
            Udap = UdapConstants.UdapVersionsSupportedValue,
            Scope = "system/Patient.read system/Practitioner.read"
        };

        _testOutputHelper.WriteLine("Client Token Request");
        _testOutputHelper.WriteLine("---------------------");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(clientRequest));
        _testOutputHelper.WriteLine(string.Empty);
        _testOutputHelper.WriteLine(string.Empty);

        var tokenResponse = await fhirClient.UdapRequestClientCredentialsTokenAsync(clientRequest);
        
        _testOutputHelper.WriteLine("Authorization Token Response");
        _testOutputHelper.WriteLine("---------------------");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(tokenResponse));
        _testOutputHelper.WriteLine(string.Empty);
        _testOutputHelper.WriteLine(string.Empty);
        
        fhirClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(UdapConstants.TokenRequestTypes.Bearer, tokenResponse.AccessToken);
        var patientResponse = await fhirClient.GetAsync("https://stage.healthtogo.me:8181/fhir/r4/stage/Patient/1001");
        
        patientResponse.EnsureSuccessStatusCode();

        _testOutputHelper.WriteLine(await patientResponse.Content.ReadAsStringAsync());

    }

    [Fact]
    public async Task RegistrationSuccess_HealthGorilla_Test()
    {
        using var fhirClient = new HttpClient();
        var disco = await fhirClient.GetUdapDiscoveryDocument(new UdapDiscoveryDocumentRequest()
        {
            Address = "https://api-conn.qa.healthgorilla.com/unit/qhin",
            Policy = new Udap.Client.Client.DiscoveryPolicy
            {
                ValidateIssuerName = false, // No issuer name in UDAP Metadata of FHIR Server.
                ValidateEndpoints = false // Authority endpoints are not hosted on same domain as Identity Provider.
            }
        });

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");


        // Get signed payload and compare registration_endpoint
        var metadata = disco.Json.Deserialize<UdapMetadata>();
        metadata.Should().NotBeNull();

        var tokenHandler = new JsonWebTokenHandler();
        var jwt = tokenHandler.ReadJsonWebToken(metadata!.SignedMetadata);
        var publicCert = jwt!.GetPublicCertificate();

        var validatedToken = await tokenHandler.ValidateTokenAsync(metadata.SignedMetadata, new TokenValidationParameters
        {
            RequireSignedTokens = true,
            ValidateIssuer = true,
            ValidIssuers = new[]
            {
                "https://api-conn.qa.healthgorilla.com/unit/qhin"
            }, //With ValidateIssuer = true issuer is validated against this list.  Docs are not clear on this, thus this example.
            ValidateAudience = false, // No aud for UDAP metadata
            ValidateLifetime = true,
            IssuerSigningKey = new X509SecurityKey(publicCert),
            ValidAlgorithms = new[] { jwt.GetHeaderValue<string>(Microsoft.IdentityModel.JsonWebTokens.JwtHeaderParameterNames.Alg) }, //must match signing algorithm
        });

        validatedToken.IsValid.Should().BeTrue(validatedToken.Exception?.Message);

        jwt.GetPayloadValue<string>(UdapConstants.Discovery.RegistrationEndpoint)
            .Should().Be(disco.RegistrationEndpoint);

        var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "udap-sandbox-surescripts.p12");

        var clientCert = new X509Certificate2(
            cert,
            _fixture.Manifest.Communities
                .Where(c => c.Name == "https://api-conn.qa.healthgorilla.com/unit/qhin").Single().IssuedCerts.First().Password);

        var now = DateTime.UtcNow;

        var document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithAudience(disco.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("dotnet system test client")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Practitioner.read")
            .Build();

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        // _testOutputHelper.WriteLine(signedSoftwareStatement);

        var requestBody = new UdapRegisterRequest
        (
           signedSoftwareStatement,
           UdapConstants.UdapVersionsSupportedValue,
           certifications: Array.Empty<string>()
        );

        var response = await fhirClient.PostAsJsonAsync(disco.RegistrationEndpoint, requestBody);

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.StatusCode.Should().Be(HttpStatusCode.Created);

        // var documentAsJson = JsonSerializer.Serialize(document);
        var result = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        _testOutputHelper.WriteLine("Client Registration Response::");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(result));
        _testOutputHelper.WriteLine("");
        // result.Should().BeEquivalentTo(documentAsJson);


        // _testOutputHelper.WriteLine(result.ClientId);


        //
        //
        //  B2B section.  Obtain an Access Token
        //
        //
        //_testOutputHelper.WriteLine($"Authorization Endpoint:: {result.Audience}");
        // var idpDisco = await fhirClient.GetDiscoveryDocumentAsync(disco.AuthorizeEndpoint);
        //
        // idpDisco.IsError.Should().BeFalse(idpDisco.Error);




        //
        // Get Access Token
        //

        var jwtPayload = new JwtPayLoadExtension(
            result!.ClientId,
            disco.TokenEndpoint, //The FHIR Authorization Server's token endpoint URL
            new List<Claim>()
            {
                new Claim(JwtClaimTypes.Subject, result.ClientId!),
                //TODO: this is required according to spec.  I was missing it.  We also need to assert this in IdentityServer.
                new Claim(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(),  ClaimValueTypes.Integer64),
                new Claim(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId()),
                new Claim(UdapConstants.JwtClaimTypes.Extensions, BuildHl7B2BExtensions() ) //see http://hl7.org/fhir/us/udap-security/b2b.html#constructing-authentication-token
            },
            now.ToUniversalTime(),
            now.AddMinutes(5).ToUniversalTime()
            );

        var clientAssertion =
            SignedSoftwareStatementBuilder<JwtPayLoadExtension>
                .Create(clientCert, jwtPayload)
                .Build();

        var clientRequest = new UdapClientCredentialsTokenRequest
        {
            Address = disco.TokenEndpoint,
            //ClientId = result.ClientId, we use Implicit ClientId in the iss claim
            ClientAssertion = new ClientAssertion()
            {
                Type = ClientAssertionTypes.JwtBearer,
                Value = clientAssertion
            },
            Udap = UdapConstants.UdapVersionsSupportedValue,
            Scope = "system/Patient.rs system/Practitioner.read"
        };

        _testOutputHelper.WriteLine("Client Token Request");
        _testOutputHelper.WriteLine("---------------------");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(clientRequest));
        _testOutputHelper.WriteLine(string.Empty);
        _testOutputHelper.WriteLine(string.Empty);

        var tokenResponse = await fhirClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        _testOutputHelper.WriteLine("Authorization Token Response");
        _testOutputHelper.WriteLine("---------------------");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(tokenResponse));
        _testOutputHelper.WriteLine(string.Empty);
        _testOutputHelper.WriteLine(string.Empty);

        fhirClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(UdapConstants.TokenRequestTypes.Bearer, tokenResponse.AccessToken);
        var patientResponse = await fhirClient.GetAsync("https://api-conn.qa.healthgorilla.com/unit/qhin/Patient/1001");

        patientResponse.EnsureSuccessStatusCode();

        _testOutputHelper.WriteLine(await patientResponse.Content.ReadAsStringAsync());

    }

    [Fact]
    public async Task RegistrationSuccess_client_credentials_Udap_Org_Test()
    {
        using var fhirClient = new HttpClient();
        var disco = await fhirClient.GetUdapDiscoveryDocument(new UdapDiscoveryDocumentRequest()
        {
            Address = "https://test.udap.org/fhir/r4/stage",
            Policy = new Udap.Client.Client.DiscoveryPolicy
            {
                ValidateIssuerName = false, // No issuer name in UDAP Metadata of FHIR Server.
                ValidateEndpoints = false // Authority endpoints are not hosted on same domain as Identity Provider.
            }
        });

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");
        // var discoJsonFormatted =
        //     JsonSerializer.Serialize(disco.Json, new JsonSerializerOptions { WriteIndented = true });
        // _testOutputHelper.WriteLine(discoJsonFormatted);
        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint!);


        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "udap-sandbox-surescripts.p12");
        
        var clientCert = new X509Certificate2(
            cert,
            _fixture.Manifest.Communities
                .Where(c => c.Name == "https://stage.healthtogo.me:8181").Single().IssuedCerts.First().Password);
        
        //
        // Could use JwtPayload.  But because we have a typed object, UdapDynamicClientRegistrationDocument
        // I have it implementing IDictionary<string,object> so the JsonExtensions.SerializeToJson method
        // can prepare it the same way JwtPayLoad is essentially implemented, but more light weight
        // and specific to this Udap Dynamic Registration.
        //

        var document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithAudience(disco.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("dotnet system test client")
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Practitioner.read")
            .Build();

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();
        // _testOutputHelper.WriteLine(signedSoftwareStatement);


        var certifications = new List<string>();

        var certification = new UdapCertificationAndEndorsementDocument("HoboJoes Basic Interop Certification");
        certification.LogoUri = "https://avatars.githubusercontent.com/u/77421324?s=48&v=4";

        //TODO: Create a UdapCertificationAndEndorsementDocument builder to build a collection of statements
        var certificationSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapCertificationAndEndorsementDocument>
                .Create(clientCert, certification)
                .Build();

        certifications.Add(certificationSoftwareStatement);

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            // TODO assert at server.  Empty Certification is an error.  Return 400.
            // Certifications = new string[0], //do not pass an empty certification.
            UdapConstants.UdapVersionsSupportedValue,
            certifications.ToArray()
        );

        var response = await fhirClient.PostAsJsonAsync(reg, requestBody, 
            new JsonSerializerOptions{ DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull});

        var result = await response.Content.ReadAsStringAsync();
        _testOutputHelper.WriteLine(result);

        response.StatusCode.Should().Be(HttpStatusCode.Created);

    }

    [Fact(Skip = "xx")]
    public async Task RegistrationSuccess_client_credentials_NationalDirectory_Test()
    {

        using var client = new HttpClient();
        var disco = await client.GetUdapDiscoveryDocument(new UdapDiscoveryDocumentRequest()
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
        // var discoJsonFormatted =
        //     JsonSerializer.Serialize(disco.Json, new JsonSerializerOptions { WriteIndented = true });
        // _testOutputHelper.WriteLine(discoJsonFormatted);
        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint!);


        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "udap-sandbox-surescripts.p12");
        
        var clientCert = new X509Certificate2(
            cert,
            _fixture.Manifest.Communities
                .Where(c => c.Name == "https://stage.healthtogo.me:8181").Single().IssuedCerts.First().Password);

        var document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithAudience(disco.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("dotnet system test client")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Practitioner.read")
            .Build();


        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        // _testOutputHelper.WriteLine(signedSoftwareStatement);

        var requestBody = new UdapRegisterRequest
        (
           signedSoftwareStatement,
           UdapConstants.UdapVersionsSupportedValue
        );

        _testOutputHelper.WriteLine(JsonSerializer.Serialize(requestBody));
        
        var response = await client.PostAsJsonAsync(reg, requestBody);
        
        
        // response.StatusCode.Should().Be(HttpStatusCode.Created);
        
        var documentAsJson = JsonSerializer.Serialize(document);
        var result = await response.Content.ReadAsStringAsync();
        // _testOutputHelper.WriteLine(result);
        result.Should().BeEquivalentTo(documentAsJson);
    }


    [Fact(Skip = "xx")]
    public async Task RegistrationSuccess_client_credentials_ForEvernorth_Test()
    {
        using var client = new HttpClient();
        var disco = await client.GetUdapDiscoveryDocument(new UdapDiscoveryDocumentRequest()
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
        // var discoJsonFormatted =
        //     JsonSerializer.Serialize(disco.Json, new JsonSerializerOptions { WriteIndented = true });
        // _testOutputHelper.WriteLine(discoJsonFormatted);
        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint!);


        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "udap-sandbox-surescripts.p12");

        var clientCert = new X509Certificate2(
            cert,
            _fixture.Manifest.Communities
                .Where(c => c.Name == "https://stage.healthtogo.me:8181").Single().IssuedCerts.First().Password);

        var document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithAudience(disco.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("dotnet system test client")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Practitioner.read")
            .Build();


        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        // _testOutputHelper.WriteLine(signedSoftwareStatement);

        var requestBody = new UdapRegisterRequest
        (
           signedSoftwareStatement,
           UdapConstants.UdapVersionsSupportedValue
        );

        // _testOutputHelper.WriteLine(JsonSerializer.Serialize(requestBody));


        var response = await client.PostAsJsonAsync(reg, requestBody);


        // response.StatusCode.Should().Be(HttpStatusCode.Created);

        var documentAsJson = JsonSerializer.Serialize(document);
        var result = await response.Content.ReadAsStringAsync();
        // _testOutputHelper.WriteLine(result);
        result.Should().BeEquivalentTo(documentAsJson);
    }


    [Fact]
    public async Task RegistrationSuccess_client_credentials_FhirLabs_desktop_NoTokenRequestScope_Test()
    {
        using var fhirLabsClient = new HttpClient();

        var disco = await fhirLabsClient.GetUdapDiscoveryDocument(new UdapDiscoveryDocumentRequest()
        {
            Address = "https://localhost:4081/fhir/r4",
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
        _testOutputHelper.WriteLine(discoJsonFormatted);
        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint!);

        // Get signed payload and compare registration_endpoint


        var metadata = JsonSerializer.Deserialize<UdapMetadata>(disco.Json);
        var jwt = new JwtSecurityToken(metadata!.SignedMetadata);
        var tokenHeader = jwt.Header;


        // var tokenHandler = new JwtSecurityTokenHandler();

        // Update JwtSecurityToken to JsonWebTokenHandler
        // See: https://stackoverflow.com/questions/60455167/why-we-have-two-classes-for-jwt-tokens-jwtsecuritytokenhandler-vs-jsonwebtokenha
        // See: https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/945
        //
        var tokenHandler = new JsonWebTokenHandler();

        var x5CArray = JsonNode.Parse(tokenHeader.X5c)?.AsArray();
        var publicCert = new X509Certificate2(Convert.FromBase64String(x5CArray!.First()!.ToString()));

        var validatedToken = await tokenHandler.ValidateTokenAsync(metadata.SignedMetadata, new TokenValidationParameters
            {
                RequireSignedTokens = true,
                ValidateIssuer = true,
                ValidIssuers = new[]
                {
                    "https://fhirlabs.net:7016/fhir/r4",
                    "http://localhost/fhir/r4"
                }, //With ValidateIssuer = true issuer is validated against this list.  Docs are not clear on this, thus this example.
                ValidateAudience = false, // No aud for UDAP metadata
                ValidateLifetime = true,
                IssuerSigningKey = new X509SecurityKey(publicCert),
                ValidAlgorithms = new[] { tokenHeader.Alg }, //must match signing algorithm
            } // , out SecurityToken validatedToken
        );

        validatedToken.IsValid.Should().BeTrue(validatedToken.Exception?.Message);

        jwt.Payload.Claims
            .Single(c => c.Type == UdapConstants.Discovery.RegistrationEndpoint)
            .Value.Should().Be(regEndpoint);

        var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");

        var clientCert = new X509Certificate2(
            cert, 
            _fixture.Manifest.Communities
                .Where(c => c.Name == "udap://fhirlabs.net").Single().IssuedCerts.First().Password);
        
        var signedSoftwareStatement = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithAudience(disco.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("dotnet system test client")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Practitioner.read")
            .BuildSoftwareStatement();

        var jsonToken = tokenHandler.ReadToken(signedSoftwareStatement);
        var requestToken = jsonToken as JsonWebToken;
        
        
        _testOutputHelper.WriteLine("---------");

        var sb = new StringBuilder();
        sb.Append("[");
        sb.Append(Base64UrlEncoder.Decode(requestToken!.EncodedHeader));
        sb.Append(",");
        sb.Append(Base64UrlEncoder.Decode(requestToken.EncodedPayload));
        sb.Append("]");
        _testOutputHelper.WriteLine(JsonNode.Parse(sb.ToString())!.ToJsonString(new JsonSerializerOptions(){WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping}));
        _testOutputHelper.WriteLine("---------"); 
        _testOutputHelper.WriteLine(string.Empty);

        var requestBody = new UdapRegisterRequest
        (
           signedSoftwareStatement,
           UdapConstants.UdapVersionsSupportedValue
        );

        // _testOutputHelper.WriteLine(JsonSerializer.Serialize(requestBody, new JsonSerializerOptions(){DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull}));

        // return;

        using var idpClient = new HttpClient(); // New client.  The existing HttpClient chains up to a CustomTrustStore 

        var response = await idpClient.PostAsJsonAsync(reg, requestBody);

        Assert.True(response.StatusCode is HttpStatusCode.Created or HttpStatusCode.OK);
        response.Content.Headers.ContentType!.ToString().Should().Be("application/json");

        // var documentAsJson = JsonSerializer.Serialize(document);
        var result = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        _testOutputHelper.WriteLine("Client Registration Response::");
        _testOutputHelper.WriteLine("---------------------");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(result));
        _testOutputHelper.WriteLine("");
        _testOutputHelper.WriteLine("");
        // result.Should().BeEquivalentTo(documentAsJson);

        // _testOutputHelper.WriteLine(result.ClientId);


        //
        //
        //  B2B section.  Obtain an Access Token
        //
        //
        //_testOutputHelper.WriteLine($"Authorization Endpoint:: {result.Audience}");
        // var idpDisco = await idpClient.GetDiscoveryDocumentAsync(disco.AuthorizeEndpoint);
        //
        // idpDisco.IsError.Should().BeFalse(idpDisco.Error);




        //
        // Get Access Token
        //
        var now = DateTime.UtcNow;

        var jwtPayload = new JwtPayLoadExtension(
            result!.ClientId,
            disco.TokenEndpoint, //The FHIR Authorization Server's token endpoint URL
            new List<Claim>()
            {
                new Claim(JwtClaimTypes.Subject, result.ClientId!),
                new Claim(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(), ClaimValueTypes.Integer),
                new Claim(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId()),
                new Claim(UdapConstants.JwtClaimTypes.Extensions, BuildHl7B2BExtensions() ) //see http://hl7.org/fhir/us/udap-security/b2b.html#constructing-authentication-token
            },
            now.ToUniversalTime(),
            now.AddMinutes(5).ToUniversalTime()
            );

        var clientAssertion =
            SignedSoftwareStatementBuilder<JwtPayLoadExtension>
                .Create(clientCert, jwtPayload)
                .Build();

        var clientRequest = new UdapClientCredentialsTokenRequest
        {
            Address = disco.TokenEndpoint,
            //ClientId = result.ClientId, we use Implicit ClientId in the iss claim
            ClientAssertion = new ClientAssertion()
            {
                Type = ClientAssertionTypes.JwtBearer,
                Value = clientAssertion
            },
            Udap = UdapConstants.UdapVersionsSupportedValue,
            Scope = "system/Patient.rs system/Practitioner.read"
        };


        _testOutputHelper.WriteLine("Client Token Request");
        _testOutputHelper.WriteLine("---------------------");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(clientRequest));
        _testOutputHelper.WriteLine(string.Empty);
        _testOutputHelper.WriteLine(string.Empty);

        var tokenResponse = await idpClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        
        _testOutputHelper.WriteLine("Authorization Token Response");
        _testOutputHelper.WriteLine("---------------------");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(tokenResponse));
        _testOutputHelper.WriteLine(string.Empty);
        _testOutputHelper.WriteLine(string.Empty);

        fhirLabsClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(TokenRequestTypes.Bearer, tokenResponse.AccessToken);
        var patientResponse = await fhirLabsClient.GetAsync("https://localhost:7016/fhir/r4/Patient/$count-em");

        patientResponse.EnsureSuccessStatusCode();

        
        _testOutputHelper.WriteLine(await patientResponse.Content.ReadAsStringAsync());

    }

    [Fact]
    public async Task RegistrationSuccess_client_credentials_FhirLabs_desktop_WithTokenRequestScopes_Test()
    {
        var handler = new HttpClientHandler();
        //
        // Interesting discussion if you are into this sort of stuff
        // https://github.com/dotnet/runtime/issues/39835
        //
        handler.ServerCertificateCustomValidationCallback = (_, cert, chain, _) =>
        {
            chain!.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer"));
            chain.ChainPolicy.ExtraStore.Add(new X509Certificate2("CertStore/intermediates/SureFhirLabs_Intermediate.cer"));
            return chain.Build(cert!);
        };

        // using var fhirLabsClient = new HttpClient(handler);
        using var fhirLabsClient = new HttpClient();

        var disco = await fhirLabsClient.GetUdapDiscoveryDocument(new UdapDiscoveryDocumentRequest()
        {
            Address = "https://localhost:7016/fhir/r4",
            Policy = new Udap.Client.Client.DiscoveryPolicy
            {
                ValidateIssuerName = false, // No issuer name in UDAP Metadata of FHIR Server.
                ValidateEndpoints = false // Authority endpoints are not hosted on same domain as Identity Provider.
            }
        });

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");
        // var discoJsonFormatted =
        //     JsonSerializer.Serialize(disco.Json, new JsonSerializerOptions { WriteIndented = true });
        // _testOutputHelper.WriteLine(discoJsonFormatted);
        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint!);

        // Get signed payload and compare registration_endpoint


        var metadata = disco.Json.Deserialize<UdapMetadata>();
        var jwt = new JwtSecurityToken(metadata!.SignedMetadata);
        var tokenHeader = jwt.Header;


        // var tokenHandler = new JwtSecurityTokenHandler();

        // Update JwtSecurityToken to JsonWebTokenHandler
        // See: https://stackoverflow.com/questions/60455167/why-we-have-two-classes-for-jwt-tokens-jwtsecuritytokenhandler-vs-jsonwebtokenha
        // See: https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/945
        //
        var tokenHandler = new JsonWebTokenHandler();

        var x5CArray = JsonNode.Parse(tokenHeader.X5c)?.AsArray();
        var publicCert = new X509Certificate2(Convert.FromBase64String(x5CArray!.First()!.ToString()));

        var validatedToken = await tokenHandler.ValidateTokenAsync(metadata.SignedMetadata, new TokenValidationParameters
            {
                RequireSignedTokens = true,
                ValidateIssuer = true,
                ValidIssuers = new[]
                {
                    "https://fhirlabs.net:7016/fhir/r4",
                    "http://localhost/fhir/r4"
                }, //With ValidateIssuer = true issuer is validated against this list.  Docs are not clear on this, thus this example.
                ValidateAudience = false, // No aud for UDAP metadata
                ValidateLifetime = true,
                IssuerSigningKey = new X509SecurityKey(publicCert),
                ValidAlgorithms = new[] { tokenHeader.Alg }, //must match signing algorithm
            } // , out SecurityToken validatedToken
        );

        validatedToken.IsValid.Should().BeTrue(validatedToken.Exception?.Message);

        jwt.Payload.Claims
            .Single(c => c.Type == UdapConstants.Discovery.RegistrationEndpoint)
            .Value.Should().Be(regEndpoint);

        var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");

        var clientCert = new X509Certificate2(
            cert,
            _fixture.Manifest.Communities
                .Where(c => c.Name == "udap://fhirlabs.net").Single().IssuedCerts.First().Password);

        var signedSoftwareStatement = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithAudience(disco.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("dotnet system test client")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .BuildSoftwareStatement();
        
        //


        var jsonToken = tokenHandler.ReadToken(signedSoftwareStatement);
        var requestToken = jsonToken as JsonWebToken;


        _testOutputHelper.WriteLine("---------");

        var sb = new StringBuilder();
        sb.Append("[");
        sb.Append(Base64UrlEncoder.Decode(requestToken!.EncodedHeader));
        sb.Append(",");
        sb.Append(Base64UrlEncoder.Decode(requestToken.EncodedPayload));
        sb.Append("]");
        _testOutputHelper.WriteLine(JsonNode.Parse(sb.ToString())!.ToJsonString(new JsonSerializerOptions() { WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }));
        _testOutputHelper.WriteLine("---------");
        _testOutputHelper.WriteLine(string.Empty);

        var requestBody = new UdapRegisterRequest
        (
           signedSoftwareStatement,
           UdapConstants.UdapVersionsSupportedValue
        );

        // _testOutputHelper.WriteLine(JsonSerializer.Serialize(requestBody, new JsonSerializerOptions(){DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull}));

        // return;

        using var idpClient = new HttpClient(); // New client.  The existing HttpClient chains up to a CustomTrustStore 

        //TODO: When creating the new UDAP Client
        // New StringContent constructor taking a MediaTypeHeaderValue to ensure CharSet can be controlled
        // by the caller.  
        // Good historical conversations.  
        // https://github.com/dotnet/runtime/pull/63231
        // https://github.com/dotnet/runtime/issues/17036
        //
#if NET7_0_OR_GREATER
        var content = new StringContent(
            JsonSerializer.Serialize(requestBody),
            new MediaTypeHeaderValue("application/json") );
#else
        var content = new StringContent(JsonSerializer.Serialize(requestBody), null, "application/json");
        content.Headers.ContentType!.CharSet = string.Empty;
#endif
        var response = await idpClient.PostAsync(reg, content);

        // var response = await idpClient.PostAsJsonAsync(reg, requestBody);

        Assert.True(response.StatusCode is HttpStatusCode.Created or HttpStatusCode.OK);

        // var documentAsJson = JsonSerializer.Serialize(document);
        var result = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        _testOutputHelper.WriteLine("Client Registration Response::");
        _testOutputHelper.WriteLine("---------------------");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(result));
        _testOutputHelper.WriteLine("");
        _testOutputHelper.WriteLine("");
        // result.Should().BeEquivalentTo(documentAsJson);

        // _testOutputHelper.WriteLine(result.ClientId);


        //
        //
        //  B2B section.  Obtain an Access Token
        //
        //
        //_testOutputHelper.WriteLine($"Authorization Endpoint:: {result.Audience}");
        // var idpDisco = await idpClient.GetDiscoveryDocumentAsync(disco.AuthorizeEndpoint);
        //
        // idpDisco.IsError.Should().BeFalse(idpDisco.Error);




        //
        // Get Access Token
        //
        var now = DateTime.UtcNow;
        var jwtPayload = new JwtPayLoadExtension(
            result!.ClientId,
            disco.TokenEndpoint, //The FHIR Authorization Server's token endpoint URL
            new List<Claim>()
            {
                new Claim(JwtClaimTypes.Subject, result.ClientId!),
                new Claim(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(), ClaimValueTypes.Integer),
                new Claim(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId()),
                new Claim(UdapConstants.JwtClaimTypes.Extensions, BuildHl7B2BExtensions() ) //see http://hl7.org/fhir/us/udap-security/b2b.html#constructing-authentication-token
            },
            now.ToUniversalTime(),
            now.AddMinutes(5).ToUniversalTime()
            );

        var clientAssertion =
            SignedSoftwareStatementBuilder<JwtPayLoadExtension>
                .Create(clientCert, jwtPayload)
                .Build();

        var clientRequest = new UdapClientCredentialsTokenRequest
        {
            Address = disco.TokenEndpoint,
            //ClientId = result.ClientId, we use Implicit ClientId in the iss claim
            ClientAssertion = new ClientAssertion()
            {
                Type = ClientAssertionTypes.JwtBearer,
                Value = clientAssertion
            },
            Udap = UdapConstants.UdapVersionsSupportedValue,
            Scope = "system/*.rs"
        };


        _testOutputHelper.WriteLine("Client Token Request");
        _testOutputHelper.WriteLine("---------------------");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(clientRequest));
        _testOutputHelper.WriteLine(string.Empty);
        _testOutputHelper.WriteLine(string.Empty);

        var tokenResponse = await idpClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        _testOutputHelper.WriteLine("Authorization Token Response");
        _testOutputHelper.WriteLine("---------------------");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(tokenResponse));
        _testOutputHelper.WriteLine(string.Empty);
        _testOutputHelper.WriteLine(string.Empty);

        tokenResponse.Scope.Should().Be("system/*.rs");

        fhirLabsClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(TokenRequestTypes.Bearer, tokenResponse.AccessToken);
        var patientResponse = await fhirLabsClient.GetAsync("https://localhost:7016/fhir/r4/Patient/$count-em");

        patientResponse.EnsureSuccessStatusCode();


        _testOutputHelper.WriteLine(await patientResponse.Content.ReadAsStringAsync());

    }

    [Fact]
    public async Task RegistrationSuccess_authorization_code_FhirLabs_desktop_Test()
    {
        using var fhirLabsClient = new HttpClient();

        var disco = await fhirLabsClient.GetUdapDiscoveryDocument(new UdapDiscoveryDocumentRequest()
        {
            Address = "https://localhost:7016/fhir/r4",
            Policy = new Udap.Client.Client.DiscoveryPolicy
            {
                ValidateIssuerName = false, // No issuer name in UDAP Metadata of FHIR Server.
                ValidateEndpoints = false // Authority endpoints are not hosted on same domain as Identity Provider.
            }
        });

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");
        // var discoJsonFormatted =
        //     JsonSerializer.Serialize(disco.Json, new JsonSerializerOptions { WriteIndented = true });
        // _testOutputHelper.WriteLine(discoJsonFormatted);
        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint!);

        // Get signed payload and compare registration_endpoint


        var metadata = JsonSerializer.Deserialize<UdapMetadata>(disco.Json);
        var jwt = new JwtSecurityToken(metadata!.SignedMetadata);
        var tokenHeader = jwt.Header;


        // var tokenHandler = new JwtSecurityTokenHandler();

        // Update JwtSecurityToken to JsonWebTokenHandler
        // See: https://stackoverflow.com/questions/60455167/why-we-have-two-classes-for-jwt-tokens-jwtsecuritytokenhandler-vs-jsonwebtokenha
        // See: https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/945
        //
        var tokenHandler = new JsonWebTokenHandler();

        var x5CArray = JsonNode.Parse(tokenHeader.X5c)?.AsArray();
        var publicCert = new X509Certificate2(Convert.FromBase64String(x5CArray!.First()!.ToString()));

        await tokenHandler.ValidateTokenAsync(metadata.SignedMetadata, new TokenValidationParameters
            {
                RequireSignedTokens = true,
                ValidateIssuer = true,
                ValidIssuers = new[]
                {
                    "https://localhost:7016/fhir/r4"
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

        var clientCert = new X509Certificate2(
            cert,
            _fixture.Manifest.Communities
                .Where(c => c.Name == "udap://fhirlabs.net").Single().IssuedCerts.First().Password);

        var document = UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithAudience(disco.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("dotnet system test client")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            // .WithScope("user/Patient.* user/Practitioner.read") //Comment out for UDAP Server mode.
            .WithResponseTypes(new HashSet<string> { "code" })
            .WithRedirectUrls(new List<string?> { new Uri($"https://client.fhirlabs.net/redirect/{Guid.NewGuid()}").AbsoluteUri }!)
            .Build();


        document.AddClaims(new List<Claim>() {new Claim("client_uri", "http://test.com/hello/")});

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        // _testOutputHelper.WriteLine(signedSoftwareStatement);

        var requestBody = new UdapRegisterRequest
        (
           signedSoftwareStatement,
           UdapConstants.UdapVersionsSupportedValue
        );

        _testOutputHelper.WriteLine(JsonSerializer.Serialize(requestBody, new JsonSerializerOptions(){DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull}));

        // return;

        using var idpClient = new HttpClient(); // New client.  The existing HttpClient chains up to a CustomTrustStore 
        var response = await idpClient.PostAsJsonAsync(reg, requestBody);

        response.StatusCode.Should().Be(HttpStatusCode.Created);
        response.Content.Headers.ContentType!.ToString().Should().Be("application/json");

        // var documentAsJson = JsonSerializer.Serialize(document);
        var result = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        _testOutputHelper.WriteLine("Client Registration Response::");
        _testOutputHelper.WriteLine("---------------------");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(result));
        _testOutputHelper.WriteLine("");
        _testOutputHelper.WriteLine("");
        // result.Should().BeEquivalentTo(documentAsJson);

        // _testOutputHelper.WriteLine(result.ClientId);


        //
        //
        //  B2B section.  Obtain an Access Token
        //
        //
        //_testOutputHelper.WriteLine($"Authorization Endpoint:: {result.Audience}");
        // var idpDisco = await idpClient.GetDiscoveryDocumentAsync(disco.AuthorizeEndpoint);
        //
        // idpDisco.IsError.Should().BeFalse(idpDisco.Error);




        //
        // Get Access Token
        //
        var now = DateTime.UtcNow;

        var jwtPayload = new JwtPayLoadExtension(
            result!.ClientId,
            disco.TokenEndpoint, //The FHIR Authorization Server's token endpoint URL
            new List<Claim>()
            {
                new Claim(JwtClaimTypes.Subject, result.ClientId!),
                new Claim(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(), ClaimValueTypes.Integer),
                new Claim(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId()),
                new Claim(UdapConstants.JwtClaimTypes.Extensions, BuildHl7B2BExtensions() ) //see http://hl7.org/fhir/us/udap-security/b2b.html#constructing-authentication-token
            },
            now.ToUniversalTime(),
            now.AddMinutes(5).ToUniversalTime()
            );

        var clientAssertion =
            SignedSoftwareStatementBuilder<JwtPayLoadExtension>
                .Create(clientCert, jwtPayload)
                .Build();

        var clientRequest = new UdapClientCredentialsTokenRequest
        {
            Address = disco.TokenEndpoint,
            //ClientId = result.ClientId, we use Implicit ClientId in the iss claim
            ClientAssertion = new ClientAssertion()
            {
                Type = ClientAssertionTypes.JwtBearer,
                Value = clientAssertion
            },
            Udap = UdapConstants.UdapVersionsSupportedValue
        };


        _testOutputHelper.WriteLine("Client Token Request");
        _testOutputHelper.WriteLine("---------------------");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(clientRequest));
        _testOutputHelper.WriteLine(string.Empty);
        _testOutputHelper.WriteLine(string.Empty);

        //
        // Need to make a GET request to /authorize
        // Need a redirect handler.
        //

        var url = new RequestUrl(disco.AuthorizeEndpoint!).CreateAuthorizeUrl(
            clientId: result.ClientId!,
            responseType: "code",
            state: CryptoRandom.CreateUniqueId(),
            scope: "udap user.cruds",
            redirectUri: document.RedirectUris!.First());

        _testOutputHelper.WriteLine(url);

        var handler = new HttpClientHandler() { AllowAutoRedirect = false };
        var httpClient = new HttpClient(handler);

        response = await httpClient.GetAsync(url);
        
        response.StatusCode.Should().Be(HttpStatusCode.Redirect);

        var authUri = new Uri(disco.AuthorizeEndpoint!);
        var loginUrl = $"{authUri.Scheme}://{authUri.Authority}/Account/Login";
        response.Headers.Location?.ToString().Should()
            .StartWith(loginUrl);


        //
        // var tokenResponse = await idpClient.RequestClientCredentialsTokenAsync(clientRequest);
        //
        //
        // _testOutputHelper.WriteLine("Authorization Token Response");
        // _testOutputHelper.WriteLine("---------------------");
        // _testOutputHelper.WriteLine(JsonSerializer.Serialize(tokenResponse));
        // _testOutputHelper.WriteLine(string.Empty);
        // _testOutputHelper.WriteLine(string.Empty);
        //
        // fhirLabsClient.DefaultRequestHeaders.Authorization =
        //     new AuthenticationHeaderValue(TokenRequestTypes.Bearer, tokenResponse.AccessToken);
        // var patientResponse = fhirLabsClient.GetAsync("https://localhost:7016/fhir/r4/Patient/$count-em");
        //
        // patientResponse.Result.EnsureSuccessStatusCode();
        //
        //
        // _testOutputHelper.WriteLine(await patientResponse.Result.Content.ReadAsStringAsync());

    }



    //
    // IDP Server must be running in ServerSupport mode of ServerSupport.UDAP for this to fail and pass the test.
    // See part of test where getting Access Token
    // var jwtPayload = new JwtPayload(
    //    result.Issuer,
    //
    // vs normal 
    //
    // var jwtPayload = new JwtPayload(
    //   result.ClientId,
    //
    // If you want Udap.Idp to run in UDAP mode the use "ASPNETCORE_ENVIRONMENT": "Production" to launch. Or
    // however you get the serer to pickup appsettings.Production.json
    //
    [Fact]
    public async Task RequestAccessTokent_Fail_For_Issuer_client_credentials_FhirLabs_desktop_Test()
    {
        using var fhirLabsClient = new HttpClient();

        var disco = await fhirLabsClient.GetUdapDiscoveryDocument(new UdapDiscoveryDocumentRequest()
        {
            Address = "https://fhirlabs.net/fhir/r4",
            Policy = new Udap.Client.Client.DiscoveryPolicy
            {
                ValidateIssuerName = false, // No issuer name in UDAP Metadata of FHIR Server.
                ValidateEndpoints = false // Authority endpoints are not hosted on same domain as Identity Provider.
            }
        });

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");
        // var discoJsonFormatted =
        //     JsonSerializer.Serialize(disco.Json, new JsonSerializerOptions { WriteIndented = true });
        // _testOutputHelper.WriteLine(discoJsonFormatted);
        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint!);

        // Get signed payload and compare registration_endpoint


        var metadata = disco.Json.Deserialize<UdapMetadata>();
        var jwt = new JwtSecurityToken(metadata!.SignedMetadata);
        var tokenHeader = jwt.Header;


        // var tokenHandler = new JwtSecurityTokenHandler();

        // Update JwtSecurityToken to JsonWebTokenHandler
        // See: https://stackoverflow.com/questions/60455167/why-we-have-two-classes-for-jwt-tokens-jwtsecuritytokenhandler-vs-jsonwebtokenha
        // See: https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/945
        //
        var tokenHandler = new JsonWebTokenHandler();

        var x5CArray = JsonNode.Parse(tokenHeader.X5c)?.AsArray();
        var publicCert = new X509Certificate2(Convert.FromBase64String(x5CArray!.First()!.ToString()));

        await tokenHandler.ValidateTokenAsync(metadata.SignedMetadata, new TokenValidationParameters
            {
                RequireSignedTokens = true,
                ValidateIssuer = true,
                ValidIssuers = new[]
                {
                    "https://localhost:7016/fhir/r4"
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

        var clientCert = new X509Certificate2(
            cert,
            _fixture.Manifest.Communities
                .Where(c => c.Name == "udap://fhirlabs.net").Single().IssuedCerts.First().Password);

        var document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithAudience(disco.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("dotnet system test client")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .Build();

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        // _testOutputHelper.WriteLine(signedSoftwareStatement);

        var requestBody = new UdapRegisterRequest
        (
           signedSoftwareStatement,
           UdapConstants.UdapVersionsSupportedValue
        );

        // _testOutputHelper.WriteLine(JsonSerializer.Serialize(requestBody, new JsonSerializerOptions(){DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull}));

        // return;

        using var idpClient = new HttpClient(); // New client.  The existing HttpClient chains up to a CustomTrustStore 
        var response = await idpClient.PostAsJsonAsync(reg, requestBody);


        response.StatusCode.Should().Be(HttpStatusCode.Created);

        // var documentAsJson = JsonSerializer.Serialize(document);
        var result = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        _testOutputHelper.WriteLine("Client Registration Response::");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(result));
        _testOutputHelper.WriteLine("");
        // result.Should().BeEquivalentTo(documentAsJson);

        // _testOutputHelper.WriteLine(result.ClientId);


        //
        //
        //  B2B section.  Obtain an Access Token
        //
        //
        //_testOutputHelper.WriteLine($"Authorization Endpoint:: {result.Audience}");
        // var idpDisco = await idpClient.GetDiscoveryDocumentAsync(disco.AuthorizeEndpoint);
        //
        // idpDisco.IsError.Should().BeFalse(idpDisco.Error);




        //
        // Get Access Token
        //
        var now = DateTime.UtcNow;

        var jwtPayload = new JwtPayLoadExtension(
            "http://invalidissuer.net/",
            disco.TokenEndpoint, //The FHIR Authorization Server's token endpoint URL
            new List<Claim>()
            {
                new Claim(JwtClaimTypes.Subject, result!.ClientId!),
                new Claim(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(), ClaimValueTypes.Integer),
                new Claim(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId()),
                new Claim(UdapConstants.JwtClaimTypes.Extensions, BuildHl7B2BExtensions() ) //see http://hl7.org/fhir/us/udap-security/b2b.html#constructing-authentication-token
            },
            now.ToUniversalTime(),
            now.AddMinutes(5).ToUniversalTime()
            );

        var clientAssertion =
            SignedSoftwareStatementBuilder<JwtPayLoadExtension>
                .Create(clientCert, jwtPayload)
                .Build();

        var clientRequest = new UdapClientCredentialsTokenRequest
        {
            Address = disco.TokenEndpoint,
            //ClientId = result.ClientId, we use Implicit ClientId in the iss claim
            ClientAssertion = new ClientAssertion()
            {
                Type = ClientAssertionTypes.JwtBearer,
                Value = clientAssertion
            },
            Udap = UdapConstants.UdapVersionsSupportedValue
        };


        _testOutputHelper.WriteLine("Client Token Request");
        _testOutputHelper.WriteLine("---------------------");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(clientRequest));
        _testOutputHelper.WriteLine(string.Empty);
        _testOutputHelper.WriteLine(string.Empty);


        var tokenResponse = await idpClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        
        _testOutputHelper.WriteLine("Authorization Token Response");
        _testOutputHelper.WriteLine("---------------------");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(tokenResponse));
        _testOutputHelper.WriteLine(string.Empty);
        _testOutputHelper.WriteLine(string.Empty);

        tokenResponse.IsError.Should().BeTrue();
        
    }

    [Fact]
    public async Task RegistrationSuccess_client_credentials_FhirLabs_LIVE_Test()
    {
        using var fhirLabsClient = new HttpClient();

        var disco = await fhirLabsClient.GetUdapDiscoveryDocument(new UdapDiscoveryDocumentRequest()
        {
            Address = "https://fhirlabs.net/fhir/r4",
            Policy = new Udap.Client.Client.DiscoveryPolicy
            {
                ValidateIssuerName = false, // No issuer name in UDAP Metadata of FHIR Server.
                ValidateEndpoints = false // Authority endpoints are not hosted on same domain as Identity Provider.
            },
            Community = "udap://fhirlabs.net"
        });

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");
        

        // Get signed payload and compare registration_endpoint
        var metadata = disco.Json.Deserialize<UdapMetadata>();
        metadata.Should().NotBeNull();

        // Update JwtSecurityToken to JsonWebTokenHandler
        // See: https://stackoverflow.com/questions/60455167/why-we-have-two-classes-for-jwt-tokens-jwtsecuritytokenhandler-vs-jsonwebtokenha
        // See: https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/945
        //
        var tokenHandler = new JsonWebTokenHandler();
        var jwt = tokenHandler.ReadJsonWebToken(metadata!.SignedMetadata);
        var publicCert = jwt!.GetPublicCertificate();

        // var subAltNames = publicCert.GetSubjectAltNames();
        var validatedToken = await tokenHandler.ValidateTokenAsync(metadata.SignedMetadata, new TokenValidationParameters
        {
            RequireSignedTokens = true,
            ValidateIssuer = true,
            ValidIssuers = new[]
            {
                "https://fhirlabs.net/fhir/r4"
            }, //With ValidateIssuer = true issuer is validated against this list.  Docs are not clear on this, thus this example.
            ValidateAudience = false, // No aud for UDAP metadata
            ValidateLifetime = true,
            IssuerSigningKey = new X509SecurityKey(publicCert),
            ValidAlgorithms = new[] { jwt.GetHeaderValue<string>(Microsoft.IdentityModel.JsonWebTokens.JwtHeaderParameterNames.Alg) }, //must match signing algorithm
        });

        validatedToken.IsValid.Should().BeTrue(validatedToken.Exception?.Message);

        jwt.GetPayloadValue<string>(UdapConstants.Discovery.RegistrationEndpoint)
            .Should().Be(disco.RegistrationEndpoint);

        var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");

        var clientCert = new X509Certificate2(
            cert,
            _fixture.Manifest.Communities
                .Where(c => c.Name == "udap://fhirlabs.net").Single().IssuedCerts.First().Password);

        var document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithAudience(disco.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("dotnet system test client")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Practitioner.read")
            .Build();

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build(UdapConstants.SupportedAlgorithm.RS384);

        // _testOutputHelper.WriteLine(signedSoftwareStatement);

        var requestBody = new UdapRegisterRequest
        (
           signedSoftwareStatement,
           UdapConstants.UdapVersionsSupportedValue
        );

        // _testOutputHelper.WriteLine(JsonSerializer.Serialize(requestBody, new JsonSerializerOptions(){DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull}));

        // return;

        using var idpClient = new HttpClient(); // New client.  The existing HttpClient chains up to a CustomTrustStore 
        var response = await idpClient.PostAsJsonAsync(disco.RegistrationEndpoint, requestBody);

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.Content.Headers.ContentType!.ToString().Should().Be("application/json");
        response.EnsureSuccessStatusCode();

        // var documentAsJson = JsonSerializer.Serialize(document);
        var result = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        _testOutputHelper.WriteLine("Client Registration Response::");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(result));
        _testOutputHelper.WriteLine("");
        // result.Should().BeEquivalentTo(documentAsJson);

        // _testOutputHelper.WriteLine(result.ClientId);


        //
        //
        //  B2B section.  Obtain an Access Token
        //
        //
        _testOutputHelper.WriteLine($"Authorization Endpoint:: {result!.Audience}");
        // var idpDisco = await idpClient.GetDiscoveryDocumentAsync(disco.AuthorizeEndpoint);
        //
        // idpDisco.IsError.Should().BeFalse(idpDisco.Error);




        //
        // Get Access Token
        //
        var now = DateTime.UtcNow;

        var jwtPayload = new JwtPayLoadExtension(
            result.ClientId,
            disco.TokenEndpoint, //The FHIR Authorization Server's token endpoint URL
            new List<Claim>()
            {
                new Claim(JwtClaimTypes.Subject, result.ClientId!),
                new Claim(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(), ClaimValueTypes.Integer),
                new Claim(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId()),
                new Claim(UdapConstants.JwtClaimTypes.Extensions, BuildHl7B2BExtensions() ) //see http://hl7.org/fhir/us/udap-security/b2b.html#constructing-authentication-token
            },
            now.ToUniversalTime(),
            now.AddMinutes(5).ToUniversalTime()
            );

        var clientAssertion =
            SignedSoftwareStatementBuilder<JwtPayLoadExtension>
                .Create(clientCert, jwtPayload)
                .Build(UdapConstants.SupportedAlgorithm.RS384);

        var clientRequest = new UdapClientCredentialsTokenRequest
        {
            Address = disco.TokenEndpoint,
            //ClientId = result.ClientId, we use Implicit ClientId in the iss claim
            ClientAssertion = new ClientAssertion()
            {
                Type = ClientAssertionTypes.JwtBearer,
                Value = clientAssertion
            },
            Udap = UdapConstants.UdapVersionsSupportedValue
        };


        _testOutputHelper.WriteLine("Client Token Request");
        _testOutputHelper.WriteLine("---------------------");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(clientRequest));
        _testOutputHelper.WriteLine(string.Empty);
        _testOutputHelper.WriteLine(string.Empty);


        var tokenResponse = await idpClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        _testOutputHelper.WriteLine("Authorization Token Response");
        _testOutputHelper.WriteLine("---------------------");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(tokenResponse));
        _testOutputHelper.WriteLine(string.Empty);
        _testOutputHelper.WriteLine(string.Empty);

        
        fhirLabsClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(TokenRequestTypes.Bearer, tokenResponse.AccessToken);
        var patientResponse = await fhirLabsClient.GetAsync("https://fhirlabs.net/fhir/r4/Patient/$count-em");

        patientResponse.EnsureSuccessStatusCode();

        _testOutputHelper.WriteLine(await patientResponse.Content.ReadAsStringAsync());

    }

    [Fact]
    public async Task RegistrationSuccess_authorization_code_FhirLabs_LIVE_Test()
    {
        var handler = new HttpClientHandler();
        //
        // Interesting discussion if you are into this sort of stuff
        // https://github.com/dotnet/runtime/issues/39835
        //
        handler.ServerCertificateCustomValidationCallback = (_, cert, chain, _) =>
        {
            chain!.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer"));
            chain.ChainPolicy.ExtraStore.Add(new X509Certificate2("CertStore/intermediates/SureFhirLabs_Intermediate.cer"));
            return chain.Build(cert!);
        };

        // using var fhirLabsClient = new HttpClient(handler);
        using var fhirLabsClient = new HttpClient();

        var disco = await fhirLabsClient.GetUdapDiscoveryDocument(new UdapDiscoveryDocumentRequest()
        {
            Address = "https://fhirlabs.net/fhir/r4",
            Policy = new Udap.Client.Client.DiscoveryPolicy
            {
                ValidateIssuerName = false, // No issuer name in UDAP Metadata of FHIR Server.
                ValidateEndpoints = false // Authority endpoints are not hosted on same domain as Identity Provider.
            }
        });

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");
        // var discoJsonFormatted =
        //     JsonSerializer.Serialize(disco.Json, new JsonSerializerOptions { WriteIndented = true });
        // _testOutputHelper.WriteLine(discoJsonFormatted);
        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint!);

        // Get signed payload and compare registration_endpoint


        var metadata = JsonSerializer.Deserialize<UdapMetadata>(disco.Json);
        var jwt = new JwtSecurityToken(metadata!.SignedMetadata);
        var tokenHeader = jwt.Header;


        // var tokenHandler = new JwtSecurityTokenHandler();

        // Update JwtSecurityToken to JsonWebTokenHandler
        // See: https://stackoverflow.com/questions/60455167/why-we-have-two-classes-for-jwt-tokens-jwtsecuritytokenhandler-vs-jsonwebtokenha
        // See: https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/945
        //
        var tokenHandler = new JsonWebTokenHandler();

        var x5CArray = JsonNode.Parse(tokenHeader.X5c)?.AsArray();
        var publicCert = new X509Certificate2(Convert.FromBase64String(x5CArray!.First()!.ToString()));

        await tokenHandler.ValidateTokenAsync(metadata.SignedMetadata, new TokenValidationParameters
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

        var clientCert = new X509Certificate2(
            cert,
            _fixture.Manifest.Communities
                .Where(c => c.Name == "udap://fhirlabs.net").Single().IssuedCerts.First().Password);

        var redirectUrls = new List<string?>
            { new Uri($"https://client.fhirlabs.net/redirect/{Guid.NewGuid()}").AbsoluteUri };

        var signedSoftwareStatement = UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithAudience(disco.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("dotnet system test client")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("user/Patient.* user/Practitioner.read")
            .WithResponseTypes(new HashSet<string> { "code" })
            .WithRedirectUrls(redirectUrls!)
            .BuildSoftwareStatement();

        
        // _testOutputHelper.WriteLine(signedSoftwareStatement);

        var requestBody = new UdapRegisterRequest
        (
           signedSoftwareStatement,
           UdapConstants.UdapVersionsSupportedValue
        );

        // _testOutputHelper.WriteLine(JsonSerializer.Serialize(requestBody, new JsonSerializerOptions(){DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull}));

        // return;

        using var idpClient = new HttpClient(); // New client.  The existing HttpClient chains up to a CustomTrustStore 
        var response = await idpClient.PostAsJsonAsync(reg, requestBody);

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.StatusCode.Should().Be(HttpStatusCode.Created);
        response.Content.Headers.ContentType!.ToString().Should().Be("application/json");

        // var documentAsJson = JsonSerializer.Serialize(document);
        var result = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        _testOutputHelper.WriteLine("Client Registration Response::");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(result));
        _testOutputHelper.WriteLine("");
        // result.Should().BeEquivalentTo(documentAsJson);

        // _testOutputHelper.WriteLine(result.ClientId);


        //
        //
        //  B2B section.  Obtain an Access Token
        //
        //
        //_testOutputHelper.WriteLine($"Authorization Endpoint:: {result.Audience}");
        // var idpDisco = await idpClient.GetDiscoveryDocumentAsync(disco.AuthorizeEndpoint);
        //
        // idpDisco.IsError.Should().BeFalse(idpDisco.Error);




        //
        // Get Access Token
        //
        var now = DateTime.UtcNow;

        var jwtPayload = new JwtPayLoadExtension(
            result!.ClientId,
            disco.TokenEndpoint, //The FHIR Authorization Server's token endpoint URL
            new List<Claim>()
            {
                new Claim(JwtClaimTypes.Subject, result.ClientId!),
                new Claim(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(), ClaimValueTypes.Integer),
                new Claim(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId()),
                new Claim(UdapConstants.JwtClaimTypes.Extensions, BuildHl7B2BExtensions() ) //see http://hl7.org/fhir/us/udap-security/b2b.html#constructing-authentication-token
            },
            now.ToUniversalTime(),
            now.AddMinutes(5).ToUniversalTime()
            );

        var clientAssertion =
            SignedSoftwareStatementBuilder<JwtPayLoadExtension>
                .Create(clientCert, jwtPayload)
                .Build();

        var clientRequest = new UdapClientCredentialsTokenRequest
        {
            Address = disco.TokenEndpoint,
            //ClientId = result.ClientId, we use Implicit ClientId in the iss claim
            ClientAssertion = new ClientAssertion()
            {
                Type = ClientAssertionTypes.JwtBearer,
                Value = clientAssertion
            },
            Udap = UdapConstants.UdapVersionsSupportedValue,
            Scope = "user/Patient.* user/Practitioner.read"
        };

        
        _testOutputHelper.WriteLine("Client Token Request");
        _testOutputHelper.WriteLine("---------------------");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(clientRequest));
        _testOutputHelper.WriteLine(string.Empty);
        _testOutputHelper.WriteLine(string.Empty);

        var url = new RequestUrl(disco.AuthorizeEndpoint!).CreateAuthorizeUrl(
            clientId: result.ClientId!,
            responseType: "code",
            state: CryptoRandom.CreateUniqueId(),
            scope: result.Scope,
            redirectUri: redirectUrls.First());

        handler = new HttpClientHandler() { AllowAutoRedirect = false };
        var httpClient = new HttpClient(handler);

        response = await httpClient.GetAsync(url);

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);


        //
        //
        // var tokenResponse = await idpClient.RequestClientCredentialsTokenAsync(clientRequest);
        //
        // _testOutputHelper.WriteLine("Authorization Token Response");
        // _testOutputHelper.WriteLine("---------------------");
        // _testOutputHelper.WriteLine(JsonSerializer.Serialize(tokenResponse));
        // _testOutputHelper.WriteLine(string.Empty);
        // _testOutputHelper.WriteLine(string.Empty);
        //
        // fhirLabsClient.DefaultRequestHeaders.Authorization =
        //     new AuthenticationHeaderValue(TokenRequestTypes.Bearer, tokenResponse.AccessToken);
        // var patientResponse = fhirLabsClient.GetAsync("https://fhirlabs.net/fhir/r4/Patient/$count-em");
        //
        // patientResponse.Result.EnsureSuccessStatusCode();
        //
        // _testOutputHelper.WriteLine(await patientResponse.Result.Content.ReadAsStringAsync());

    }
    [Fact]
    public async Task RegistrationMissingScope_client_credentials_FhirLabs_desktop_Test()
    {
        using var fhirLabsClient = new HttpClient();

        var disco = await fhirLabsClient.GetUdapDiscoveryDocument(new UdapDiscoveryDocumentRequest()
        {
            Address = "https://localhost:7016/fhir/r4",
            Policy = new Udap.Client.Client.DiscoveryPolicy
            {
                ValidateIssuerName = false, // No issuer name in UDAP Metadata of FHIR Server.
                ValidateEndpoints = false // Authority endpoints are not hosted on same domain as Identity Provider.
            },
            Community = "udap://fhirlabs.net"
        });

        disco.HttpResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        disco.IsError.Should().BeFalse($"{disco.Error} :: {disco.HttpErrorReason}");
        
        // var discoJsonFormatted =
        //     JsonSerializer.Serialize(disco.Json, new JsonSerializerOptions { WriteIndented = true });
        // _testOutputHelper.WriteLine(discoJsonFormatted);
        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint!);

        // Get signed payload and compare registration_endpoint


        var metadata = JsonSerializer.Deserialize<UdapMetadata>(disco.Json);
        var jwt = new JwtSecurityToken(metadata!.SignedMetadata);
        var tokenHeader = jwt.Header;


        // var tokenHandler = new JwtSecurityTokenHandler();

        // Update JwtSecurityToken to JsonWebTokenHandler
        // See: https://stackoverflow.com/questions/60455167/why-we-have-two-classes-for-jwt-tokens-jwtsecuritytokenhandler-vs-jsonwebtokenha
        // See: https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/945
        //
        var tokenHandler = new JsonWebTokenHandler();

        var x5CArray = JsonNode.Parse(tokenHeader.X5c)?.AsArray();
        var publicCert = new X509Certificate2(Convert.FromBase64String(x5CArray!.First()!.ToString()));

        var validatedToken = await tokenHandler.ValidateTokenAsync(metadata.SignedMetadata, new TokenValidationParameters
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

        validatedToken.IsValid.Should().BeTrue();

        jwt.Payload.Claims
            .Single(c => c.Type == UdapConstants.Discovery.RegistrationEndpoint)
            .Value.Should().Be(regEndpoint);

        var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");

        var clientCert = new X509Certificate2(
            cert,
            _fixture.Manifest.Communities
                .Where(c => c.Name == "udap://fhirlabs.net").Single().IssuedCerts.First().Password);

        var document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithAudience(disco.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("dotnet system test client")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .Build();

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        // _testOutputHelper.WriteLine(signedSoftwareStatement);

        var requestBody = new UdapRegisterRequest
        (
           signedSoftwareStatement,
           UdapConstants.UdapVersionsSupportedValue
        );

        // _testOutputHelper.WriteLine(JsonSerializer.Serialize(requestBody, new JsonSerializerOptions(){DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull}));

        // return;

        using var idpClient = new HttpClient(); // New client.  The existing HttpClient chains up to a CustomTrustStore 
        var response = await idpClient.PostAsJsonAsync(reg, requestBody);

        var result = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        _testOutputHelper.WriteLine("Client Registration Response::");
        _testOutputHelper.WriteLine("---------------------");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(result));
        _testOutputHelper.WriteLine("");
        _testOutputHelper.WriteLine("");



        // IF YOU RUN IN HL7 MODE /////////////////////////////////
        // response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        // var errorResponse = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();
        // errorResponse!.Error.Should().Be(UdapDynamicClientRegistrationErrors.InvalidClientMetadata);
        // errorResponse.ErrorDescription.Should().Be("scope is required");
        /////////////////////////////////




        //
        // Get Access Token
        //
        var now = DateTime.UtcNow;

        var jwtPayload = new JwtPayLoadExtension(
            result!.ClientId,
            disco.TokenEndpoint, //The FHIR Authorization Server's token endpoint URL
            new List<Claim>()
            {
                new Claim(JwtClaimTypes.Subject, result.ClientId!),
                new Claim(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(), ClaimValueTypes.Integer),
                new Claim(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId()),
                new Claim(UdapConstants.JwtClaimTypes.Extensions, BuildHl7B2BExtensions() ) //see http://hl7.org/fhir/us/udap-security/b2b.html#constructing-authentication-token
            },
            now.ToUniversalTime(),
            now.AddMinutes(5).ToUniversalTime()
            );

        var clientAssertion =
            SignedSoftwareStatementBuilder<JwtPayLoadExtension>
                .Create(clientCert, jwtPayload)
                .Build();

        var clientRequest = new UdapClientCredentialsTokenRequest
        {
            Address = disco.TokenEndpoint,
            //ClientId = result.ClientId, we use Implicit ClientId in the iss claim
            ClientAssertion = new ClientAssertion()
            {
                Type = ClientAssertionTypes.JwtBearer,
                Value = clientAssertion
            },
            Udap = UdapConstants.UdapVersionsSupportedValue
        };


        _testOutputHelper.WriteLine("Client Token Request");
        _testOutputHelper.WriteLine("---------------------");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(clientRequest));
        _testOutputHelper.WriteLine(string.Empty);
        _testOutputHelper.WriteLine(string.Empty);

        var tokenResponse = await idpClient.UdapRequestClientCredentialsTokenAsync(clientRequest);


        _testOutputHelper.WriteLine("Authorization Token Response");
        _testOutputHelper.WriteLine("---------------------");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(tokenResponse));
        _testOutputHelper.WriteLine(string.Empty);
        _testOutputHelper.WriteLine(string.Empty);

        fhirLabsClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(TokenRequestTypes.Bearer, tokenResponse.AccessToken);
        var patientResponse = await fhirLabsClient.GetAsync("https://localhost:7016/fhir/r4/Patient/$count-em");

        patientResponse.EnsureSuccessStatusCode();


        _testOutputHelper.WriteLine(await patientResponse.Content.ReadAsStringAsync());
    }

    private string BuildHl7B2BExtensions()
    {
        return "{\"version\": \"1\", \"subject_name\": \"todo.  more work to do here\"}";
    }
}