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
using Udap.Model.Registration;
using Udap.Util.Extensions;
using Xunit.Abstractions;
using static IdentityModel.OidcConstants;

namespace Udap.Client.Integration.Tests;

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

        Manifest = TestConfig.GetSection("UdapFileCertStoreManifest").Get<UdapFileCertStoreManifest>();
    }
}

/// <summary>
/// Full Web tests.  Using <see cref="Udap.Idp"/> web server.
/// </summary>
public class IdServerRegistrationTests : IClassFixture<TestFixture>
{
    private TestFixture _fixture;
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
        // var discoJsonFormatted =
        //     JsonSerializer.Serialize(disco.Json, new JsonSerializerOptions { WriteIndented = true });
        // _testOutputHelper.WriteLine(discoJsonFormatted);
        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint);


        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "udap-sandbox-surescripts.p12");

        var clientCert = new X509Certificate2(
            cert,
            _fixture.Manifest.ResourceServers.First().Communities
                .Where(c => c.Name == "https://stage.healthtogo.me:8181").Single().IssuedCerts.First().Password);

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
            // Certifications = new string[0], JWS compact serialization
            Udap = UdapConstants.UdapVersionsSupportedValue
        };

        var response = await fhirClient.PostAsJsonAsync(reg, requestBody);

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

        var jwtPayload = new JwtPayload(
            result.ClientId,
            disco.TokenEndpoint, //The FHIR Authorization Server's token endpoint URL
            new List<Claim>()
            {
                new Claim(JwtClaimTypes.Subject, result.ClientId),
                //TODO: this is required according to spec.  I was missing it.  We also need to assert this in IdentityServer.
                new Claim(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(),  ClaimValueTypes.Integer64),
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
            Udap = UdapConstants.UdapVersionsSupportedValue,
            Scope = "system/Patient.* system/Practitioner.read"
        };

        _testOutputHelper.WriteLine("Client Token Request");
        _testOutputHelper.WriteLine("---------------------");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(clientRequest));
        _testOutputHelper.WriteLine(string.Empty);
        _testOutputHelper.WriteLine(string.Empty);

        var tokenResponse = await fhirClient.RequestClientCredentialsTokenAsync(clientRequest);
        
        _testOutputHelper.WriteLine("Authorization Token Response");
        _testOutputHelper.WriteLine("---------------------");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(tokenResponse));
        _testOutputHelper.WriteLine(string.Empty);
        _testOutputHelper.WriteLine(string.Empty);
        
        fhirClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(UdapConstants.TokenRequestTypes.Bearer, tokenResponse.AccessToken);
        var patientResponse = fhirClient.GetAsync("https://stage.healthtogo.me:8181/fhir/r4/stage/Patient/1001");
        
        patientResponse.Result.EnsureSuccessStatusCode();

        _testOutputHelper.WriteLine(await patientResponse.Result.Content.ReadAsStringAsync());

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
        var reg = new Uri(regEndpoint);


        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "udap-sandbox-surescripts.p12");
        
        var clientCert = new X509Certificate2(
            cert,
            _fixture.Manifest.ResourceServers.First().Communities
                .Where(c => c.Name == "https://stage.healthtogo.me:8181").Single().IssuedCerts.First().Password);

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
            Scope = "system/Patient.* system/Practitioner.read",
            LogoUri = new Uri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
    };


        var encodedHeader = jwtHeader.Base64UrlEncode();
        var encodedPayload = document.Base64UrlEncode();
        var encodedSignature =
            JwtTokenUtilities.CreateEncodedSignature(string.Concat(encodedHeader, ".", encodedPayload),
                signingCredentials);
        var signedSoftwareStatement = string.Concat(encodedHeader, ".", encodedPayload, ".", encodedSignature);
        // _testOutputHelper.WriteLine(signedSoftwareStatement);

        var certifications = new List<string>();

        var certifiations = new UdapCertificationAndEndorsementDocument("HoboJoes Basic Interop Certification");
        certifiations.LogoUri = "https://avatars.githubusercontent.com/u/77421324?s=48&v=4";


        var certificationsPayloadEncoded = certifiations.Base64UrlEncode();

        var encodedCertificationSignature =
            JwtTokenUtilities.CreateEncodedSignature(string.Concat(encodedHeader, ".", certificationsPayloadEncoded),
                signingCredentials);

        var signedCertification = string.Concat(encodedHeader, ".", certificationsPayloadEncoded, ".", encodedCertificationSignature);
        certifications.Add(signedCertification);

        var requestBody = new UdapRegisterRequest
        {
            SoftwareStatement = signedSoftwareStatement,
            // TODO assert at server.  Empty Certification is an error.  Return 400.
            // Certifications = new string[0], //do not pass an empty certification.
            Certifications = certifications.ToArray(),
            Udap = UdapConstants.UdapVersionsSupportedValue,
        };

        var response = await fhirClient.PostAsJsonAsync(reg, requestBody);

        //TODO: Server should return specific formatted error message.  Example
        //
        // I think this is normal for the test tool my Report indicates I passed all tests.
        // {"error_description":"invalid registration metadata; see test report","error":"invalid_client_metadata"}
        //
        /// https://www.udap.org/udap-dynamic-client-registration-stu1.html#section-5.2
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
        var discoJsonFormatted =
            JsonSerializer.Serialize(disco.Json, new JsonSerializerOptions { WriteIndented = true });
        // _testOutputHelper.WriteLine(discoJsonFormatted);
        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint);


        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "udap-sandbox-surescripts.p12");
        
        var clientCert = new X509Certificate2(
            cert,
            _fixture.Manifest.ResourceServers.First().Communities
                .Where(c => c.Name == "https://stage.healthtogo.me:8181").Single().IssuedCerts.First().Password);

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
            // Certifications = new string[0], JWS compact serialization
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
        var discoJsonFormatted =
            JsonSerializer.Serialize(disco.Json, new JsonSerializerOptions { WriteIndented = true });
        // _testOutputHelper.WriteLine(discoJsonFormatted);
        var regEndpoint = disco.RegistrationEndpoint;
        var reg = new Uri(regEndpoint);


        var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"),
            "udap-sandbox-surescripts.p12");

        var clientCert = new X509Certificate2(
            cert,
            _fixture.Manifest.ResourceServers.First().Communities
                .Where(c => c.Name == "https://stage.healthtogo.me:8181").Single().IssuedCerts.First().Password);

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
            // Certifications = new string[0], JWS compact serialization
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
    public async Task RegistrationSuccess_client_credentials_FhirLabs_desktop_NoTokenRequestScope_Test()
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
            _fixture.Manifest.ResourceServers.First().Communities
                .Where(c => c.Name == "udap://surefhir.labs").Single().IssuedCerts.First().Password);
        
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
        //
        

        var jsonToken = tokenHandler.ReadToken(signedSoftwareStatement);
        var requestToken = jsonToken as JsonWebToken;
        
        
        _testOutputHelper.WriteLine("---------");

        var sb = new StringBuilder();
        sb.Append("[");
        sb.Append(Base64UrlEncoder.Decode(requestToken.EncodedHeader));
        sb.Append(",");
        sb.Append(Base64UrlEncoder.Decode(requestToken.EncodedPayload));
        sb.Append("]");
        _testOutputHelper.WriteLine(JsonObject.Parse(sb.ToString()).ToJsonString(new JsonSerializerOptions(){WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping}));
        _testOutputHelper.WriteLine("---------"); 
        _testOutputHelper.WriteLine(string.Empty);

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

        var jwtPayload = new JwtPayload(
            result.ClientId,
            disco.TokenEndpoint, //The FHIR Authorization Server's token endpoint URL
            new List<Claim>()
            {
                new Claim(JwtClaimTypes.Subject, result.ClientId),
                new Claim(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(), ClaimValueTypes.Integer),
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
            Udap = UdapConstants.UdapVersionsSupportedValue,
            Scope = "system/Patient.* system/Practitioner.read"
        };


        _testOutputHelper.WriteLine("Client Token Request");
        _testOutputHelper.WriteLine("---------------------");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(clientRequest));
        _testOutputHelper.WriteLine(string.Empty);
        _testOutputHelper.WriteLine(string.Empty);

        var tokenResponse = await idpClient.RequestClientCredentialsTokenAsync(clientRequest);

        
        _testOutputHelper.WriteLine("Authorization Token Response");
        _testOutputHelper.WriteLine("---------------------");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(tokenResponse));
        _testOutputHelper.WriteLine(string.Empty);
        _testOutputHelper.WriteLine(string.Empty);

        fhirLabsClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(TokenRequestTypes.Bearer, tokenResponse.AccessToken);
        var patientResponse = fhirLabsClient.GetAsync("https://localhost:7016/fhir/r4/Patient/$count-em");

        patientResponse.Result.EnsureSuccessStatusCode();

        
        _testOutputHelper.WriteLine(await patientResponse.Result.Content.ReadAsStringAsync());

    }

    [Fact]
    public async Task RegistrationSuccess_client_credentials_FhirLabs_desktop_WithTokenRequestScopes_Test()
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
            _fixture.Manifest.ResourceServers.First().Communities
                .Where(c => c.Name == "udap://surefhir.labs").Single().IssuedCerts.First().Password);

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
            // Scope = "system/Patient.* system/Practitioner.read"
        };


        var encodedHeader = jwtHeader.Base64UrlEncode();
        var encodedPayload = document.Base64UrlEncode();
        var encodedSignature =
            JwtTokenUtilities.CreateEncodedSignature(string.Concat(encodedHeader, ".", encodedPayload),
                signingCredentials);
        var signedSoftwareStatement = string.Concat(encodedHeader, ".", encodedPayload, ".", encodedSignature);
        //


        var jsonToken = tokenHandler.ReadToken(signedSoftwareStatement);
        var requestToken = jsonToken as JsonWebToken;


        _testOutputHelper.WriteLine("---------");

        var sb = new StringBuilder();
        sb.Append("[");
        sb.Append(Base64UrlEncoder.Decode(requestToken.EncodedHeader));
        sb.Append(",");
        sb.Append(Base64UrlEncoder.Decode(requestToken.EncodedPayload));
        sb.Append("]");
        _testOutputHelper.WriteLine(JsonObject.Parse(sb.ToString()).ToJsonString(new JsonSerializerOptions() { WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }));
        _testOutputHelper.WriteLine("---------");
        _testOutputHelper.WriteLine(string.Empty);

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

        var jwtPayload = new JwtPayload(
            result.ClientId,
            disco.TokenEndpoint, //The FHIR Authorization Server's token endpoint URL
            new List<Claim>()
            {
                new Claim(JwtClaimTypes.Subject, result.ClientId),
                new Claim(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(), ClaimValueTypes.Integer),
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
            Udap = UdapConstants.UdapVersionsSupportedValue,
            Scope = "system.cruds"
        };


        _testOutputHelper.WriteLine("Client Token Request");
        _testOutputHelper.WriteLine("---------------------");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(clientRequest));
        _testOutputHelper.WriteLine(string.Empty);
        _testOutputHelper.WriteLine(string.Empty);

        var tokenResponse = await idpClient.RequestClientCredentialsTokenAsync(clientRequest);

        _testOutputHelper.WriteLine("Authorization Token Response");
        _testOutputHelper.WriteLine("---------------------");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(tokenResponse));
        _testOutputHelper.WriteLine(string.Empty);
        _testOutputHelper.WriteLine(string.Empty);

        tokenResponse.Scope.Should().Be("system.cruds");

        fhirLabsClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(TokenRequestTypes.Bearer, tokenResponse.AccessToken);
        var patientResponse = fhirLabsClient.GetAsync("https://localhost:7016/fhir/r4/Patient/$count-em");

        patientResponse.Result.EnsureSuccessStatusCode();


        _testOutputHelper.WriteLine(await patientResponse.Result.Content.ReadAsStringAsync());

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
            _fixture.Manifest.ResourceServers.First().Communities
                .Where(c => c.Name == "udap://surefhir.labs").Single().IssuedCerts.First().Password);

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
            GrantTypes = new HashSet<string> { "authorization_code" },
            ResponseTypes = new HashSet<string> { "code" },  
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            // Scope = "user/Patient.* user/Practitioner.read",  //Comment out for UDAP Server mode.
            RedirectUris = new List<string>{ new Uri($"https://client.fhirlabs.net/redirect/{Guid.NewGuid()}").AbsoluteUri },
            
        };
        document.AddClaims(new List<Claim>() {new Claim("client_uri", "http://test.com/hello/")});

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

        var jwtPayload = new JwtPayload(
            result.ClientId,
            disco.TokenEndpoint, //The FHIR Authorization Server's token endpoint URL
            new List<Claim>()
            {
                new Claim(JwtClaimTypes.Subject, result.ClientId),
                new Claim(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(), ClaimValueTypes.Integer),
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


        _testOutputHelper.WriteLine("Client Token Request");
        _testOutputHelper.WriteLine("---------------------");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(clientRequest));
        _testOutputHelper.WriteLine(string.Empty);
        _testOutputHelper.WriteLine(string.Empty);

        
        var tokenResponse = await idpClient.RequestClientCredentialsTokenAsync(clientRequest);


        _testOutputHelper.WriteLine("Authorization Token Response");
        _testOutputHelper.WriteLine("---------------------");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(tokenResponse));
        _testOutputHelper.WriteLine(string.Empty);
        _testOutputHelper.WriteLine(string.Empty);

        fhirLabsClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(TokenRequestTypes.Bearer, tokenResponse.AccessToken);
        var patientResponse = fhirLabsClient.GetAsync("https://localhost:7016/fhir/r4/Patient/$count-em");

        patientResponse.Result.EnsureSuccessStatusCode();


        _testOutputHelper.WriteLine(await patientResponse.Result.Content.ReadAsStringAsync());

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
            _fixture.Manifest.ResourceServers.First().Communities
                .Where(c => c.Name == "udap://surefhir.labs").Single().IssuedCerts.First().Password);

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
            // Scope = "system/Patient.* system/Practitioner.read"
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

        var jwtPayload = new JwtPayload(
            result.Issuer,
            disco.TokenEndpoint, //The FHIR Authorization Server's token endpoint URL
            new List<Claim>()
            {
                new Claim(JwtClaimTypes.Subject, result.ClientId),
                new Claim(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(), ClaimValueTypes.Integer),
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


        _testOutputHelper.WriteLine("Client Token Request");
        _testOutputHelper.WriteLine("---------------------");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(clientRequest));
        _testOutputHelper.WriteLine(string.Empty);
        _testOutputHelper.WriteLine(string.Empty);


        var tokenResponse = await idpClient.RequestClientCredentialsTokenAsync(clientRequest);

        
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
            }
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
        var publicCert = jwt?.GetPublicCertificate();
        
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
            ValidAlgorithms = new[] { jwt.GetHeaderValue<string>(Microsoft.IdentityModel.JsonWebTokens.JwtHeaderParameterNames.Alg) }, //must match signing algorithm
        });

        jwt.GetPayloadValue<string>(UdapConstants.Discovery.RegistrationEndpoint)
            .Should().Be(disco.RegistrationEndpoint);

        var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");

        var clientCert = new X509Certificate2(
            cert,
            _fixture.Manifest.ResourceServers.First().Communities
                .Where(c => c.Name == "udap://surefhir.labs").Single().IssuedCerts.First().Password);

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

        // var document = new UdapDynamicClientRegistrationDocument
        // {
        //     Issuer = "https://fhirlabs.net:7016/fhir/r4",
        //     Subject = "https://fhirlabs.net:7016/fhir/r4",
        //     Audience = regEndpoint,
        //     Expiration = EpochTime.GetIntDate(now.AddMinutes(5).ToUniversalTime()),
        //     IssuedAt = EpochTime.GetIntDate(now.ToUniversalTime()),
        //     JwtId = jwtId,
        //     ClientName = "udapTestClient",
        //     Contacts = new HashSet<string> { "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com" },
        //     GrantTypes = new HashSet<string> { "client_credentials" },
        //     // ResponseTypes = new HashSet<string> { "authorization_code" },  TODO: Add tests.  This should not be here when grantTypes contains client_credentials
        //     TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
        //     Scope = "system/Patient.* system/Practitioner.read"
        // };

        var document = UdapClientCredentialsDcrBuilder
            .Create(clientCert)
            .WithAudience(disco.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("FhirLabs Client")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.* system/Practitioner.read")
            .Build();

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
        var response = await idpClient.PostAsJsonAsync(disco.RegistrationEndpoint, requestBody);

        if (response.StatusCode != HttpStatusCode.Created)
        {
            _testOutputHelper.WriteLine(await response.Content.ReadAsStringAsync());
        }

        response.Content.Headers.ContentType!.ToString().Should().Be("application/json");
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
        _testOutputHelper.WriteLine($"Authorization Endpoint:: {result.Audience}");
        // var idpDisco = await idpClient.GetDiscoveryDocumentAsync(disco.AuthorizeEndpoint);
        //
        // idpDisco.IsError.Should().BeFalse(idpDisco.Error);




        //
        // Get Access Token
        //

        var jwtPayload = new JwtPayload(
            result.ClientId,
            disco.TokenEndpoint, //The FHIR Authorization Server's token endpoint URL
            new List<Claim>()
            {
                new Claim(JwtClaimTypes.Subject, result.ClientId),
                new Claim(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(), ClaimValueTypes.Integer),
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


        _testOutputHelper.WriteLine("Client Token Request");
        _testOutputHelper.WriteLine("---------------------");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(clientRequest));
        _testOutputHelper.WriteLine(string.Empty);
        _testOutputHelper.WriteLine(string.Empty);


        var tokenResponse = await idpClient.RequestClientCredentialsTokenAsync(clientRequest);

        _testOutputHelper.WriteLine("Authorization Token Response");
        _testOutputHelper.WriteLine("---------------------");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(tokenResponse));
        _testOutputHelper.WriteLine(string.Empty);
        _testOutputHelper.WriteLine(string.Empty);

        
        fhirLabsClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(TokenRequestTypes.Bearer, tokenResponse.AccessToken);
        var patientResponse = fhirLabsClient.GetAsync("https://fhirlabs.net/fhir/r4/Patient/$count-em");

        patientResponse.Result.EnsureSuccessStatusCode();

        _testOutputHelper.WriteLine(await patientResponse.Result.Content.ReadAsStringAsync());

    }

    [Fact]
    public async Task RegistrationSuccess_authorization_code_FhirLabs_LIVE_Test()
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

        var clientCert = new X509Certificate2(
            cert,
            _fixture.Manifest.ResourceServers.First().Communities
                .Where(c => c.Name == "udap://surefhir.labs").Single().IssuedCerts.First().Password);

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
            GrantTypes = new HashSet<string> { "authorization_code" },
            ResponseTypes = new HashSet<string> { "code" },
            TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
            Scope = "user/Patient.* user/Practitioner.read",  //Comment out for UDAP Server mode.
            RedirectUris = new List<string> { new Uri($"https://client.fhirlabs.net/redirect/{Guid.NewGuid()}").AbsoluteUri },
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

        var jwtPayload = new JwtPayload(
            result.ClientId,
            disco.TokenEndpoint, //The FHIR Authorization Server's token endpoint URL
            new List<Claim>()
            {
                new Claim(JwtClaimTypes.Subject, result.ClientId),
                new Claim(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(), ClaimValueTypes.Integer),
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
            Udap = UdapConstants.UdapVersionsSupportedValue,
            Scope = "user/Patient.* user/Practitioner.read"
        };

        
        _testOutputHelper.WriteLine("Client Token Request");
        _testOutputHelper.WriteLine("---------------------");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(clientRequest));
        _testOutputHelper.WriteLine(string.Empty);
        _testOutputHelper.WriteLine(string.Empty);

        var tokenResponse = await idpClient.RequestClientCredentialsTokenAsync(clientRequest);

        _testOutputHelper.WriteLine("Authorization Token Response");
        _testOutputHelper.WriteLine("---------------------");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(tokenResponse));
        _testOutputHelper.WriteLine(string.Empty);
        _testOutputHelper.WriteLine(string.Empty);

        fhirLabsClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(TokenRequestTypes.Bearer, tokenResponse.AccessToken);
        var patientResponse = fhirLabsClient.GetAsync("https://fhirlabs.net/fhir/r4/Patient/$count-em");

        patientResponse.Result.EnsureSuccessStatusCode();

        _testOutputHelper.WriteLine(await patientResponse.Result.Content.ReadAsStringAsync());

    }
    [Fact]
    public async Task RegistrationMissingScope_client_credentials_FhirLabs_desktop_Test()
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
            Community = "udap://surefhir.labs"
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

        validatedToken.IsValid.Should().BeTrue();

        jwt.Payload.Claims
            .Single(c => c.Type == UdapConstants.Discovery.RegistrationEndpoint)
            .Value.Should().Be(regEndpoint);

        var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");

        var clientCert = new X509Certificate2(
            cert,
            _fixture.Manifest.ResourceServers.First().Communities
                .Where(c => c.Name == "udap://surefhir.labs").Single().IssuedCerts.First().Password);

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
            // Scope = "system/Patient.* system/Practitioner.read"
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

        var jwtPayload = new JwtPayload(
            result.ClientId,
            disco.TokenEndpoint, //The FHIR Authorization Server's token endpoint URL
            new List<Claim>()
            {
                new Claim(JwtClaimTypes.Subject, result.ClientId),
                new Claim(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(), ClaimValueTypes.Integer),
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


        _testOutputHelper.WriteLine("Client Token Request");
        _testOutputHelper.WriteLine("---------------------");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(clientRequest));
        _testOutputHelper.WriteLine(string.Empty);
        _testOutputHelper.WriteLine(string.Empty);

        var tokenResponse = await idpClient.RequestClientCredentialsTokenAsync(clientRequest);


        _testOutputHelper.WriteLine("Authorization Token Response");
        _testOutputHelper.WriteLine("---------------------");
        _testOutputHelper.WriteLine(JsonSerializer.Serialize(tokenResponse));
        _testOutputHelper.WriteLine(string.Empty);
        _testOutputHelper.WriteLine(string.Empty);

        fhirLabsClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(TokenRequestTypes.Bearer, tokenResponse.AccessToken);
        var patientResponse = fhirLabsClient.GetAsync("https://localhost:7016/fhir/r4/Patient/$count-em");

        patientResponse.Result.EnsureSuccessStatusCode();


        _testOutputHelper.WriteLine(await patientResponse.Result.Content.ReadAsStringAsync());
    }

    private string BuildHl7B2BExtensions()
    {
        return "{\"version\": \"1\", \"subject_name\": \"todo.  more work to do here\"}";
    }
}