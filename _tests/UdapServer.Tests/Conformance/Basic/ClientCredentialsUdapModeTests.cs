#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Duende.IdentityServer.Models;
using FluentAssertions;
using IdentityModel;
using IdentityModel.Client;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Udap.Client.Client.Extensions;
using Udap.Common.Models;
using Udap.Model;
using Udap.Model.Access;
using Udap.Model.Registration;
using Udap.Model.Statement;
using Udap.Server.Configuration;
using Udap.Util.Extensions;
using UdapServer.Tests.Common;
using Xunit.Abstractions;

namespace UdapServer.Tests.Conformance.Basic;

[Collection("Udap.Idp")]
public class ClientCredentialsUdapModeTests
{
    private readonly ITestOutputHelper _testOutputHelper;
    private UdapIdentityServerPipeline _mockPipeline = new UdapIdentityServerPipeline();

    public ClientCredentialsUdapModeTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;

        var sureFhirLabsAnchor = new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer");
        var intermediateCert = new X509Certificate2("CertStore/intermediates/SureFhirLabs_Intermediate.cer");

        var anchorCommunity2 = new X509Certificate2("CertStore/anchors/caLocalhostCert2.cer");
        var intermediateCommunity2 = new X509Certificate2("CertStore/intermediates/intermediateLocalhostCert2.cer");

        _mockPipeline.OnPostConfigureServices += s =>
        {
            s.AddSingleton<ServerSettings>(new ServerSettings
            {
                ServerSupport = ServerSupport.UDAP,
                DefaultUserScopes = "udap",
                DefaultSystemScopes = "udap",
                ForceStateParamOnAuthorizationCode = true
            });
        };

        _mockPipeline.OnPreConfigureServices += s =>
        {
            // This registers Clients as List<Client> so downstream I can pick it up in InMemoryUdapClientRegistrationStore
            // TODO: PR Deunde for this issue.
            // They register Clients as IEnumerable<Client> in AddInMemoryClients extension
            s.AddSingleton(_mockPipeline.Clients);
        };

        _mockPipeline.Initialize(enableLogging: true);
        _mockPipeline.BrowserClient.AllowAutoRedirect = false;

        _mockPipeline.Communities.Add(new Community
        {
            Name = "udap://fhirlabs.net",
            Enabled = true,
            Default = true,
            Anchors = new[]
            {
                new Anchor
                {
                    BeginDate = sureFhirLabsAnchor.NotBefore.ToUniversalTime(),
                    EndDate = sureFhirLabsAnchor.NotAfter.ToUniversalTime(),
                    Name = sureFhirLabsAnchor.Subject,
                    Community = "udap://fhirlabs.net",
                    Certificate = sureFhirLabsAnchor.ToPemFormat(),
                    Thumbprint = sureFhirLabsAnchor.Thumbprint,
                    Enabled = true,
                    Intermediates = new List<Intermediate>()
                    {
                        new Intermediate
                        {
                            BeginDate = intermediateCert.NotBefore.ToUniversalTime(),
                            EndDate = intermediateCert.NotAfter.ToUniversalTime(),
                            Name = intermediateCert.Subject,
                            Certificate = intermediateCert.ToPemFormat(),
                            Thumbprint = intermediateCert.Thumbprint,
                            Enabled = true
                        }
                    }
                }
            }
        });

        _mockPipeline.Communities.Add(new Community
        {
            Name = "localhost_fhirlabs_community2",
            Enabled = true,
            Default = false,
            Anchors = new[]
            {
                new Anchor
                {
                    BeginDate = anchorCommunity2.NotBefore.ToUniversalTime(),
                    EndDate = anchorCommunity2.NotAfter.ToUniversalTime(),
                    Name = anchorCommunity2.Subject,
                    Community = "localhost_fhirlabs_community2",
                    Certificate = anchorCommunity2.ToPemFormat(),
                    Thumbprint = anchorCommunity2.Thumbprint,
                    Enabled = true,
                    Intermediates = new List<Intermediate>()
                    {
                        new Intermediate
                        {
                            BeginDate = intermediateCommunity2.NotBefore.ToUniversalTime(),
                            EndDate = intermediateCommunity2.NotAfter.ToUniversalTime(),
                            Name = intermediateCommunity2.Subject,
                            Certificate = intermediateCommunity2.ToPemFormat(),
                            Thumbprint = intermediateCommunity2.Thumbprint,
                            Enabled = true
                        }
                    }
                }
            }
        });
        

        _mockPipeline.IdentityScopes.Add(new IdentityResources.OpenId());
        _mockPipeline.IdentityScopes.Add(new IdentityResources.Profile());
        _mockPipeline.ApiScopes.Add(new ApiScope("system/Patient.rs"));
        _mockPipeline.ApiScopes.Add(new ApiScope(" system/Appointment.rs"));
    }

    [Fact]
    public async Task Todo()
    {
        //Need tests here:

        // Ensure the missing scope test during /connect/token request works
        // It should test in UDAP server mode and specifically UdapScopeResolverMiddleware and 
    }

    [Fact]
    public async Task GetAccessToken()
    {
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");

        var document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithAudience(UdapIdentityServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs")
            .Build();

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            new string[] { }
        );

        var regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapIdentityServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.Created);
        var regDocumentResult = await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();




        //
        // Get Access Token
        //
        var now = DateTime.UtcNow;
        var jwtPayload = new JwtPayLoadExtension(
            regDocumentResult!.ClientId,
            IdentityServerPipeline.TokenEndpoint,
            new List<Claim>()
            {
                new Claim(JwtClaimTypes.Subject, regDocumentResult.ClientId!),
                new Claim(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(),
                    ClaimValueTypes.Integer),
                new Claim(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId()),
                // new Claim(UdapConstants.JwtClaimTypes.Extensions, BuildHl7B2BExtensions() ) //see http://hl7.org/fhir/us/udap-security/b2b.html#constructing-authentication-token
            },
            now.ToUniversalTime(),
            now.AddMinutes(5).ToUniversalTime()
        );

        var clientAssertion =
            SignedSoftwareStatementBuilder<JwtPayLoadExtension>
                .Create(clientCert, jwtPayload)
                .Build("RS384");
        
        var clientRequest = new UdapClientCredentialsTokenRequest
        {
            Address = IdentityServerPipeline.TokenEndpoint,
            //ClientId = result.ClientId, we use Implicit ClientId in the iss claim
            ClientAssertion = new ClientAssertion()
            {
                Type = OidcConstants.ClientAssertionTypes.JwtBearer,
                Value = clientAssertion
            },
            Udap = UdapConstants.UdapVersionsSupportedValue,
            Scope = "system/Patient.rs"
        };

        var tokenResponse = await _mockPipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        tokenResponse.Scope.Should().Be("system/Patient.rs", tokenResponse.Raw);

    }

    [Fact]
    public async Task GetAccessTokenECDSA()
    {
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.ecdsa.client.pfx", "udap-test", 
            X509KeyStorageFlags.Exportable);

        var document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithAudience(UdapIdentityServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs")
            .Build();

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .BuildECDSA();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            new string[] { }
        );

        var regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapIdentityServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.Created);
        var regDocumentResult = await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();




        //
        // Get Access Token
        //
        var now = DateTime.UtcNow;
        var jwtPayload = new JwtPayLoadExtension(
            regDocumentResult!.ClientId,
            IdentityServerPipeline.TokenEndpoint,
            new List<Claim>()
            {
                new Claim(JwtClaimTypes.Subject, regDocumentResult.ClientId!),
                new Claim(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(),
                    ClaimValueTypes.Integer),
                new Claim(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId()),
                // new Claim(UdapConstants.JwtClaimTypes.Extensions, BuildHl7B2BExtensions() ) //see http://hl7.org/fhir/us/udap-security/b2b.html#constructing-authentication-token
            },
            now.ToUniversalTime(),
            now.AddMinutes(5).ToUniversalTime()
        );

        var clientAssertion =
            SignedSoftwareStatementBuilder<JwtPayLoadExtension>
                .Create(clientCert, jwtPayload)
                .BuildECDSA();

        var clientRequest = new UdapClientCredentialsTokenRequest
        {
            Address = IdentityServerPipeline.TokenEndpoint,
            //ClientId = result.ClientId, we use Implicit ClientId in the iss claim
            ClientAssertion = new ClientAssertion()
            {
                Type = OidcConstants.ClientAssertionTypes.JwtBearer,
                Value = clientAssertion
            },
            Udap = UdapConstants.UdapVersionsSupportedValue,
            Scope = "system/Patient.rs"
        };

        var tokenResponse = await _mockPipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        tokenResponse.Scope.Should().Be("system/Patient.rs", tokenResponse.Raw);

    }

    [Fact]
    public async Task UpdateRegistration()
    {
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");

        //
        // First Registration
        //
        var document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithAudience(UdapIdentityServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs")
            .Build();

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            new string[] { }
        );

        var regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapIdentityServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.Created);
        var regDocumentResult = await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        regDocumentResult!.Scope.Should().Be("system/Patient.rs");

        var clientIdWithDefaultSubAltName = regDocumentResult.ClientId;

        //
        // Second Registration
        //
        document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithAudience(UdapIdentityServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Appointment.rs")
            .Build();

        signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            new string[] { }
        );

        regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapIdentityServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        regDocumentResult = await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        regDocumentResult!.Scope.Should().Be("system/Patient.rs system/Appointment.rs");

        regDocumentResult!.ClientId.Should().Be(clientIdWithDefaultSubAltName);

        //
        // Third Registration with different Uri Subject Alt Name from same client certificate
        // expect 201 created because I changed the SAN selected by calling WithIssuer
        //

        document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithIssuer(new Uri("https://fhirlabs.net:7016/fhir/r4"))
            .WithAudience(UdapIdentityServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Appointment.rs")
            .Build();

        signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            new string[] { }
        );

        regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapIdentityServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.Created, await regResponse.Content.ReadAsStringAsync());
        var regDocumentResultForSelectedSubAltName =
            await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        regDocumentResultForSelectedSubAltName!.Scope.Should().Be("system/Patient.rs system/Appointment.rs");
        var clientIdWithSelectedSubAltName = regDocumentResultForSelectedSubAltName.ClientId;
        clientIdWithSelectedSubAltName.Should().NotBe(clientIdWithDefaultSubAltName);

        //
        // Fourth Registration with Uri Subject Alt Name from third registration
        // expect 200 OK because I changed scope
        //
        document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithIssuer(new Uri("https://fhirlabs.net:7016/fhir/r4"))
            .WithAudience(UdapIdentityServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs")
            .Build();

        signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            new string[] { }
        );

        regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapIdentityServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var regDocumentResultForSelectedSubAltNameSecond =
            await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        regDocumentResultForSelectedSubAltNameSecond!.Scope.Should().Be("system/Patient.rs");

        regDocumentResultForSelectedSubAltNameSecond!.ClientId.Should().Be(clientIdWithSelectedSubAltName);

    }

    [Fact]
    public async Task RegisterClientCredentialsThenRegisterAuthorizationCode()
    {
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");

        //
        // First Registration
        //
        var document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithAudience(UdapIdentityServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs")
            .Build();

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            new string[] { }
        );

        var regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapIdentityServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.Created);
        var regDocumentResult = await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        regDocumentResult!.Scope.Should().Be("system/Patient.rs");

        //
        // Second Registration as Authorization Code Flow should be a new registration
        //
        document = UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithAudience(UdapIdentityServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Appointment.rs")
            .WithResponseTypes(new List<string> { "code" })
            .WithRedirectUrls(new List<string> { "https://code_client/callback" })
            .Build();

        signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            new string[] { }
        );

        regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapIdentityServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.Created, await regResponse.Content.ReadAsStringAsync());
        regDocumentResult = await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        regDocumentResult!.Scope.Should().Be("system/Patient.rs system/Appointment.rs");

        //
        // Third Registration as Authorization Code Flow for second time will be an updated HttpStatus code 200
        //
        document = UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithAudience(UdapIdentityServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs")
            .WithResponseTypes(new List<string> { "code" })
            .WithRedirectUrls(new List<string> { "https://code_client/callback" })
            .Build();

        signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            new string[] { }
        );

        regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapIdentityServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.OK, await regResponse.Content.ReadAsStringAsync());
        regDocumentResult = await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        regDocumentResult!.Scope.Should().Be("system/Patient.rs");
    }

    /// <summary>
    /// This is a special case.  In my test environment I received a certificate from EMRDirect.  The certificate
    /// contains two Subject Alternative Names; https://fhirlabs.net/fhir/r4 and https://fhirlabs.net:7016/fhir/r4.
    /// I also created my own community with PKI infrastructure where the client certificate has the same SubAltNames.
    /// So if a client registers with one client certificate and then registers again with the second certificate,
    /// the registration should change to the other community.
    ///
    /// Below in the test I have generated two community PKI structures to build the scenario.
    /// </summary>
    /// <returns></returns>
    [Fact]
    public async Task ChangeRegistrationBetweenCommunitiesWhereSubAltNamesTheSame()
    {
        var clientCertCommunity1 = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
        // var clientCertCommunity2 = new X509Certificate2("CertStore/issued/fhirlabs.7016.net.client.pfx", "udap-test");

        //
        // First Registration
        //
        var document = UdapDcrBuilderForClientCredentials
            .Create(clientCertCommunity1)
            .WithAudience(UdapIdentityServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs")
            .Build();

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCertCommunity1, document)
                .Build();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            new string[] { }
        );

        var regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapIdentityServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.Created);
        var regDocumentResult = await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        regDocumentResult!.Scope.Should().Be("system/Patient.rs");

        var clientIdWithDefaultSubAltName = regDocumentResult.ClientId;

        //
        // Second Registration
        //
        document = UdapDcrBuilderForClientCredentials
            .Create(clientCertCommunity1)
            .WithAudience(UdapIdentityServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Appointment.rs")
            .Build();

        signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCertCommunity1, document)
                .Build();

        requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            new string[] { }
        );

        regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapIdentityServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        regDocumentResult = await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        regDocumentResult!.Scope.Should().Be("system/Patient.rs system/Appointment.rs");

        regDocumentResult!.ClientId.Should().Be(clientIdWithDefaultSubAltName);
    }

    [Fact]
    public async Task CancelRegistration()
    {
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");

        //
        // Registration
        //
        var document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithAudience(UdapIdentityServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs")
            .Build();

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            new string[] { }
        );

        var regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapIdentityServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.Created);
        var regDocumentResult = await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        regDocumentResult!.Scope.Should().Be("system/Patient.rs");

        var clientIdWithDefaultSubAltName = regDocumentResult.ClientId;

        //
        // Cancel Registration
        //
        document = UdapDcrBuilderForClientCredentials
            .Cancel(clientCert)
            .WithAudience(UdapIdentityServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Appointment.rs")
            .Build();

        signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            new string[] { }
        );
        

        regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapIdentityServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.OK); // Deleted finished so returns a 200 status code according to udap.org specifications
        
        //
        // Even during a cancel registration it is expected that he SoftwareStatement returned is the same.
        //
        regDocumentResult = await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        regDocumentResult!.SoftwareStatement.Should().Be(signedSoftwareStatement);
        // regDocumentResult.ClientId.Should().Be(clientIdWithDefaultSubAltName);  //with a cancel it is possible to delete multiple client ids.

        //
        // Repeated un-register should be 400 rather than not found (404).
        // This is following section 5.2 of https://www.udap.org/udap-dynamic-client-registration.html
        //
        regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapIdentityServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.BadRequest); 

        //
        // Registration with different Uri Subject Alt Name from same client certificate
        // expect 201 created because I changed the SAN selected by calling WithIssuer
        //

        document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithIssuer(new Uri("https://fhirlabs.net:7016/fhir/r4"))
            .WithAudience(UdapIdentityServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Appointment.rs")
            .Build();

        signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            new string[] { }
        );

        regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapIdentityServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.Created, await regResponse.Content.ReadAsStringAsync());
        var regDocumentResultForSelectedSubAltName =
            await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        regDocumentResultForSelectedSubAltName!.Scope.Should().Be("system/Patient.rs system/Appointment.rs");
        var clientIdWithSelectedSubAltName = regDocumentResultForSelectedSubAltName.ClientId;
        clientIdWithSelectedSubAltName.Should().NotBe(clientIdWithDefaultSubAltName);

        
        //
        // Cancel Registration
        //
        document = UdapDcrBuilderForClientCredentials
            .Cancel(clientCert)
            .WithIssuer(new Uri("https://fhirlabs.net:7016/fhir/r4"))
            .WithAudience(UdapIdentityServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs")
            .Build();

        signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            new string[] { }
        );

        regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapIdentityServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.OK); // Deleted finished so returns a 200 status code according to udap.org specifications
        //
        // Even during a cancel registration it is expected that he SoftwareStatement returned is the same.
        //
        regDocumentResult = await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        regDocumentResult!.SoftwareStatement.Should().Be(signedSoftwareStatement);
        // regDocumentResult.ClientId.Should().Be(clientIdWithSelectedSubAltName);  //with a cancel it is possible to delete multiple client ids.
        //
        // Repeated un-register should be 400 rather than not found (404).
        // This is following section 5.2 of https://www.udap.org/udap-dynamic-client-registration.html
        //
        regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapIdentityServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.BadRequest); // Deleted finished so returns a 404 status code
    }

    [Fact]
    public async Task RegisterTwoCommunitiesWithSameISS_AndCancelOne()
    {
        var clientCert_1 = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
        var clientCert_2 = new X509Certificate2("CertStore/issued/fhirLabsApiClientLocalhostCert2.pfx", "udap-test");

        //
        // Register Client 1
        //
        var document = UdapDcrBuilderForClientCredentials
            .Create(clientCert_1)
            .WithAudience(UdapIdentityServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs")
            .Build();

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert_1, document)
                .Build();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            new string[] { }
        );

        var regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapIdentityServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.Created);
        var regDocumentResult = await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        regDocumentResult!.Scope.Should().Be("system/Patient.rs");


        //
        // Register Client 2
        //
        document = UdapDcrBuilderForClientCredentials
            .Create(clientCert_2)
            .WithAudience(UdapIdentityServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test 2")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs")
            .Build();

        signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert_2, document)
                .Build();

        requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            new string[] { }
        );

        regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapIdentityServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.Created);
        regDocumentResult = await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        regDocumentResult!.Scope.Should().Be("system/Patient.rs");

        //
        // Cancel Registration
        //
        document = UdapDcrBuilderForClientCredentials
            .Cancel(clientCert_1)
            .WithAudience(UdapIdentityServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Appointment.rs")
            .Build();

        signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert_1, document)
                .Build();

        requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            new string[] { }
        );


        regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapIdentityServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.OK); // Deleted finished so returns a 200 status code according to udap.org specifications
        
    }

    [Fact]
    public async Task Missing_grant_types_RegistrationResultsIn_invalid_client()
    {
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");

        //
        // Registration
        //
        var document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithAudience(UdapIdentityServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs")
            .Build();

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            new string[] { }
        );

        var regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapIdentityServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.Created);
        var regDocumentResult = await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        regDocumentResult!.Scope.Should().Be("system/Patient.rs");

        var clientIdWithDefaultSubAltName = regDocumentResult.ClientId;

        //
        // Cancel Registration
        //
        document = UdapDcrBuilderForClientCredentials
            .Cancel(clientCert)
            .WithAudience(UdapIdentityServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Appointment.rs")
            .Build();

        signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            new string[] { }
        );



        regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapIdentityServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.OK); // Deleted finished so returns a 200 status code according to udap.org specifications

        //
        // Even during a cancel registration it is expected that he SoftwareStatement returned is the same.
        //
        regDocumentResult = await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        regDocumentResult!.SoftwareStatement.Should().Be(signedSoftwareStatement);
        // regDocumentResult.ClientId.Should().Be(clientIdWithDefaultSubAltName);  //with a cancel it is possible to delete multiple client ids.

        //
        // Repeated un-register should be 400 rather than not found (404).
        // This is following section 5.2 of https://www.udap.org/udap-dynamic-client-registration.html
        //
        regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapIdentityServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.BadRequest); // Deleted finished so returns a 204 status code

        //
        // Registration with different Uri Subject Alt Name from same client certificate
        // expect 201 created because I changed the SAN selected by calling WithIssuer.
        // I can have a new registration if identifying a different SAN
        //

        document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithIssuer(new Uri("https://fhirlabs.net:7016/fhir/r4"))
            .WithAudience(UdapIdentityServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Appointment.rs")
            .Build();

        signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            new string[] { }
        );

        regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapIdentityServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.Created, await regResponse.Content.ReadAsStringAsync());
        var regDocumentResultForSelectedSubAltName =
            await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        regDocumentResultForSelectedSubAltName!.Scope.Should().Be("system/Patient.rs system/Appointment.rs");
        var clientIdWithSelectedSubAltName = regDocumentResultForSelectedSubAltName.ClientId;
        clientIdWithSelectedSubAltName.Should().NotBe(clientIdWithDefaultSubAltName);


        //
        // Cancel Registration
        //
        document = UdapDcrBuilderForClientCredentials
            .Cancel(clientCert)
            .WithIssuer(new Uri("https://fhirlabs.net:7016/fhir/r4"))
            .WithAudience(UdapIdentityServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs")
            .Build();

        signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            new string[] { }
        );

        regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapIdentityServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.OK); // Deleted finished so returns a 200 status code according to udap.org specifications
        //
        // Even during a cancel registration it is expected that he SoftwareStatement returned is the same.
        //
        regDocumentResult = await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        regDocumentResult!.SoftwareStatement.Should().Be(signedSoftwareStatement);
        // regDocumentResult.ClientId.Should().Be(clientIdWithSelectedSubAltName);  //with a cancel it is possible to delete multiple client ids.
        //
        // Repeated un-register should be 400 rather than not found (404).
        // This is following section 5.2 of https://www.udap.org/udap-dynamic-client-registration.html
        //
        regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapIdentityServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.BadRequest); // Deleted finished so returns a 404 status code
    }
}