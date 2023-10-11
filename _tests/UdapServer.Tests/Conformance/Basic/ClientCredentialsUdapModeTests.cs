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
using Udap.Client.Configuration;
using Udap.Common.Models;
using Udap.Model;
using Udap.Model.Access;
using Udap.Model.Registration;
using Udap.Model.Statement;
using Udap.Server.Configuration;
using Udap.Server.Validation;
using Udap.Util.Extensions;
using UdapServer.Tests.Common;
using Xunit.Abstractions;

namespace UdapServer.Tests.Conformance.Basic;

[Collection("Udap.Auth.Server")]
public class ClientCredentialsUdapModeTests
{
    private readonly ITestOutputHelper _testOutputHelper;
    private UdapAuthServerPipeline _mockPipeline = new UdapAuthServerPipeline();

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
                DefaultSystemScopes = "udap"
            });

            s.AddSingleton<UdapClientOptions>(new UdapClientOptions
            {
                ClientName = "Mock Client",
                Contacts = new HashSet<string> { "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com" }
            });

        };

        _mockPipeline.OnPreConfigureServices += (_, s) =>
        {
            // This registers Clients as List<Client> so downstream I can pick it up in InMemoryUdapClientRegistrationStore
            // Duende's AddInMemoryClients extension registers as IEnumerable<Client> and is used in InMemoryClientStore as readonly.
            // It was not intended to work with the concept of a dynamic client registration.
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
        _mockPipeline.ApiScopes.AddRange(new HL7SmartScopeExpander().ExpandToApiScopes("system/Patient.rs"));
        _mockPipeline.ApiScopes.AddRange(new HL7SmartScopeExpander().ExpandToApiScopes(" system/Appointment.rs"));
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
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
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
            UdapAuthServerPipeline.RegistrationEndpoint,
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
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
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
            UdapAuthServerPipeline.RegistrationEndpoint,
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
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
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
            UdapAuthServerPipeline.RegistrationEndpoint,
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
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
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
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        regDocumentResult = await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        regDocumentResult!.Scope.Should().Be("system/Appointment.rs system/Patient.rs");

        regDocumentResult!.ClientId.Should().Be(clientIdWithDefaultSubAltName);

        //
        // Third Registration with different Uri Subject Alt Name from same client certificate
        // expect 201 created because I changed the SAN selected by calling WithIssuer
        //

        document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithIssuer(new Uri("https://fhirlabs.net:7016/fhir/r4"))
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
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
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.Created, await regResponse.Content.ReadAsStringAsync());
        var regDocumentResultForSelectedSubAltName =
            await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        regDocumentResultForSelectedSubAltName!.Scope.Should().Be("system/Appointment.rs system/Patient.rs");
        var clientIdWithSelectedSubAltName = regDocumentResultForSelectedSubAltName.ClientId;
        clientIdWithSelectedSubAltName.Should().NotBe(clientIdWithDefaultSubAltName);

        //
        // Fourth Registration with Uri Subject Alt Name from third registration
        // expect 200 OK because I changed scope
        //
        document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithIssuer(new Uri("https://fhirlabs.net:7016/fhir/r4"))
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
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
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var regDocumentResultForSelectedSubAltNameSecond =
            await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        regDocumentResultForSelectedSubAltNameSecond!.Scope.Should().Be("system/Patient.rs");

        regDocumentResultForSelectedSubAltNameSecond!.ClientId.Should().Be(clientIdWithSelectedSubAltName);

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
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
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
            UdapAuthServerPipeline.RegistrationEndpoint,
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
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
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
            UdapAuthServerPipeline.RegistrationEndpoint,
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
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.BadRequest); 

        //
        // Registration with different Uri Subject Alt Name from same client certificate
        // expect 201 created because I changed the SAN selected by calling WithIssuer
        //

        document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithIssuer(new Uri("https://fhirlabs.net:7016/fhir/r4"))
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
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
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.Created, await regResponse.Content.ReadAsStringAsync());
        var regDocumentResultForSelectedSubAltName =
            await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        regDocumentResultForSelectedSubAltName!.Scope.Should().Be("system/Appointment.rs system/Patient.rs");
        var clientIdWithSelectedSubAltName = regDocumentResultForSelectedSubAltName.ClientId;
        clientIdWithSelectedSubAltName.Should().NotBe(clientIdWithDefaultSubAltName);

        
        //
        // Cancel Registration
        //
        document = UdapDcrBuilderForClientCredentials
            .Cancel(clientCert)
            .WithIssuer(new Uri("https://fhirlabs.net:7016/fhir/r4"))
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
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
            UdapAuthServerPipeline.RegistrationEndpoint,
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
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.BadRequest); // Deleted finished so returns a 404 status code
    }

    [Fact]
    public async Task RegisterTwoCommunitiesWithSameISS_AndCancelOne()
    {
        var clientCert_1 = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
        var clientCert_2 = new X509Certificate2("CertStore/issued/fhirLabsApiClientLocalhostCert2.pfx", "udap-test");

        //
        // Register Client 1 from community "udap://fhirlabs.net"
        //
        var document = UdapDcrBuilderForClientCredentials
            .Create(clientCert_1)
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
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
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.Created);
        var regDocumentResult = await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        regDocumentResult!.Scope.Should().Be("system/Patient.rs");


        //
        // Register Client 2 from community "localhost_fhirlabs_community2"
        //
        document = UdapDcrBuilderForClientCredentials
            .Create(clientCert_2)
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
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
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.Created);
        regDocumentResult = await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        regDocumentResult!.Scope.Should().Be("system/Patient.rs");

        _mockPipeline.Clients.Count.Should().Be(2);

        //
        // Cancel Registration from community "udap://fhirlabs.net"
        //
        document = UdapDcrBuilderForClientCredentials
            .Cancel(clientCert_1)
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
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
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.OK); // Deleted finished so returns a 200 status code according to udap.org specifications


        //Store validation
        _mockPipeline.Clients.Count.Should().Be(1);

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
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
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
            UdapAuthServerPipeline.RegistrationEndpoint,
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
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
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
            UdapAuthServerPipeline.RegistrationEndpoint,
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
            UdapAuthServerPipeline.RegistrationEndpoint,
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
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
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
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.Created, await regResponse.Content.ReadAsStringAsync());
        var regDocumentResultForSelectedSubAltName =
            await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        regDocumentResultForSelectedSubAltName!.Scope.Should().Be("system/Appointment.rs system/Patient.rs");
        var clientIdWithSelectedSubAltName = regDocumentResultForSelectedSubAltName.ClientId;
        clientIdWithSelectedSubAltName.Should().NotBe(clientIdWithDefaultSubAltName);


        //
        // Cancel Registration
        //
        document = UdapDcrBuilderForClientCredentials
            .Cancel(clientCert)
            .WithIssuer(new Uri("https://fhirlabs.net:7016/fhir/r4"))
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
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
            UdapAuthServerPipeline.RegistrationEndpoint,
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
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.BadRequest); // Deleted finished so returns a 404 status code
    }

    [Fact]
    public async Task ReplayRegistration()
    {
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");

        //
        // First Registration
        //
        var document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
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
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.Created);
        var regDocumentResult = await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        regDocumentResult!.Scope.Should().Be("system/Patient.rs");



        //
        // Second Registration
        //
        regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var errorResult = await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();
        errorResult.Should().NotBeNull();
        errorResult!.Error.Should().Be("invalid_client_metadata");
        errorResult.ErrorDescription.Should().Be("software_statement replayed");
        
    }
}