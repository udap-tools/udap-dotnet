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
using Duende.IdentityServer.Test;
using Duende.IdentityModel;
using Duende.IdentityModel.Client;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Udap.Client.Extensions;
using Udap.Client.Configuration;
using Udap.Common.Extensions;
using Udap.Common.Models;
using Udap.Model;
using Udap.Model.Access;
using Udap.Model.Registration;
using Udap.Model.Statement;
using Udap.Server.Configuration;
using Udap.Server.Models;
using Udap.Server.Validation;
using Udap.Util.Extensions;
using UdapServer.Tests.Common;
using Xunit.Abstractions;

namespace UdapServer.Tests.Conformance.Basic;


[Collection("Udap.Auth.Server")]
public class ScopeExpansionTests
{
    private readonly ITestOutputHelper _testOutputHelper;
    private readonly UdapAuthServerPipeline _mockPipeline = new();

    public ScopeExpansionTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;

#if NET9_0_OR_GREATER
        var sureFhirLabsAnchor = X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/SureFhirLabs_CA.cer");
        var intermediateCert = X509CertificateLoader.LoadCertificateFromFile("CertStore/intermediates/SureFhirLabs_Intermediate.cer");
#else
        var sureFhirLabsAnchor = new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer");
        var intermediateCert = new X509Certificate2("CertStore/intermediates/SureFhirLabs_Intermediate.cer");
#endif

        _mockPipeline.OnPostConfigureServices += services =>
        {
            services.AddSingleton(sp =>
            {
                var serverSettings = sp.GetRequiredService<IOptions<ServerSettings>>().Value;
                serverSettings.RequireConsent = false;
                serverSettings.RequirePkce = false;
                serverSettings.SsraaVersion = SsraaVersion.V1_1; // Support V1 and V2 for backward compat
                return serverSettings;
            });

            services.AddSingleton(new UdapClientOptions
            {
                ClientName = "Mock Client",
                Contacts = new HashSet<string> { "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com" }
            });

            services.AddScoped<IScopeExpander, HL7SmartScopeExpander>();
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
            Anchors =
            [
                new Anchor(sureFhirLabsAnchor, "udap://fhirlabs.net")
                {
                    BeginDate = sureFhirLabsAnchor.NotBefore.ToUniversalTime(),
                    EndDate = sureFhirLabsAnchor.NotAfter.ToUniversalTime(),
                    Name = sureFhirLabsAnchor.Subject,
                    Enabled = true,
                    Intermediates = new List<Intermediate>()
                    {
                        new(intermediateCert)
                        {
                            BeginDate = intermediateCert.NotBefore.ToUniversalTime(),
                            EndDate = intermediateCert.NotAfter.ToUniversalTime(),
                            Name = intermediateCert.Subject,
                            Enabled = true
                        }
                    }
                }
            ]
        });

        _mockPipeline.ApiScopes.AddRange(new HL7SmartScopeExpander().ExpandToApiScopes("system/Patient.cruds"));
        _mockPipeline.ApiScopes.AddRange(new HL7SmartScopeExpander().ExpandToApiScopes("system/Encounter.r"));
        _mockPipeline.ApiScopes.AddRange(new HL7SmartScopeExpander().ExpandToApiScopes("system/Condition.s"));
        _mockPipeline.ApiScopes.Add( new ApiScope("system/Practitioner.read"));


        _mockPipeline.IdentityScopes.Add(new IdentityResources.OpenId());
        _mockPipeline.ApiScopes.Add(new UdapApiScopes.Udap());

        _mockPipeline.Users.Add(new TestUser
        {
            SubjectId = "bob",
            Username = "bob",
            Claims =
            [
                new Claim("name", "Bob Loblaw"),
                new Claim("email", "bob@loblaw.com"),
                new Claim("role", "Attorney")
            ]
        });
    }


    [Theory]
    [InlineData("cruds")]
    public void GenerateCombinations_ReturnsUniqueStringCombinationsInGivenOrder(string input)
    {
        var expectedOutput = ScopeExtensions.GenerateCombinations(input);

        foreach (var output in expectedOutput)
        {
            _testOutputHelper.WriteLine(output);
        }
    }

   
    [Fact]
    public async Task ScopeV2WithClientCredentialsTest()
    {
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif
        var resultDocument = await RegisterClientWithAuthServer("system/Patient.rs", clientCert);
        Assert.NotNull(resultDocument);
        Assert.NotNull(resultDocument!.ClientId);

        //
        // Get Access Token
        //
        var now = DateTime.UtcNow;
        var jwtPayload = new JwtPayLoadExtension(
            resultDocument.ClientId,
            IdentityServerPipeline.TokenEndpoint,
            new List<Claim>()
            {
                new(JwtClaimTypes.Subject, resultDocument.ClientId!),
                new(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(), ClaimValueTypes.Integer),
                new(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId()),
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
            Scope = "system/Patient.r"
        };

        var tokenResponse = await _mockPipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        Assert.Equal("system/Patient.r", tokenResponse.Scope);


        //
        // Again
        //

        jwtPayload = new JwtPayLoadExtension(
            resultDocument.ClientId,
            IdentityServerPipeline.TokenEndpoint,
            new List<Claim>()
            {
                new(JwtClaimTypes.Subject, resultDocument.ClientId!),
                new(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(), ClaimValueTypes.Integer),
                new(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId()),
                // new Claim(UdapConstants.JwtClaimTypes.Extensions, BuildHl7B2BExtensions() ) //see http://hl7.org/fhir/us/udap-security/b2b.html#constructing-authentication-token
            },
            now.ToUniversalTime(),
            now.AddMinutes(5).ToUniversalTime()
        );

        clientAssertion =
            SignedSoftwareStatementBuilder<JwtPayLoadExtension>
                .Create(clientCert, jwtPayload)
                .Build("RS384");


        clientRequest = new UdapClientCredentialsTokenRequest
        {
            Address = IdentityServerPipeline.TokenEndpoint,
            //ClientId = result.ClientId, we use Implicit ClientId in the iss claim
            ClientAssertion = new ClientAssertion()
            {
                Type = OidcConstants.ClientAssertionTypes.JwtBearer,
                Value = clientAssertion
            },
            Udap = UdapConstants.UdapVersionsSupportedValue,
            Scope = "system/Patient.s"
        };

        tokenResponse = await _mockPipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        Assert.Equal("system/Patient.s", tokenResponse.Scope);


        //
        // Again
        //

        jwtPayload = new JwtPayLoadExtension(
            resultDocument.ClientId,
            IdentityServerPipeline.TokenEndpoint,
            new List<Claim>()
            {
                new(JwtClaimTypes.Subject, resultDocument.ClientId!),
                new(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(), ClaimValueTypes.Integer),
                new(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId()),
                // new Claim(UdapConstants.JwtClaimTypes.Extensions, BuildHl7B2BExtensions() ) //see http://hl7.org/fhir/us/udap-security/b2b.html#constructing-authentication-token
            },
            now.ToUniversalTime(),
            now.AddMinutes(5).ToUniversalTime()
        );

        clientAssertion =
            SignedSoftwareStatementBuilder<JwtPayLoadExtension>
                .Create(clientCert, jwtPayload)
                .Build("RS384");


        clientRequest = new UdapClientCredentialsTokenRequest
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

        tokenResponse = await _mockPipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        Assert.Equal("system/Patient.rs", tokenResponse.Scope);

        
        //
        // Again negative
        //

        jwtPayload = new JwtPayLoadExtension(
            resultDocument.ClientId,
            IdentityServerPipeline.TokenEndpoint,
            new List<Claim>()
            {
                new(JwtClaimTypes.Subject, resultDocument.ClientId!),
                new(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(), ClaimValueTypes.Integer),
                new(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId()),
                // new Claim(UdapConstants.JwtClaimTypes.Extensions, BuildHl7B2BExtensions() ) //see http://hl7.org/fhir/us/udap-security/b2b.html#constructing-authentication-token
            },
            now.ToUniversalTime(),
            now.AddMinutes(5).ToUniversalTime()
        );

        clientAssertion =
            SignedSoftwareStatementBuilder<JwtPayLoadExtension>
                .Create(clientCert, jwtPayload)
                .Build("RS384");


        clientRequest = new UdapClientCredentialsTokenRequest
        {
            Address = IdentityServerPipeline.TokenEndpoint,
            //ClientId = result.ClientId, we use Implicit ClientId in the iss claim
            ClientAssertion = new ClientAssertion()
            {
                Type = OidcConstants.ClientAssertionTypes.JwtBearer,
                Value = clientAssertion
            },
            Udap = UdapConstants.UdapVersionsSupportedValue,
            Scope = "system/Patient.u"
        };

        tokenResponse = await _mockPipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        Assert.True(tokenResponse.IsError);
        Assert.Equal("invalid_scope", tokenResponse.Error);
    }

    [Fact]
    public async Task ScopeV2WithClientCredentialsExtendedTest()
    {
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif
        var resultDocument = await RegisterClientWithAuthServer("system/Patient.rs", clientCert);
        Assert.NotNull(resultDocument);
        Assert.NotNull(resultDocument!.ClientId);

        Assert.Equal("system/Patient.rs", resultDocument.Scope);
        Assert.Equal(3, _mockPipeline.Clients[0].AllowedScopes.Count);

        var now = DateTime.UtcNow;
        var jwtPayload = new JwtPayLoadExtension(
            resultDocument.ClientId,
            IdentityServerPipeline.TokenEndpoint,
            new List<Claim>()
            {
                new(JwtClaimTypes.Subject, resultDocument.ClientId!),
                new(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(), ClaimValueTypes.Integer),
                new(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId()),
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
            Scope = "system/Patient.rs system/Patient.r system/Patient.s"
        };

        var tokenResponse = await _mockPipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);
        Assert.Equal("system/Patient.r system/Patient.rs system/Patient.s", tokenResponse.Scope);
    }

    [Fact]
    public async Task ScopeV2WithClientCredentialsExtended2Test()
    {
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif
        var resultDocument = await RegisterClientWithAuthServer("system/*.rs", clientCert);
        Assert.NotNull(resultDocument);
        Assert.NotNull(resultDocument!.ClientId);

        Assert.Equal("system/Condition.s system/Encounter.r system/Patient.rs", resultDocument.Scope);

        var now = DateTime.UtcNow;
        var jwtPayload = new JwtPayLoadExtension(
            resultDocument.ClientId,
            IdentityServerPipeline.TokenEndpoint,
            new List<Claim>()
            {
                new(JwtClaimTypes.Subject, resultDocument.ClientId!),
                new(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(), ClaimValueTypes.Integer),
                new(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId()),
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
            Scope = "system/Condition.s system/Encounter.r system/Patient.rs"
        };

        var tokenResponse = await _mockPipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);
        Assert.Equal("system/Condition.s system/Encounter.r system/Patient.rs", tokenResponse.Scope);
    }

    [Fact]
    public async Task ScopeV2WithClientCredentialsWildcardTest()
    {
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif
        var resultDocument = await RegisterClientWithAuthServer("system/*.read", clientCert);
        Assert.NotNull(resultDocument);
        Assert.NotNull(resultDocument!.ClientId);

        Assert.Equal("system/Practitioner.read", resultDocument.Scope);

        var now = DateTime.UtcNow;
        var jwtPayload = new JwtPayLoadExtension(
            resultDocument.ClientId,
            IdentityServerPipeline.TokenEndpoint,
            new List<Claim>()
            {
                new(JwtClaimTypes.Subject, resultDocument.ClientId!),
                new(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(), ClaimValueTypes.Integer),
                new(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId()),
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
            Scope = "system/Practitioner.read"
        };

        var tokenResponse = await _mockPipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);
        Assert.Equal("system/Practitioner.read", tokenResponse.Scope);
    }

    [Fact]
    public async Task ScopeV2WithAuthCodeTest()
    {
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif

        var signedSoftwareStatement = UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("openid system/Patient.rs")
            .WithResponseTypes(new List<string> { "code" })
            .WithRedirectUrls(new List<string> { "https://code_client/callback" })
            .WithGrantType("refresh_token")
            .BuildSoftwareStatement();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            Array.Empty<string>()
        );

        _mockPipeline.BrowserClient.AllowAutoRedirect = true;

        var response = await _mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var resultDocument = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        Assert.NotNull(resultDocument);
        Assert.NotNull(resultDocument!.ClientId);

        var state = Guid.NewGuid().ToString();
        var nonce = Guid.NewGuid().ToString();

        await _mockPipeline.LoginAsync("bob");

        var url = _mockPipeline.CreateAuthorizeUrl(
            clientId: resultDocument.ClientId!,
            responseType: "code",
            scope: "openid system/Patient.rs",
            redirectUri: "https://code_client/callback",
            state: state,
            nonce: nonce);

        _mockPipeline.BrowserClient.AllowAutoRedirect = false;
        response = await _mockPipeline.BrowserClient.GetAsync(url);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);

        Assert.NotNull(response.Headers.Location);
        Assert.Contains("https://code_client/callback", response.Headers.Location!.AbsoluteUri);
        // _testOutputHelper.WriteLine(response.Headers.Location!.AbsoluteUri);
        var queryParams = QueryHelpers.ParseQuery(response.Headers.Location.Query);
        Assert.Contains(queryParams, p => p.Key == "code");
        // Obsolete scope results in newer Duende builds during upgrade from 7.2.4 to 7.3.1
        // Assert.Equal("openid system/Patient.rs", queryParams.Single(q => q.Key == "scope").Value.ToString(), StringComparer.OrdinalIgnoreCase);
        Assert.Equal(state, queryParams.Single(q => q.Key == "state").Value.ToString(), StringComparer.OrdinalIgnoreCase);

    }

    [Fact]
    public async Task RegisterInvalidScopeTests()
    {
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif
        var regResponse = await RegisterClientWithAuthServerResponse("system/Mars.read", clientCert);
        
        _testOutputHelper.WriteLine(await regResponse.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.BadRequest, regResponse.StatusCode);
        var errorResult = await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();
        Assert.NotNull(errorResult);
        Assert.Equal("invalid_client_metadata", errorResult!.Error);
        Assert.Equal("invalid_scope supplied", errorResult.ErrorDescription);
    }

    [Fact]
    public async Task RegisterEmptyScopeTests()
    {
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif
        var regResponse = await RegisterClientWithAuthServerResponse("", clientCert);

        _testOutputHelper.WriteLine(await regResponse.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.BadRequest, regResponse.StatusCode);
        var errorResult = await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();
        Assert.NotNull(errorResult);
        Assert.Equal("invalid_client_metadata", errorResult!.Error);
        Assert.Equal("scope is required", errorResult.ErrorDescription);
    }

    [Fact]
    public async Task TokenRequestWithInvalidScopeTest()
    {
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif
        var resultDocument = await RegisterClientWithAuthServer("system/*.read", clientCert);
        Assert.NotNull(resultDocument);
        Assert.NotNull(resultDocument!.ClientId);

        Assert.Equal("system/Practitioner.read", resultDocument.Scope);

        var now = DateTime.UtcNow;
        var jwtPayload = new JwtPayLoadExtension(
            resultDocument.ClientId,
            IdentityServerPipeline.TokenEndpoint,
            new List<Claim>()
            {
                new(JwtClaimTypes.Subject, resultDocument.ClientId!),
                new(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(), ClaimValueTypes.Integer),
                new(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId()),
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
            Scope = "system/Mars.read"
        };

        var tokenResponse = await _mockPipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);
        Assert.True(tokenResponse.IsError);
        Assert.Equal("invalid_scope", tokenResponse.Error);
    }

    /// <summary>
    /// Missing so return the registered scope.
    /// </summary>
    /// <returns></returns>
    [Fact]
    public async Task TokenRequestWithMissingScopeTest()
    {
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif
        var resultDocument = await RegisterClientWithAuthServer("system/*.read", clientCert);
        Assert.NotNull(resultDocument);
        Assert.NotNull(resultDocument!.ClientId);

        Assert.Equal("system/Practitioner.read", resultDocument.Scope);

        var now = DateTime.UtcNow;
        var jwtPayload = new JwtPayLoadExtension(
            resultDocument.ClientId,
            IdentityServerPipeline.TokenEndpoint,
            new List<Claim>()
            {
                new(JwtClaimTypes.Subject, resultDocument.ClientId!),
                new(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(), ClaimValueTypes.Integer),
                new(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId()),
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
            Udap = UdapConstants.UdapVersionsSupportedValue
        };

        var tokenResponse = await _mockPipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);
        Assert.Equal("system/Practitioner.read", tokenResponse.Scope);
    }


    private async Task<UdapDynamicClientRegistrationDocument?> RegisterClientWithAuthServer(string scopes, X509Certificate2 clientCert)
    {
        var response = await RegisterClientWithAuthServerResponse(scopes, clientCert);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var resultDocument = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();

        return resultDocument;
    }

    private async Task<HttpResponseMessage> RegisterClientWithAuthServerResponse(string scopes, X509Certificate2 clientCert)
    {
        // await _mockAuthorServerPipeline.LoginAsync("bob");

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
            .WithScope(scopes)
            .Build();

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            Array.Empty<string>()
        );

        var response = await _mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));
        return response;
    }
}
