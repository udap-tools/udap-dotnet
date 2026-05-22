#region (c) 2024 Joseph Shook. All rights reserved.
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
using Duende.IdentityModel;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Test;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Udap.Client;
using Udap.Client.Configuration;
using Udap.Common.Models;
using Udap.Model;
using Udap.Model.Registration;
using Udap.Server.Configuration;
using UdapServer.Tests.Common;
using Xunit.Abstractions;

namespace UdapServer.Tests.Conformance.Basic;

/// <summary>
/// Tests for SSRAA IG version compliance.
///
/// The UDAP base protocol (udap.org) is at version 1. The <c>udap</c> field in every
/// registration request is always <c>"1"</c> regardless of which SSRAA IG version the
/// server enforces. SSRAA STU 2.0 adds mandatory PKCE (S256) and state for all
/// authorization code flows; this is a server-side policy configured via
/// <see cref="ServerSettings.SsraaVersion"/>.
/// </summary>
[Collection("Udap.Auth.Server")]
public class Stu2ComplianceTests
{
    private readonly ITestOutputHelper _testOutputHelper;

    public Stu2ComplianceTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
    }

    /// <summary>
    /// Creates a pipeline configured for SSRAA STU 2.0 (PKCE and state required).
    /// </summary>
    private UdapAuthServerPipeline CreateStu2Pipeline()
    {
        var mockPipeline = new UdapAuthServerPipeline();
#if NET9_0_OR_GREATER
        var sureFhirLabsAnchor = X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/SureFhirLabs_CA.cer");
        var intermediateCert = X509CertificateLoader.LoadCertificateFromFile("CertStore/intermediates/SureFhirLabs_Intermediate.cer");
#else
        var sureFhirLabsAnchor = new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer");
        var intermediateCert = new X509Certificate2("CertStore/intermediates/SureFhirLabs_Intermediate.cer");
#endif

        mockPipeline.OnPostConfigureServices += s =>
        {
            s.AddSingleton(new ServerSettings
            {
                DefaultUserScopes = "user/*.read",
                DefaultSystemScopes = "system/*.read",
                SsraaVersion = SsraaVersion.V2_0,
                RequireConsent = false
            });

            s.AddSingleton<IOptionsMonitor<UdapClientOptions>>(new OptionsMonitorForTests<UdapClientOptions>(
                new UdapClientOptions
                {
                    ClientName = "Mock Client",
                    Contacts = new HashSet<string> { "mailto:Joseph.Shook@Surescripts.com" }
                    // UdapVersion defaults to UdapVersionsSupportedValue ("1")
                }));
        };

        mockPipeline.OnPreConfigureServices += (_, s) =>
        {
            s.AddSingleton(mockPipeline.Clients);
            s.AddScoped<IUdapClient>(sp => new UdapClient(
                mockPipeline.BackChannelClient,
                sp.GetRequiredService<UdapClientDiscoveryValidator>(),
                sp.GetRequiredService<IOptionsMonitor<UdapClientOptions>>(),
                sp.GetRequiredService<ILogger<UdapClient>>()));
        };

        mockPipeline.Initialize(enableLogging: true);
        mockPipeline.BrowserClient.AllowAutoRedirect = false;

        mockPipeline.Communities.Add(new Community
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
                    Intermediates =
                    [
                        new Intermediate(intermediateCert)
                        {
                            BeginDate = intermediateCert.NotBefore.ToUniversalTime(),
                            EndDate = intermediateCert.NotAfter.ToUniversalTime(),
                            Name = intermediateCert.Subject,
                            Enabled = true
                        }
                    ]
                }
            ]
        });

        mockPipeline.IdentityScopes.Add(new IdentityResources.OpenId());
        mockPipeline.IdentityScopes.Add(new IdentityResources.Profile());
        mockPipeline.ApiScopes.Add(new ApiScope("user/*.read"));
        mockPipeline.ApiScopes.Add(new ApiScope("system/*.read"));

        mockPipeline.Users.Add(new TestUser
        {
            SubjectId = "bob",
            Username = "bob",
            Claims =
            [
                new Claim("name", "Bob Loblaw"),
                new Claim("email", "bob@loblaw.com")
            ]
        });

        return mockPipeline;
    }

    /// <summary>
    /// Creates a pipeline configured for SSRAA STU 2.0 with explicit overrides for
    /// RequirePkce and/or ForceStateParamOnAuthorizationCode. Passing false for either
    /// tests the opt-out capability (nullable bool semantics).
    /// </summary>
    private UdapAuthServerPipeline CreateStu2PipelineWithOverrides(bool? requirePkce = null, bool? forceState = null)
    {
        var mockPipeline = new UdapAuthServerPipeline();
#if NET9_0_OR_GREATER
        var sureFhirLabsAnchor = X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/SureFhirLabs_CA.cer");
        var intermediateCert = X509CertificateLoader.LoadCertificateFromFile("CertStore/intermediates/SureFhirLabs_Intermediate.cer");
#else
        var sureFhirLabsAnchor = new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer");
        var intermediateCert = new X509Certificate2("CertStore/intermediates/SureFhirLabs_Intermediate.cer");
#endif

        mockPipeline.OnPostConfigureServices += s =>
        {
            s.AddSingleton(new ServerSettings
            {
                DefaultUserScopes = "user/*.read",
                DefaultSystemScopes = "system/*.read",
                SsraaVersion = SsraaVersion.V2_0,
                RequireConsent = false,
                RequirePkce = requirePkce,
                ForceStateParamOnAuthorizationCode = forceState
            });

            s.AddSingleton<IOptionsMonitor<UdapClientOptions>>(new OptionsMonitorForTests<UdapClientOptions>(
                new UdapClientOptions
                {
                    ClientName = "Mock Client",
                    Contacts = new HashSet<string> { "mailto:Joseph.Shook@Surescripts.com" }
                }));
        };

        mockPipeline.OnPreConfigureServices += (_, s) =>
        {
            s.AddSingleton(mockPipeline.Clients);
            s.AddScoped<IUdapClient>(sp => new UdapClient(
                mockPipeline.BackChannelClient,
                sp.GetRequiredService<UdapClientDiscoveryValidator>(),
                sp.GetRequiredService<IOptionsMonitor<UdapClientOptions>>(),
                sp.GetRequiredService<ILogger<UdapClient>>()));
        };

        mockPipeline.Initialize(enableLogging: true);
        mockPipeline.BrowserClient.AllowAutoRedirect = false;

        mockPipeline.Communities.Add(new Community
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
                    Intermediates =
                    [
                        new Intermediate(intermediateCert)
                        {
                            BeginDate = intermediateCert.NotBefore.ToUniversalTime(),
                            EndDate = intermediateCert.NotAfter.ToUniversalTime(),
                            Name = intermediateCert.Subject,
                            Enabled = true
                        }
                    ]
                }
            ]
        });

        mockPipeline.IdentityScopes.Add(new IdentityResources.OpenId());
        mockPipeline.IdentityScopes.Add(new IdentityResources.Profile());
        mockPipeline.ApiScopes.Add(new ApiScope("user/*.read"));
        mockPipeline.ApiScopes.Add(new ApiScope("system/*.read"));

        mockPipeline.Users.Add(new TestUser
        {
            SubjectId = "bob",
            Username = "bob",
            Claims =
            [
                new Claim("name", "Bob Loblaw"),
                new Claim("email", "bob@loblaw.com")
            ]
        });

        return mockPipeline;
    }

    /// <summary>
    /// Creates a pipeline configured for SSRAA STU 1.1 (PKCE and state optional).
    /// </summary>
    private UdapAuthServerPipeline CreateStu1Pipeline()
    {
        var mockPipeline = new UdapAuthServerPipeline();
#if NET9_0_OR_GREATER
        var sureFhirLabsAnchor = X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/SureFhirLabs_CA.cer");
        var intermediateCert = X509CertificateLoader.LoadCertificateFromFile("CertStore/intermediates/SureFhirLabs_Intermediate.cer");
#else
        var sureFhirLabsAnchor = new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer");
        var intermediateCert = new X509Certificate2("CertStore/intermediates/SureFhirLabs_Intermediate.cer");
#endif

        mockPipeline.OnPostConfigureServices += s =>
        {
            s.AddSingleton(new ServerSettings
            {
                DefaultUserScopes = "user/*.read",
                DefaultSystemScopes = "system/*.read",
                SsraaVersion = SsraaVersion.V1_1,
                RequireConsent = false
            });

            s.AddSingleton<IOptionsMonitor<UdapClientOptions>>(new OptionsMonitorForTests<UdapClientOptions>(
                new UdapClientOptions
                {
                    ClientName = "Mock Client",
                    Contacts = new HashSet<string> { "mailto:Joseph.Shook@Surescripts.com" }
                    // UdapVersion defaults to UdapVersionsSupportedValue ("1")
                }));
        };

        mockPipeline.OnPreConfigureServices += (_, s) =>
        {
            s.AddSingleton(mockPipeline.Clients);
            s.AddScoped<IUdapClient>(sp => new UdapClient(
                mockPipeline.BackChannelClient,
                sp.GetRequiredService<UdapClientDiscoveryValidator>(),
                sp.GetRequiredService<IOptionsMonitor<UdapClientOptions>>(),
                sp.GetRequiredService<ILogger<UdapClient>>()));
        };

        mockPipeline.Initialize(enableLogging: true);
        mockPipeline.BrowserClient.AllowAutoRedirect = false;

        mockPipeline.Communities.Add(new Community
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
                    Intermediates =
                    [
                        new Intermediate(intermediateCert)
                        {
                            BeginDate = intermediateCert.NotBefore.ToUniversalTime(),
                            EndDate = intermediateCert.NotAfter.ToUniversalTime(),
                            Name = intermediateCert.Subject,
                            Enabled = true
                        }
                    ]
                }
            ]
        });

        mockPipeline.IdentityScopes.Add(new IdentityResources.OpenId());
        mockPipeline.IdentityScopes.Add(new IdentityResources.Profile());
        mockPipeline.ApiScopes.Add(new ApiScope("user/*.read"));
        mockPipeline.ApiScopes.Add(new ApiScope("system/*.read"));

        mockPipeline.Users.Add(new TestUser
        {
            SubjectId = "bob",
            Username = "bob",
            Claims =
            [
                new Claim("name", "Bob Loblaw"),
                new Claim("email", "bob@loblaw.com")
            ]
        });

        return mockPipeline;
    }

    // -----------------------------------------------------------------------
    // SSRAA STU 2.0 server behaviour
    // -----------------------------------------------------------------------

    /// <summary>
    /// Any UDAP client registering with udap="1" succeeds on an STU 2.0 server.
    /// The udap field is always "1" — it identifies the UDAP base protocol version,
    /// not the SSRAA IG version.
    /// </summary>
    [Fact]
    public async Task UdapRegistration_OnStu2Server_Succeeds()
    {
        var mockPipeline = CreateStu2Pipeline();
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
            .WithClientName("Test Client")
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .WithContacts(new HashSet<string> { "mailto:test@example.com" })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("openid user/*.read")
            .WithResponseTypes(new List<string> { "code" })
            .WithRedirectUrls(new List<string> { "https://code_client/callback" })
            .BuildSoftwareStatement();

        // The udap field is always "1" (UDAP protocol version) for both SSRAA versions.
        var requestBody = new UdapRegisterRequest(
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        var response = await mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var resultDocument = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        Assert.NotNull(resultDocument);
        Assert.NotNull(resultDocument!.ClientId);
    }

    /// <summary>
    /// On an STU 2.0 server, registration sets client.RequirePkce = true for all UDAP clients.
    /// PKCE enforcement is a server-wide policy, not a per-client setting based on the udap field.
    /// </summary>
    [Fact]
    public async Task Stu2Server_SetsClientRequirePkce_OnRegistration()
    {
        var mockPipeline = CreateStu2Pipeline();
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
            .WithClientName("Test Client")
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .WithContacts(new HashSet<string> { "mailto:test@example.com" })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("openid user/*.read")
            .WithResponseTypes(new List<string> { "code" })
            .WithRedirectUrls(new List<string> { "https://code_client/callback" })
            .BuildSoftwareStatement();

        var requestBody = new UdapRegisterRequest(
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        var response = await mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var resultDocument = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();

        var client = mockPipeline.Clients.Single(c => c.ClientId == resultDocument!.ClientId);
        Assert.True(client.RequirePkce, "STU 2.0 server policy requires PKCE for all UDAP auth-code clients");
    }

    /// <summary>
    /// On an STU 2.0 server, an authorize request missing the code_challenge is rejected.
    /// Providing code_challenge_method without code_challenge surfaces the error via the
    /// middleware as a 400 JSON response.
    /// </summary>
    [Fact]
    public async Task Stu2Server_RequiresPkce_ForAuthCodeClients()
    {
        var mockPipeline = CreateStu2Pipeline();
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
            .WithClientName("Test Client")
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .WithContacts(new HashSet<string> { "mailto:test@example.com" })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("openid user/*.read")
            .WithResponseTypes(new List<string> { "code" })
            .WithRedirectUrls(new List<string> { "https://code_client/callback" })
            .BuildSoftwareStatement();

        var requestBody = new UdapRegisterRequest(
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        mockPipeline.BrowserClient.AllowAutoRedirect = true;
        var response = await mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var resultDocument = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();

        await mockPipeline.LoginAsync("bob");

        // code_challenge_method is supplied without code_challenge — Duende rejects this
        // and the middleware converts the error page redirect into a 400 JSON response.
        var url = mockPipeline.CreateAuthorizeUrl(
            clientId: resultDocument!.ClientId!,
            responseType: "code",
            scope: "openid",
            redirectUri: "https://code_client/callback",
            state: Guid.NewGuid().ToString(),
            nonce: Guid.NewGuid().ToString(),
            codeChallengeMethod: OidcConstants.CodeChallengeMethods.Sha256
            // code_challenge intentionally omitted
        );

        mockPipeline.BrowserClient.AllowAutoRedirect = false;
        response = await mockPipeline.BrowserClient.GetAsync(url);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var errorMessage = await response.Content.ReadFromJsonAsync<ErrorMessage>();
        Assert.NotNull(errorMessage);
        Assert.Equal("invalid_request", errorMessage!.Error);
        Assert.Equal("code challenge required", errorMessage.ErrorDescription, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// On an STU 2.0 server, an authorize request missing the state parameter is redirected
    /// back to the client with error=invalid_request.
    /// </summary>
    [Fact]
    public async Task Stu2Server_RequiresState_ForAuthCodeClients()
    {
        var mockPipeline = CreateStu2Pipeline();
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
            .WithClientName("Test Client")
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .WithContacts(new HashSet<string> { "mailto:test@example.com" })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("openid user/*.read")
            .WithResponseTypes(new List<string> { "code" })
            .WithRedirectUrls(new List<string> { "https://code_client/callback" })
            .BuildSoftwareStatement();

        var requestBody = new UdapRegisterRequest(
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        mockPipeline.BrowserClient.AllowAutoRedirect = true;
        var response = await mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var resultDocument = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();

        await mockPipeline.LoginAsync("bob");

        var udapClient = mockPipeline.Resolve<IUdapClient>();
        var pkce = udapClient.GeneratePkce();

        // Authorize without state — STU 2.0 server middleware intercepts and redirects with error.
        var url = mockPipeline.CreateAuthorizeUrl(
            clientId: resultDocument!.ClientId!,
            responseType: "code",
            scope: "openid",
            redirectUri: "https://code_client/callback",
            nonce: Guid.NewGuid().ToString(),
            codeChallenge: pkce.CodeChallenge,
            codeChallengeMethod: OidcConstants.CodeChallengeMethods.Sha256
            // state intentionally omitted
        );

        mockPipeline.BrowserClient.AllowAutoRedirect = false;
        response = await mockPipeline.BrowserClient.GetAsync(url);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.NotNull(response.Headers.Location);
        var queryParams = QueryHelpers.ParseQuery(response.Headers.Location!.Query);
        Assert.Contains(queryParams, p => p.Key == "error" && p.Value == "invalid_request");
        Assert.Contains(queryParams, p => p.Key == "error_description" && p.Value.ToString().Contains("Missing state"));
    }

    // -----------------------------------------------------------------------
    // SSRAA STU 1.1 server behaviour
    // -----------------------------------------------------------------------

    /// <summary>
    /// Any UDAP client registering with udap="1" succeeds on an STU 1.1 server.
    /// </summary>
    [Fact]
    public async Task UdapRegistration_OnStu1Server_Succeeds()
    {
        var mockPipeline = CreateStu1Pipeline();
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
            .WithClientName("Test Client")
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .WithContacts(new HashSet<string> { "mailto:test@example.com" })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("openid user/*.read")
            .WithResponseTypes(new List<string> { "code" })
            .WithRedirectUrls(new List<string> { "https://code_client/callback" })
            .BuildSoftwareStatement();

        var requestBody = new UdapRegisterRequest(
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        var response = await mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var resultDocument = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        Assert.NotNull(resultDocument);
        Assert.NotNull(resultDocument!.ClientId);
    }

    /// <summary>
    /// On an STU 1.1 server, registration does not set client.RequirePkce.
    /// PKCE is optional under STU 1.1.
    /// </summary>
    [Fact]
    public async Task Stu1Server_DoesNotSetClientRequirePkce_OnRegistration()
    {
        var mockPipeline = CreateStu1Pipeline();
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
            .WithClientName("Test Client")
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .WithContacts(new HashSet<string> { "mailto:test@example.com" })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("openid user/*.read")
            .WithResponseTypes(new List<string> { "code" })
            .WithRedirectUrls(new List<string> { "https://code_client/callback" })
            .BuildSoftwareStatement();

        var requestBody = new UdapRegisterRequest(
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        var response = await mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var resultDocument = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();

        var client = mockPipeline.Clients.Single(c => c.ClientId == resultDocument!.ClientId);
        Assert.False(client.RequirePkce, "STU 1.1 server does not require PKCE");
    }

    /// <summary>
    /// On an STU 1.1 server, an authorize request without the state parameter succeeds.
    /// The middleware does not enforce state under STU 1.1.
    /// </summary>
    [Fact]
    public async Task Stu1Server_DoesNotRequireState_ForAuthCodeClients()
    {
        var mockPipeline = CreateStu1Pipeline();
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
            .WithClientName("Test Client")
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .WithContacts(new HashSet<string> { "mailto:test@example.com" })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("openid user/*.read")
            .WithResponseTypes(new List<string> { "code" })
            .WithRedirectUrls(new List<string> { "https://code_client/callback" })
            .BuildSoftwareStatement();

        var requestBody = new UdapRegisterRequest(
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        mockPipeline.BrowserClient.AllowAutoRedirect = true;
        var response = await mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var resultDocument = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();

        await mockPipeline.LoginAsync("bob");

        // Authorize without state — STU 1.1 server allows this.
        var url = mockPipeline.CreateAuthorizeUrl(
            clientId: resultDocument!.ClientId!,
            responseType: "code",
            scope: "openid",
            redirectUri: "https://code_client/callback",
            nonce: Guid.NewGuid().ToString()
            // state intentionally omitted — allowed under STU 1.1
        );

        mockPipeline.BrowserClient.AllowAutoRedirect = false;
        response = await mockPipeline.BrowserClient.GetAsync(url);

        // Should redirect to callback with code, not an error
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.NotNull(response.Headers.Location);
        Assert.Contains("https://code_client/callback", response.Headers.Location!.AbsoluteUri);
        var queryParams = QueryHelpers.ParseQuery(response.Headers.Location.Query);
        Assert.Contains(queryParams, p => p.Key == "code");
        Assert.DoesNotContain(queryParams, p => p.Key == "error");
    }

    /// <summary>
    /// On an STU 2.0 server, an authorize request with NO PKCE parameters at all
    /// (neither code_challenge nor code_challenge_method) is rejected.
    /// This covers the scenario where a client simply omits PKCE entirely.
    /// </summary>
    [Fact]
    public async Task Stu2Server_RequiresPkce_NoPkceParamsAtAll()
    {
        var mockPipeline = CreateStu2Pipeline();
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
            .WithClientName("Test Client")
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .WithContacts(new HashSet<string> { "mailto:test@example.com" })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("openid user/*.read")
            .WithResponseTypes(new List<string> { "code" })
            .WithRedirectUrls(new List<string> { "https://code_client/callback" })
            .BuildSoftwareStatement();

        var requestBody = new UdapRegisterRequest(
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        mockPipeline.BrowserClient.AllowAutoRedirect = true;
        var response = await mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var resultDocument = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();

        await mockPipeline.LoginAsync("bob");

        // Authorize with NO PKCE parameters at all — no code_challenge, no code_challenge_method
        var url = mockPipeline.CreateAuthorizeUrl(
            clientId: resultDocument!.ClientId!,
            responseType: "code",
            scope: "openid",
            redirectUri: "https://code_client/callback",
            state: Guid.NewGuid().ToString(),
            nonce: Guid.NewGuid().ToString()
            // code_challenge and code_challenge_method both omitted
        );

        mockPipeline.BrowserClient.AllowAutoRedirect = false;
        response = await mockPipeline.BrowserClient.GetAsync(url);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var errorMessage = await response.Content.ReadFromJsonAsync<ErrorMessage>();
        Assert.NotNull(errorMessage);
        Assert.Equal("invalid_request", errorMessage!.Error);
        Assert.Equal("code challenge required", errorMessage.ErrorDescription, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// On an STU 2.0 server with RequirePkce explicitly set to false, PKCE is not required.
    /// This tests the opt-out capability.
    /// </summary>
    [Fact]
    public async Task Stu2Server_RequirePkceOptOut_AllowsNoPkce()
    {
        var mockPipeline = CreateStu2PipelineWithOverrides(requirePkce: false);
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
            .WithClientName("Test Client")
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .WithContacts(new HashSet<string> { "mailto:test@example.com" })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("openid user/*.read")
            .WithResponseTypes(new List<string> { "code" })
            .WithRedirectUrls(new List<string> { "https://code_client/callback" })
            .BuildSoftwareStatement();

        var requestBody = new UdapRegisterRequest(
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        mockPipeline.BrowserClient.AllowAutoRedirect = true;
        var response = await mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var resultDocument = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();

        var client = mockPipeline.Clients.Single(c => c.ClientId == resultDocument!.ClientId);
        Assert.False(client.RequirePkce, "RequirePkce=false should override V2_0 default");

        await mockPipeline.LoginAsync("bob");

        // Authorize without PKCE — should succeed because RequirePkce is explicitly false
        var url = mockPipeline.CreateAuthorizeUrl(
            clientId: resultDocument!.ClientId!,
            responseType: "code",
            scope: "openid",
            redirectUri: "https://code_client/callback",
            state: Guid.NewGuid().ToString(),
            nonce: Guid.NewGuid().ToString()
        );

        mockPipeline.BrowserClient.AllowAutoRedirect = false;
        response = await mockPipeline.BrowserClient.GetAsync(url);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.NotNull(response.Headers.Location);
        Assert.Contains("https://code_client/callback", response.Headers.Location!.AbsoluteUri);
        var queryParams = QueryHelpers.ParseQuery(response.Headers.Location.Query);
        Assert.Contains(queryParams, p => p.Key == "code");
        Assert.DoesNotContain(queryParams, p => p.Key == "error");
    }

    /// <summary>
    /// On an STU 2.0 server with ForceStateParamOnAuthorizationCode explicitly set to false,
    /// the state parameter is not required. This tests the opt-out capability.
    /// </summary>
    [Fact]
    public async Task Stu2Server_ForceStateOptOut_AllowsNoState()
    {
        var mockPipeline = CreateStu2PipelineWithOverrides(forceState: false);
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
            .WithClientName("Test Client")
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .WithContacts(new HashSet<string> { "mailto:test@example.com" })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("openid user/*.read")
            .WithResponseTypes(new List<string> { "code" })
            .WithRedirectUrls(new List<string> { "https://code_client/callback" })
            .BuildSoftwareStatement();

        var requestBody = new UdapRegisterRequest(
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        mockPipeline.BrowserClient.AllowAutoRedirect = true;
        var response = await mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var resultDocument = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();

        await mockPipeline.LoginAsync("bob");

        var udapClient = mockPipeline.Resolve<IUdapClient>();
        var pkce = udapClient.GeneratePkce();

        // Authorize without state but with PKCE (PKCE is still required by V2_0 default)
        // State is opted out via ForceStateParamOnAuthorizationCode=false
        var url = mockPipeline.CreateAuthorizeUrl(
            clientId: resultDocument!.ClientId!,
            responseType: "code",
            scope: "openid",
            redirectUri: "https://code_client/callback",
            nonce: Guid.NewGuid().ToString(),
            codeChallenge: pkce.CodeChallenge,
            codeChallengeMethod: OidcConstants.CodeChallengeMethods.Sha256
            // state intentionally omitted
        );

        mockPipeline.BrowserClient.AllowAutoRedirect = false;
        response = await mockPipeline.BrowserClient.GetAsync(url);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.NotNull(response.Headers.Location);
        Assert.Contains("https://code_client/callback", response.Headers.Location!.AbsoluteUri);
        var queryParams = QueryHelpers.ParseQuery(response.Headers.Location.Query);
        Assert.Contains(queryParams, p => p.Key == "code");
        Assert.DoesNotContain(queryParams, p => p.Key == "error");
    }

    // -----------------------------------------------------------------------
    // udap field validation (applies to any server version)
    // -----------------------------------------------------------------------

    /// <summary>
    /// A registration request with a non-"1" value for the udap field is rejected.
    /// The UDAP base protocol is at version 1; no other value is valid.
    /// </summary>
    [Fact]
    public async Task InvalidUdapVersion_ReturnsError()
    {
        var mockPipeline = CreateStu2Pipeline();
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
            .WithClientName("Invalid Version Client")
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .WithContacts(new HashSet<string> { "mailto:test@example.com" })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("openid user/*.read")
            .WithResponseTypes(new List<string> { "code" })
            .WithRedirectUrls(new List<string> { "https://code_client/callback" })
            .BuildSoftwareStatement();

        var requestBody = new UdapRegisterRequest(
            signedSoftwareStatement,
            "3" // Invalid — UDAP protocol only has version "1"
        );

        var response = await mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var errorResponse = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();
        Assert.NotNull(errorResponse);
        Assert.Equal(UdapDynamicClientRegistrationErrors.InvalidClientMetadata, errorResponse!.Error);
        Assert.Contains("Unsupported UDAP version", errorResponse.ErrorDescription);
    }

    /// <summary>
    /// A registration request with an empty udap field is rejected.
    /// </summary>
    [Fact]
    public async Task MissingUdapVersion_ReturnsError()
    {
        var mockPipeline = CreateStu2Pipeline();
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
            .WithClientName("Missing Version Client")
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .WithContacts(new HashSet<string> { "mailto:test@example.com" })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("openid user/*.read")
            .WithResponseTypes(new List<string> { "code" })
            .WithRedirectUrls(new List<string> { "https://code_client/callback" })
            .BuildSoftwareStatement();

        var requestBody = new { software_statement = signedSoftwareStatement, udap = "" };

        var response = await mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var errorResponse = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();
        Assert.NotNull(errorResponse);
        Assert.Equal(UdapDynamicClientRegistrationErrors.InvalidClientMetadata, errorResponse!.Error);
        Assert.Contains("udap version is missing", errorResponse.ErrorDescription);
    }
}
