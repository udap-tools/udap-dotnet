#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Web;
using Duende.IdentityServer;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Test;
using FluentAssertions;
using FluentAssertions.Common;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using Udap.Client.Client;
using Udap.Client.Configuration;
using Udap.Common;
using Udap.Common.Certificates;
using Udap.Common.Models;
using Udap.Model;
using Udap.Model.Access;
using Udap.Model.Registration;
using Udap.Server.Configuration;
using Udap.Server.Models;
using Udap.Server.Security.Authentication.TieredOAuth;
using Udap.Util.Extensions;
using UdapServer.Tests.Common;
using Xunit.Abstractions;

namespace UdapServer.Tests.Conformance.Tiered;

[Collection("Udap.Auth.Server")]
public class TieredOauthTests
{
    private readonly ITestOutputHelper _testOutputHelper;

    private readonly UdapAuthServerPipeline _mockAuthorServerPipeline = new();
    private readonly UdapIdentityServerPipeline _mockIdPPipeline = new();
    private readonly UdapIdentityServerPipeline _mockIdPPipeline2 = new("https://idpserver2", "appsettings.Idp2.json");
    
    private readonly X509Certificate2 _community1Anchor;
    private readonly X509Certificate2 _community1IntermediateCert;
    private readonly X509Certificate2 _community2Anchor;
    private readonly X509Certificate2 _community2IntermediateCert;

    public TieredOauthTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
        _community1Anchor = new X509Certificate2("CertStore/anchors/caLocalhostCert.cer");
        _community1IntermediateCert = new X509Certificate2("CertStore/intermediates/intermediateLocalhostCert.cer");

        _community2Anchor = new X509Certificate2("CertStore/anchors/caLocalhostCert2.cer");
        _community2IntermediateCert = new X509Certificate2("CertStore/intermediates/intermediateLocalhostCert2.cer");
            }

    private void BuildUdapAuthorizationServer(List<string>? tieredOAuthScopes = null)
    {
        _mockAuthorServerPipeline.OnPostConfigureServices += services =>
        {
            services.AddSingleton(new ServerSettings
            {
                ForceStateParamOnAuthorizationCode = true, //false (default)
                RequireConsent = false
            });

            services.AddSingleton<IOptionsMonitor<UdapClientOptions>>(new OptionsMonitorForTests<UdapClientOptions>(
                new UdapClientOptions
                {
                    ClientName = "AuthServer Client",
                    Contacts = new HashSet<string> { "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com" },
                    TieredOAuthClientLogo = "https://server/UDAP_Ecosystem_Gears.png"
                })
            );

            //
            // Allow logo resolve back to udap.auth server
            //
            services.AddSingleton<HttpClient>(_ => _mockAuthorServerPipeline.BrowserClient);

            if (tieredOAuthScopes != null)
            {
                services.ConfigureAll<TieredOAuthAuthenticationOptions>(options =>
                {
                    options.Scope.Clear();
                    foreach (var tieredOAuthScope in tieredOAuthScopes)
                    {
                        options.Scope.Add(tieredOAuthScope);
                    }
                });
            }
        };

        _mockAuthorServerPipeline.OnPreConfigureServices += (builderContext, services) =>
        {
            // This registers Clients as List<Client> so downstream I can pick it up in InMemoryUdapClientRegistrationStore
            // Duende's AddInMemoryClients extension registers as IEnumerable<Client> and is used in InMemoryClientStore as readonly.
            // It was not intended to work with the concept of a dynamic client registration.
            services.AddSingleton(_mockAuthorServerPipeline.Clients);

            services.Configure<UdapFileCertStoreManifest>(builderContext.Configuration.GetSection(Constants.UDAP_FILE_STORE_MANIFEST));

            services.AddAuthentication()
                //
                // By convention the scheme name should match the community name in UdapFileCertStoreManifest
                // to allow discovery of the IdPBaseUrl
                //
                .AddTieredOAuthForTests(options =>
                    {
                        options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                    },
                    _mockAuthorServerPipeline,
                    _mockIdPPipeline,
                    _mockIdPPipeline2);


            services.AddAuthorization(); // required for TieredOAuth Testing


            services.ConfigureAll<OpenIdConnectOptions>(options =>
            {
                options.BackchannelHttpHandler = _mockIdPPipeline2.Server?.CreateHandler();
            });


            using var serviceProvider = services.BuildServiceProvider();

        };  

        _mockAuthorServerPipeline.Initialize(enableLogging: true);
        _mockAuthorServerPipeline.BrowserClient.AllowAutoRedirect = false;
        

        _mockAuthorServerPipeline.Communities.Add(new Community
        {
            Id = 0,
            Name = "https://idpserver",
            Enabled = true,
            Default = true,
            Anchors = new[]
            {
                new Anchor(_community1Anchor, "https://idpserver")
                {
                    BeginDate = _community1Anchor.NotBefore.ToUniversalTime(),
                    EndDate = _community1Anchor.NotAfter.ToUniversalTime(),
                    Name = _community1Anchor.Subject,
                    Enabled = true,
                    Intermediates = new List<Intermediate>()
                    {
                        new(_community1IntermediateCert)
                        {
                            BeginDate = _community1IntermediateCert.NotBefore.ToUniversalTime(),
                            EndDate = _community1IntermediateCert.NotAfter.ToUniversalTime(),
                            Name = _community1IntermediateCert.Subject,
                            Enabled = true
                        }
                    }
                }
            }
        });

        _mockAuthorServerPipeline.Communities.Add(new Community
        {
            Id = 1,
            Name = "udap://idp-community-2",
            Enabled = true,
            Default = true,
            Anchors = new[]
            {
                new Anchor(_community2Anchor, "udap://idp-community-2")
                {
                    BeginDate = _community2Anchor.NotBefore.ToUniversalTime(),
                    EndDate = _community2Anchor.NotAfter.ToUniversalTime(),
                    Name = _community2Anchor.Subject,
                    Enabled = true,
                    Intermediates = new List<Intermediate>()
                    {
                        new(_community2IntermediateCert)
                        {
                            BeginDate =  _community2IntermediateCert.NotBefore.ToUniversalTime(),
                            EndDate = _community2IntermediateCert.NotAfter.ToUniversalTime(),
                            Name = _community2IntermediateCert.Subject,
                            Enabled = true
                        }
                    }
                }
            }
        });


        // _mockAuthorServerPipeline.


        _mockAuthorServerPipeline.IdentityScopes.Add(new IdentityResources.OpenId());
        _mockAuthorServerPipeline.IdentityScopes.Add(new IdentityResources.Profile());
        _mockAuthorServerPipeline.ApiScopes.Add(new UdapApiScopes.Udap());

        _mockAuthorServerPipeline.ApiScopes.Add(new ApiScope("user/*.read"));

        _mockAuthorServerPipeline.Users.Add(new TestUser
        {
            SubjectId = "bob",
            Username = "bob",
            Claims = new[]
            {
                new Claim("name", "Bob Loblaw"),
                new Claim("email", "bob@loblaw.com"),
                new Claim("role", "Attorney")
            }
        });

        _mockAuthorServerPipeline.UserStore = new TestUserStore(_mockAuthorServerPipeline.Users);
    }

    private void BuildUdapIdentityProvider1()
    {
        _mockIdPPipeline.OnPostConfigureServices += services =>
        {
            services.AddSingleton(
                sp =>
                {
                    var serverSettings = sp.GetService<IOptions<ServerSettings>>().Value; // must resolve to trigger the post config at TieredIdpServerSettings
                    serverSettings.DefaultUserScopes = "udap";
                    serverSettings.DefaultSystemScopes = "udap";
                    // ForceStateParamOnAuthorizationCode = false (default)
                    serverSettings.AlwaysIncludeUserClaimsInIdToken = true;
                    serverSettings.RequireConsent = false;
                    
                    return serverSettings;
                });
           

            // This registers Clients as List<Client> so downstream I can pick it up in InMemoryUdapClientRegistrationStore
            // Duende's AddInMemoryClients extension registers as IEnumerable<Client> and is used in InMemoryClientStore as readonly.
            // It was not intended to work with the concept of a dynamic client registration.
            services.AddSingleton(_mockIdPPipeline.Clients);

            //
            // Allow logo resolve back to udap.auth server
            //
            services.AddSingleton<HttpClient>(sp => _mockAuthorServerPipeline.BrowserClient);
        };
        

        _mockIdPPipeline.Initialize(enableLogging: true);
        Debug.Assert(_mockIdPPipeline.BrowserClient != null, "_mockIdPPipeline.BrowserClient != null");
        _mockIdPPipeline.BrowserClient.AllowAutoRedirect = false;

        _mockIdPPipeline.Communities.Add(new Community
        {
            Name = "udap://idp-community-1",
            Enabled = true,
            Default = true,
            Anchors = new[]
            {
                new Anchor(_community1Anchor, "udap://idp-community-1")
                {
                    BeginDate = _community1Anchor.NotBefore.ToUniversalTime(),
                    EndDate = _community1Anchor.NotAfter.ToUniversalTime(),
                    Name = _community1Anchor.Subject,
                    Enabled = true,
                    Intermediates = new List<Intermediate>()
                    {
                        new(_community1IntermediateCert)
                        {
                            BeginDate =  _community1IntermediateCert.NotBefore.ToUniversalTime(),
                            EndDate = _community1IntermediateCert.NotAfter.ToUniversalTime(),
                            Name = _community1IntermediateCert.Subject,
                            Enabled = true
                        }
                    }
                }
            }
        });

        _mockIdPPipeline.IdentityScopes.Add(new IdentityResources.OpenId());
        _mockIdPPipeline.IdentityScopes.Add(new UdapIdentityResources.Profile());
        _mockIdPPipeline.ApiScopes.Add(new UdapApiScopes.Udap());
        _mockIdPPipeline.IdentityScopes.Add(new IdentityResources.Email());
        _mockIdPPipeline.IdentityScopes.Add(new UdapIdentityResources.FhirUser());

        _mockIdPPipeline.Users.Add(new TestUser
        {
            SubjectId = "bob",
            Username = "bob",
            Claims = new[]
            {
                new Claim("name", "Bob Loblaw"),
                new Claim("email", "bob@loblaw.com"),
                new Claim("role", "Attorney"),
                new Claim("hl7_identifier", "123")
            }
        });

        // Allow pipeline to sign in during Login
        _mockIdPPipeline.Subject = new IdentityServerUser("bob").CreatePrincipal();
    }

    private void BuildUdapIdentityProvider2()
    {
        _mockIdPPipeline2.OnPostConfigureServices += services =>
        {
            services.AddSingleton(
                sp =>
                {
                    var serverSettings = sp.GetService<IOptions<ServerSettings>>().Value;
                    serverSettings.DefaultUserScopes = "udap";
                    serverSettings.DefaultSystemScopes = "udap";
                    // ForceStateParamOnAuthorizationCode = false (default)
                    serverSettings.AlwaysIncludeUserClaimsInIdToken = true;
                    serverSettings.RequireConsent = false;

                    return serverSettings;
                });
            

            // This registers Clients as List<Client> so downstream I can pick it up in InMemoryUdapClientRegistrationStore
            // Duende's AddInMemoryClients extension registers as IEnumerable<Client> and is used in InMemoryClientStore as readonly.
            // It was not intended to work with the concept of a dynamic client registration.
            services.AddSingleton(_mockIdPPipeline2.Clients);

            //
            // Allow logo resolve back to udap.auth server
            //
            services.AddSingleton<HttpClient>(sp => _mockAuthorServerPipeline.BrowserClient);
        };

       

        _mockIdPPipeline2.Initialize(enableLogging: true);
        Debug.Assert(_mockIdPPipeline2.BrowserClient != null, "_mockIdPPipeline2.BrowserClient != null");
        _mockIdPPipeline2.BrowserClient.AllowAutoRedirect = false;

        _mockIdPPipeline2.Communities.Add(new Community
        {
            Name = "udap://idp-community-2",
            Enabled = true,
            Default = true,
            Anchors = new[]
            {
                new Anchor(_community2Anchor, "udap://idp-community-2")
                {
                    BeginDate = _community2Anchor.NotBefore.ToUniversalTime(),
                    EndDate = _community2Anchor.NotAfter.ToUniversalTime(),
                    Name = _community2Anchor.Subject,
                    Enabled = true,
                    Intermediates = new List<Intermediate>()
                    {
                        new(_community2IntermediateCert)
                        {
                            BeginDate =  _community2IntermediateCert.NotBefore.ToUniversalTime(),
                            EndDate = _community2IntermediateCert.NotAfter.ToUniversalTime(),
                            Name = _community2IntermediateCert.Subject,
                            Enabled = true
                        }
                    }
                }
            }
        });

        _mockIdPPipeline2.IdentityScopes.Add(new IdentityResources.OpenId());
        _mockIdPPipeline2.IdentityScopes.Add(new UdapIdentityResources.Profile());
        _mockIdPPipeline2.ApiScopes.Add(new UdapApiScopes.Udap());
        _mockIdPPipeline2.IdentityScopes.Add(new IdentityResources.Email());
        _mockIdPPipeline2.IdentityScopes.Add(new UdapIdentityResources.FhirUser());

        _mockIdPPipeline2.Users.Add(new TestUser
        {
            SubjectId = "bob",
            Username = "bob",
            Claims = new[]
            {
                new Claim("name", "Bob Loblaw"),
                new Claim("email", "bob@loblaw.com"),
                new Claim("role", "Attorney"),
                new Claim("hl7_identifier", "123")
            }
        });

        // Allow pipeline to sign in during Login
        _mockIdPPipeline2.Subject = new IdentityServerUser("bob").CreatePrincipal();
    }

    /// <summary>
    /// 
    /// </summary>
    /// <returns></returns>
    [Fact]
    public async Task ClientAuthorize_IdPDiscovery_IdPRegistration_IdPAuthAccess_ClientAuthAccess_Test()
    {
        BuildUdapAuthorizationServer();
        BuildUdapIdentityProvider1();
        

        // Register client with auth server
        var resultDocument = await RegisterClientWithAuthServer();
        _mockAuthorServerPipeline.RemoveSessionCookie();
        _mockAuthorServerPipeline.RemoveLoginCookie();
        resultDocument.Should().NotBeNull();
        resultDocument!.ClientId.Should().NotBeNull();

        var clientId = resultDocument.ClientId!;

        var dynamicIdp = _mockAuthorServerPipeline.ApplicationServices.GetRequiredService<DynamicIdp>();
        dynamicIdp.Name = _mockIdPPipeline.BaseUrl;

        //////////////////////
        // ClientAuthorize
        //////////////////////

        // Data Holder's Auth Server validates Identity Provider's Server software statement

        var clientState = Guid.NewGuid().ToString();

        // Builds https://server/connect/authorize plus query params
        var clientAuthorizeUrl = _mockAuthorServerPipeline.CreateAuthorizeUrl(
            clientId: clientId,
            responseType: "code",
            scope: "udap openid user/*.read",
            redirectUri: "https://code_client/callback",
            state: clientState,
            extra: new
            {
                idp = "https://idpserver"
            });

        _mockAuthorServerPipeline.BrowserClient.AllowAutoRedirect = false;
        // The BrowserHandler.cs will normally set the cookie to indicate user signed in.
        // We want to skip that and get a redirect to the login page
        _mockAuthorServerPipeline.BrowserClient.AllowCookies = false;
        var response = await _mockAuthorServerPipeline.BrowserClient.GetAsync(clientAuthorizeUrl);
        response.StatusCode.Should().Be(HttpStatusCode.Redirect, await response.Content.ReadAsStringAsync());
        response.Headers.Location.Should().NotBeNull();
        response.Headers.Location!.AbsoluteUri.Should().Contain("https://server/Account/Login");
        // _testOutputHelper.WriteLine(response.Headers.Location!.AbsoluteUri);
        var queryParams = QueryHelpers.ParseQuery(response.Headers.Location.Query);
        queryParams.Should().Contain(p => p.Key == "ReturnUrl");
        queryParams.Should().NotContain(p => p.Key == "code");
        queryParams.Should().NotContain(p => p.Key == "state");

        
        // Pull the inner query params from the ReturnUrl
        var returnUrl = queryParams.Single(p => p.Key == "ReturnUrl").Value.ToString();
        returnUrl.Should().StartWith("/connect/authorize/callback?");
        queryParams = QueryHelpers.ParseQuery(returnUrl);
        queryParams.Single(q => q.Key == "scope").Value.ToString().Should().Contain("udap openid user/*.read");
        queryParams.Single(q => q.Key == "state").Value.Should().BeEquivalentTo(clientState);
        queryParams.Single(q => q.Key == "idp").Value.Should().BeEquivalentTo("https://idpserver");
        
        var schemes = await _mockAuthorServerPipeline.Resolve<IAuthenticationSchemeProvider>().GetAllSchemesAsync();
   
        var sb = new StringBuilder();
        sb.Append("https://server/externallogin/challenge?"); // built in UdapAccount/Login/Index.cshtml.cs
        sb.Append("scheme=").Append(schemes.First().Name);
        sb.Append("&returnUrl=").Append(Uri.EscapeDataString(returnUrl));
        clientAuthorizeUrl = sb.ToString();



        //////////////////////////////////
        //
        // IdPDiscovery
        // IdPRegistration
        // IdPAuthAccess
        //
        //////////////////////////////////


        // Auto Dynamic registration between Auth Server and Identity Provider happens here.
        // /Challenge?
        //      ctx.ChallengeAsync -> launch registered scheme.  In this case the TieredOauthAuthenticationHandler
        //         see: OnExternalLoginChallenge and Challenge(props, scheme) in ExternalLogin/Challenge.cshtml.cs or UdapTieredLogin/Challenge.cshtml.cs
        //      Backchannel
        //          Discovery
        //          Auto registration
        //          externalloging/challenge or in the Udap implementation it is the UdapAccount/Login/Index.cshtml.cs.  XSRF cookie is set here.

        // *** We are here after the request to the IdPs /authorize  call.  If the client is registered already then Discovery and Reg is skipped ***
        //
        //          Authentication request (/authorize?)
        //            User logs in at IdP
        //          Authentication response
        //          Token request
        //          Data Holder incorporates user input into authorization decision
        //


        
        // response after discovery and registration
        _mockAuthorServerPipeline.BrowserClient.AllowCookies = true; // Need to set the idsrv cookie so calls to /authorize will succeed

        _mockAuthorServerPipeline.BrowserClient.GetXsrfCookie("https://server/federation/udap-tiered/signin", new TieredOAuthAuthenticationOptions().CorrelationCookie.Name!).Should().BeNull();
        var backChannelChallengeResponse = await _mockAuthorServerPipeline.BrowserClient.GetAsync(clientAuthorizeUrl);
        _mockAuthorServerPipeline.BrowserClient.GetXsrfCookie("https://server/federation/udap-tiered/signin", new TieredOAuthAuthenticationOptions().CorrelationCookie.Name!).Should().NotBeNull();
        
        backChannelChallengeResponse.StatusCode.Should().Be(HttpStatusCode.Redirect, await backChannelChallengeResponse.Content.ReadAsStringAsync());
        backChannelChallengeResponse.Headers.Location.Should().NotBeNull();
        backChannelChallengeResponse.Headers.Location!.AbsoluteUri.Should().StartWith("https://idpserver/connect/authorize");
        
        // _testOutputHelper.WriteLine(backChannelChallengeResponse.Headers.Location!.AbsoluteUri);
        QueryHelpers.ParseQuery(backChannelChallengeResponse.Headers.Location.Query).Single(p => p.Key == "client_id").Value.Should().NotBeEmpty();
        var backChannelState = QueryHelpers.ParseQuery(backChannelChallengeResponse.Headers.Location.Query).Single(p => p.Key == "state").Value.ToString();
        backChannelState.Should().NotBeNullOrEmpty();
        
        var idpClient = _mockIdPPipeline.Clients.Single(c => c.ClientName == "AuthServer Client");
        idpClient.AlwaysIncludeUserClaimsInIdToken.Should().BeTrue();


        Debug.Assert(_mockIdPPipeline.BrowserClient != null, "_mockIdPPipeline.BrowserClient != null");
        var backChannelAuthResult = await _mockIdPPipeline.BrowserClient.GetAsync(backChannelChallengeResponse.Headers.Location);

        
        backChannelAuthResult.StatusCode.Should().Be(HttpStatusCode.Redirect, await backChannelAuthResult.Content.ReadAsStringAsync());
        // _testOutputHelper.WriteLine(backChannelAuthResult.Headers.Location!.AbsoluteUri);
        backChannelAuthResult.Headers.Location!.AbsoluteUri.Should().StartWith("https://idpserver/Account/Login");

        // Run IdP /Account/Login
        var loginCallbackResult = await _mockIdPPipeline.BrowserClient.GetAsync(backChannelAuthResult.Headers.Location!.AbsoluteUri);
        loginCallbackResult.StatusCode.Should().Be(HttpStatusCode.Redirect, await backChannelAuthResult.Content.ReadAsStringAsync());
        // _testOutputHelper.WriteLine(loginCallbackResult.Headers.Location!.OriginalString);
        loginCallbackResult.Headers.Location!.OriginalString.Should().StartWith("/connect/authorize/callback?");

        // Run IdP /connect/authorize/callback
        var authorizeCallbackResult = await _mockIdPPipeline.BrowserClient.GetAsync(
            $"https://idpserver{loginCallbackResult.Headers.Location!.OriginalString}");
        // _testOutputHelper.WriteLine(authorizeCallbackResult.Headers.Location!.OriginalString);
        authorizeCallbackResult.StatusCode.Should().Be(HttpStatusCode.Redirect, await authorizeCallbackResult.Content.ReadAsStringAsync());
        authorizeCallbackResult.Headers.Location.Should().NotBeNull();
        authorizeCallbackResult.Headers.Location!.AbsoluteUri.Should().StartWith("https://server/federation/udap-tiered/signin?");

        QueryHelpers.ParseQuery(authorizeCallbackResult.Headers.Location.Query).Single(p => p.Key == "code").Value.Should().NotBeEmpty();

        //
        // Validate backchannel state is the same
        //
        backChannelState.Should().BeEquivalentTo(_mockAuthorServerPipeline.GetClientState(authorizeCallbackResult));

        //
        // Ensure client state and back channel state never become the same.
        //
        clientState.Should().NotBeEquivalentTo(backChannelState);

        _mockAuthorServerPipeline.GetSessionCookie().Should().BeNull();
        _mockAuthorServerPipeline.BrowserClient.GetCookie("https://server", "idsrv").Should().BeNull();

        // Run Auth Server /federation/udap-tiered/signin  This is the Registered scheme callback endpoint
        // Allow one redirect to run /connect/token.
        //  Sets Cookies: idsrv.external idsrv.session, and idsrv 
        //  Backchannel calls:
        //      POST https://idpserver/connect/token
        //      GET https://idpserver/.well-known/openid-configuration
        //      GET https://idpserver/.well-known/openid-configuration/jwks
        //
        //  Redirects to https://server/externallogin/callback
        //

        _mockAuthorServerPipeline.BrowserClient.AllowAutoRedirect = true;
        _mockAuthorServerPipeline.BrowserClient.StopRedirectingAfter = 1;
        _mockAuthorServerPipeline.BrowserClient.AllowCookies = true;


        // "https://server/federation/udap-tiered/signin?..."
        var schemeCallbackResult = await _mockAuthorServerPipeline.BrowserClient.GetAsync(authorizeCallbackResult.Headers.Location!.AbsoluteUri);


        schemeCallbackResult.StatusCode.Should().Be(HttpStatusCode.Redirect, await schemeCallbackResult.Content.ReadAsStringAsync());
        schemeCallbackResult.Headers.Location.Should().NotBeNull();
        schemeCallbackResult.Headers.Location!.OriginalString.Should().StartWith("/connect/authorize/callback?");
        // _testOutputHelper.WriteLine(schemeCallbackResult.Headers.Location!.OriginalString);
        // Validate Cookies
        _mockAuthorServerPipeline.GetSessionCookie().Should().NotBeNull();
        _testOutputHelper.WriteLine(_mockAuthorServerPipeline.GetSessionCookie()!.Value);
        _mockAuthorServerPipeline.BrowserClient.GetCookie("https://server", "idsrv").Should().NotBeNull();
        //TODO assert match State and nonce between Auth Server and IdP

        //
        // Check the IdToken in the back channel.  Ensure the HL7_Identifier is in the claims
        //
        // _testOutputHelper.WriteLine(_mockIdPPipeline.IdToken.ToString()); 
        _mockIdPPipeline.IdToken.Should().NotBeNull();
        _mockIdPPipeline.IdToken!.Claims.Should().Contain(c => c.Type == "hl7_identifier");
        _mockIdPPipeline.IdToken.Claims.Single(c => c.Type == "hl7_identifier").Value.Should().Be("123");

        // Run the authServer  https://server/connect/authorize/callback 
        _mockAuthorServerPipeline.BrowserClient.AllowAutoRedirect = false;
        
        var clientCallbackResult = await _mockAuthorServerPipeline.BrowserClient.GetAsync(
                       $"https://server{schemeCallbackResult.Headers.Location!.OriginalString}");

        clientCallbackResult.StatusCode.Should().Be(HttpStatusCode.Redirect, await clientCallbackResult.Content.ReadAsStringAsync());
        clientCallbackResult.Headers.Location.Should().NotBeNull();
        clientCallbackResult.Headers.Location!.AbsoluteUri.Should().StartWith("https://code_client/callback?");
        // _testOutputHelper.WriteLine(clientCallbackResult.Headers.Location!.AbsoluteUri);
        
        
        // Assert match state and nonce between User and Auth Server
        clientState.Should().BeEquivalentTo(_mockAuthorServerPipeline.GetClientState(clientCallbackResult));

        queryParams = QueryHelpers.ParseQuery(clientCallbackResult.Headers.Location.Query);
        queryParams.Should().Contain(p => p.Key == "code");
        var code = queryParams.Single(p => p.Key == "code").Value.ToString();
        // _testOutputHelper.WriteLine($"Code: {code}");
        ////////////////////////////
        //
        // ClientAuthAccess
        //
        ///////////////////////////

        // Get a Access Token (Cash in the code)

        var privateCerts = _mockAuthorServerPipeline.Resolve<IPrivateCertificateStore>();

        var tokenRequest = AccessTokenRequestForAuthorizationCodeBuilder.Create(
            clientId,
            "https://server/connect/token",
            privateCerts.IssuedCertificates.Select(ic => ic.Certificate).First(),
            "https://code_client/callback",
            code)
            .Build();


        dynamicIdp.Name = null; // Influence UdapClient resolution in AddTieredOAuthForTests.
        var udapClient = _mockAuthorServerPipeline.Resolve<IUdapClient>();
        

        var accessToken = await udapClient.ExchangeCodeForTokenResponse(tokenRequest);
        accessToken.Should().NotBeNull();
        accessToken.IdentityToken.Should().NotBeNull();
        var jwt = new JwtSecurityToken(accessToken.IdentityToken);
        new JwtSecurityToken(accessToken.AccessToken).Should().NotBeNull();

        using var jsonDocument = JsonDocument.Parse(jwt.Payload.SerializeToJson());
        var formattedStatement = JsonSerializer.Serialize(
            jsonDocument,
            new JsonSerializerOptions { WriteIndented = true }
        );

        var formattedHeader = Base64UrlEncoder.Decode(jwt.EncodedHeader);
        
        _testOutputHelper.WriteLine(formattedHeader);
        _testOutputHelper.WriteLine(formattedStatement);



        // udap.org Tiered 4.3
        // aud: client_id of Resource Holder (matches client_id in Resource Holder request in Step 3.4)
        jwt.Claims.Should().Contain(c => c.Type == "aud");
        jwt.Claims.Single(c => c.Type == "aud").Value.Should().Be(clientId);

        // iss: IdP’s unique identifying URI (matches idp parameter from Step 2)
        jwt.Claims.Should().Contain(c => c.Type == "iss");
        jwt.Claims.Single(c => c.Type == "iss").Value.Should().Be(UdapAuthServerPipeline.BaseUrl);

        jwt.Claims.Should().Contain(c => c.Type == "hl7_identifier");
        jwt.Claims.Single(c => c.Type == "hl7_identifier").Value.Should().Be("123");




        // sub: unique identifier for user in namespace of issuer, i.e. iss + sub is globally unique

        // TODO: Currently the sub is the code given at access time.  Maybe that is OK?  I could put the clientId in from 
        // backchannel.  But I am not sure I want to show that.  After all it is still globally unique.
        // jwt.Claims.Should().Contain(c => c.Type == "sub");
        // jwt.Claims.Single(c => c.Type == "sub").Value.Should().Be(backChannelClientId);

        // jwt.Claims.Should().Contain(c => c.Type == "sub");
        // jwt.Claims.Single(c => c.Type == "sub").Value.Should().Be(backChannelCode);

        // Todo: Nonce 
        // Todo: Validate claims.  Like missing name and other identity claims.  Maybe add a hl7_identifier
        // Why is idp:TieredOAuth in the returned claims?


        /*
         * new Claim("name", "Bob Loblaw"),
                new Claim("email", "bob@loblaw.com"),
                new Claim("role", "Attorney")
         */
    }

    [Fact] //(Skip = "Dynamic Tiered OAuth Provider WIP")]
    public async Task Tiered_OAuth_With_DynamicProvider()
    {
        BuildUdapAuthorizationServer();
        BuildUdapIdentityProvider2();

        // Register client with auth server
        var resultDocument = await RegisterClientWithAuthServer();
        _mockAuthorServerPipeline.RemoveSessionCookie();
        _mockAuthorServerPipeline.RemoveLoginCookie();
        resultDocument.Should().NotBeNull();
        resultDocument!.ClientId.Should().NotBeNull();

        var clientId = resultDocument.ClientId!;

        var dynamicIdp = _mockAuthorServerPipeline.ApplicationServices.GetRequiredService<DynamicIdp>();
        dynamicIdp.Name = _mockIdPPipeline2.BaseUrl;

        //////////////////////
        // ClientAuthorize
        //////////////////////

        // Data Holder's Auth Server validates Identity Provider's Server software statement

        var clientState = Guid.NewGuid().ToString();

        var clientAuthorizeUrl = _mockAuthorServerPipeline.CreateAuthorizeUrl(
            clientId: clientId,
            responseType: "code",
            scope: "udap openid user/*.read",
            redirectUri: "https://code_client/callback",
            state: clientState,
            extra: new
            {
                idp = "https://idpserver2?community=udap://idp-community-2"
            });
        
        _mockAuthorServerPipeline.BrowserClient.AllowAutoRedirect = false;
        // The BrowserHandler.cs will normally set the cookie to indicate user signed in.
        // We want to skip that and get a redirect to the login page
        _mockAuthorServerPipeline.BrowserClient.AllowCookies = false;
        var response = await _mockAuthorServerPipeline.BrowserClient.GetAsync(clientAuthorizeUrl);
        response.StatusCode.Should().Be(HttpStatusCode.Redirect, await response.Content.ReadAsStringAsync());
        response.Headers.Location.Should().NotBeNull();
        response.Headers.Location!.AbsoluteUri.Should().Contain("https://server/Account/Login");
        // _testOutputHelper.WriteLine(response.Headers.Location!.AbsoluteUri);
        var queryParams = QueryHelpers.ParseQuery(response.Headers.Location.Query);
        queryParams.Should().Contain(p => p.Key == "ReturnUrl");
        queryParams.Should().NotContain(p => p.Key == "code");
        queryParams.Should().NotContain(p => p.Key == "state");


        // Pull the inner query params from the ReturnUrl
        var returnUrl = queryParams.Single(p => p.Key == "ReturnUrl").Value.ToString();
        returnUrl.Should().StartWith("/connect/authorize/callback?");
        queryParams = QueryHelpers.ParseQuery(returnUrl);
        queryParams.Single(q => q.Key == "scope").Value.ToString().Should().Contain("udap openid user/*.read");
        queryParams.Single(q => q.Key == "state").Value.Should().BeEquivalentTo(clientState);
        queryParams.Single(q => q.Key == "idp").Value.Should().BeEquivalentTo("https://idpserver2?community=udap://idp-community-2");

        // var schemes = await _mockAuthorServerPipeline.Resolve<IIdentityProviderStore>().GetAllSchemeNamesAsync();


        var sb = new StringBuilder();
        sb.Append("https://server/externallogin/challenge?"); // built in UdapAccount/Login/Index.cshtml.cs
        sb.Append("scheme=").Append(TieredOAuthAuthenticationDefaults.AuthenticationScheme);
        sb.Append("&returnUrl=").Append(Uri.EscapeDataString(returnUrl));
        clientAuthorizeUrl = sb.ToString();

        //////////////////////////////////
        //
        // IdPDiscovery
        // IdPRegistration
        // IdPAuthAccess
        //
        //////////////////////////////////


        // Auto Dynamic registration between Auth Server and Identity Provider happens here.
        // /Challenge?
        //      ctx.ChallengeAsync -> launch registered scheme.  In this case the TieredOauthAuthenticationHandler
        //         see: OnExternalLoginChallenge and Challenge(props, scheme) in ExternalLogin/Challenge.cshtml.cs or UdapTieredLogin/Challenge.cshtml.cs
        //      Backchannel
        //          Discovery
        //          Auto registration
        //          externalloging/challenge or in the Udap implementation it is the UdapAccount/Login/Index.cshtml.cs.  XSRF cookie is set here.

        // *** We are here after the request to the IdPs /authorize  call.  If the client is registered already then Discovery and Reg is skipped ***
        //
        //          Authentication request (/authorize?)
        //            User logs in at IdP
        //          Authentication response
        //          Token request
        //          Data Holder incorporates user input into authorization decision
        //



        // response after discovery and registration
        _mockAuthorServerPipeline.BrowserClient.AllowCookies = true; // Need to set the idsrv cookie so calls to /authorize will succeed
        
        _mockAuthorServerPipeline.BrowserClient.GetXsrfCookie("https://server/federation/udap-tiered/signin", new TieredOAuthAuthenticationOptions().CorrelationCookie.Name!).Should().BeNull();
        var backChannelChallengeResponse = await _mockAuthorServerPipeline.BrowserClient.GetAsync(clientAuthorizeUrl);
        _mockAuthorServerPipeline.BrowserClient.GetXsrfCookie("https://server/federation/udap-tiered/signin", new TieredOAuthAuthenticationOptions().CorrelationCookie.Name!).Should().NotBeNull();

        backChannelChallengeResponse.StatusCode.Should().Be(HttpStatusCode.Redirect, await backChannelChallengeResponse.Content.ReadAsStringAsync());
        backChannelChallengeResponse.Headers.Location.Should().NotBeNull();
        backChannelChallengeResponse.Headers.Location!.AbsoluteUri.Should().StartWith("https://idpserver2/connect/authorize");

        // _testOutputHelper.WriteLine(backChannelChallengeResponse.Headers.Location!.AbsoluteUri);
        QueryHelpers.ParseQuery(backChannelChallengeResponse.Headers.Location.Query).Single(p => p.Key == "client_id").Value.Should().NotBeEmpty();
        var backChannelState = QueryHelpers.ParseQuery(backChannelChallengeResponse.Headers.Location.Query).Single(p => p.Key == "state").Value.ToString();
        backChannelState.Should().NotBeNullOrEmpty();


        var idpClient = _mockIdPPipeline2.Clients.Single(c => c.ClientName == "AuthServer Client");
        idpClient.AlwaysIncludeUserClaimsInIdToken.Should().BeTrue();

        _mockIdPPipeline2.BrowserClient.Should().NotBeNull();
        var backChannelAuthResult = await _mockIdPPipeline2.BrowserClient!.GetAsync(backChannelChallengeResponse.Headers.Location);


        backChannelAuthResult.StatusCode.Should().Be(HttpStatusCode.Redirect, await backChannelAuthResult.Content.ReadAsStringAsync());
        // _testOutputHelper.WriteLine(backChannelAuthResult.Headers.Location!.AbsoluteUri);
        backChannelAuthResult.Headers.Location!.AbsoluteUri.Should().StartWith("https://idpserver2/Account/Login");

        // Run IdP /Account/Login
        var loginCallbackResult = await _mockIdPPipeline2.BrowserClient.GetAsync(backChannelAuthResult.Headers.Location!.AbsoluteUri);
        loginCallbackResult.StatusCode.Should().Be(HttpStatusCode.Redirect, await backChannelAuthResult.Content.ReadAsStringAsync());
        // _testOutputHelper.WriteLine(loginCallbackResult.Headers.Location!.OriginalString);
        loginCallbackResult.Headers.Location!.OriginalString.Should().StartWith("/connect/authorize/callback?");

        // Run IdP /connect/authorize/callback
        var authorizeCallbackResult = await _mockIdPPipeline2.BrowserClient.GetAsync(
            $"https://idpserver2{loginCallbackResult.Headers.Location!.OriginalString}");
        // _testOutputHelper.WriteLine(authorizeCallbackResult.Headers.Location!.OriginalString);
        authorizeCallbackResult.StatusCode.Should().Be(HttpStatusCode.Redirect, await authorizeCallbackResult.Content.ReadAsStringAsync());
        authorizeCallbackResult.Headers.Location.Should().NotBeNull();
        authorizeCallbackResult.Headers.Location!.AbsoluteUri.Should().StartWith("https://server/federation/udap-tiered/signin?");

        var backChannelCode = QueryHelpers.ParseQuery(authorizeCallbackResult.Headers.Location.Query).Single(p => p.Key == "code").Value.ToString();
        backChannelCode.Should().NotBeEmpty();

        //
        // Validate backchannel state is the same
        //
        backChannelState.Should().BeEquivalentTo(_mockAuthorServerPipeline.GetClientState(authorizeCallbackResult));

        //
        // Ensure client state and back channel state never become the same.
        //
        clientState.Should().NotBeEquivalentTo(backChannelState);

        _mockAuthorServerPipeline.GetSessionCookie().Should().BeNull();
        _mockAuthorServerPipeline.BrowserClient.GetCookie("https://server", "idsrv").Should().BeNull();

        // Run Auth Server /federation/idpserver2/signin  This is the Registered scheme callback endpoint
        // Allow one redirect to run /connect/token.
        //  Sets Cookies: idsrv.external idsrv.session, and idsrv 
        //  Backchannel calls:
        //      POST https://idpserver2/connect/token
        //      GET https://idpserver2/.well-known/openid-configuration
        //      GET https://idpserver2/.well-known/openid-configuration/jwks
        //
        //  Redirects to https://server/externallogin/callback
        //

        _mockAuthorServerPipeline.BrowserClient.AllowAutoRedirect = true;
        _mockAuthorServerPipeline.BrowserClient.StopRedirectingAfter = 1;
        _mockAuthorServerPipeline.BrowserClient.AllowCookies = true;


        // "https://server/federation/idpserver2/signin?..."
        var schemeCallbackResult = await _mockAuthorServerPipeline.BrowserClient.GetAsync(authorizeCallbackResult.Headers.Location!.AbsoluteUri);


        schemeCallbackResult.StatusCode.Should().Be(HttpStatusCode.Redirect, await schemeCallbackResult.Content.ReadAsStringAsync());
        schemeCallbackResult.Headers.Location.Should().NotBeNull();
        schemeCallbackResult.Headers.Location!.OriginalString.Should().StartWith("/connect/authorize/callback?");
        // _testOutputHelper.WriteLine(schemeCallbackResult.Headers.Location!.OriginalString);
        // Validate Cookies
        _mockAuthorServerPipeline.GetSessionCookie().Should().NotBeNull();
        // _testOutputHelper.WriteLine(_mockAuthorServerPipeline.GetSessionCookie()!.Value);
        // _mockAuthorServerPipeline.BrowserClient.GetCookie("https://server", "idsrv").Should().NotBeNull();
        //TODO assert match State and nonce between Auth Server and IdP

        //
        // Check the IdToken in the back channel.  Ensure the HL7_Identifier is in the claims
        //
        // _testOutputHelper.WriteLine(_mockIdPPipeline2.IdToken.ToString()); 

        _mockIdPPipeline2.IdToken.Should().NotBeNull();
        _mockIdPPipeline2.IdToken!.Claims.Should().Contain(c => c.Type == "hl7_identifier");
        _mockIdPPipeline2.IdToken.Claims.Single(c => c.Type == "hl7_identifier").Value.Should().Be("123");

        // Run the authServer  https://server/connect/authorize/callback 
        _mockAuthorServerPipeline.BrowserClient.AllowAutoRedirect = false;

        var clientCallbackResult = await _mockAuthorServerPipeline.BrowserClient.GetAsync(
                       $"https://server{schemeCallbackResult.Headers.Location!.OriginalString}");

        clientCallbackResult.StatusCode.Should().Be(HttpStatusCode.Redirect, await clientCallbackResult.Content.ReadAsStringAsync());
        clientCallbackResult.Headers.Location.Should().NotBeNull();
        clientCallbackResult.Headers.Location!.AbsoluteUri.Should().StartWith("https://code_client/callback?");
        // _testOutputHelper.WriteLine(clientCallbackResult.Headers.Location!.AbsoluteUri);


        // Assert match state and nonce between User and Auth Server
        clientState.Should().BeEquivalentTo(_mockAuthorServerPipeline.GetClientState(clientCallbackResult));

        queryParams = QueryHelpers.ParseQuery(clientCallbackResult.Headers.Location.Query);
        queryParams.Should().Contain(p => p.Key == "code");
        var code = queryParams.Single(p => p.Key == "code").Value.ToString();
        // _testOutputHelper.WriteLine($"Code: {code}");
        ////////////////////////////
        //
        // ClientAuthAccess
        //
        ///////////////////////////

        // Get a Access Token (Cash in the code)

        var privateCerts = _mockAuthorServerPipeline.Resolve<IPrivateCertificateStore>();

        var tokenRequest = AccessTokenRequestForAuthorizationCodeBuilder.Create(
            clientId,
            "https://server/connect/token",
            privateCerts.IssuedCertificates.Select(ic => ic.Certificate).First(),
            "https://code_client/callback",
            code)
            .Build();


        dynamicIdp.Name = null; // Influence UdapClient resolution in AddTieredOAuthForTests.
        var udapClient = _mockAuthorServerPipeline.Resolve<IUdapClient>();

        var accessToken = await udapClient.ExchangeCodeForTokenResponse(tokenRequest);
        accessToken.Should().NotBeNull();
        accessToken.IdentityToken.Should().NotBeNull();
        var jwt = new JwtSecurityToken(accessToken.IdentityToken);
        new JwtSecurityToken(accessToken.AccessToken).Should().NotBeNull();


        using var jsonDocument = JsonDocument.Parse(jwt.Payload.SerializeToJson());
        var formattedStatement = JsonSerializer.Serialize(
            jsonDocument,
            new JsonSerializerOptions { WriteIndented = true }
        );

        var formattedHeader = Base64UrlEncoder.Decode(jwt.EncodedHeader);

        _testOutputHelper.WriteLine(formattedHeader);
        _testOutputHelper.WriteLine(formattedStatement);



        // udap.org Tiered 4.3
        // aud: client_id of Resource Holder (matches client_id in Resource Holder request in Step 3.4)
        jwt.Claims.Should().Contain(c => c.Type == "aud");
        jwt.Claims.Single(c => c.Type == "aud").Value.Should().Be(clientId);

        // iss: IdP’s unique identifying URI (matches idp parameter from Step 2)
        jwt.Claims.Should().Contain(c => c.Type == "iss");
        jwt.Claims.Single(c => c.Type == "iss").Value.Should().Be(UdapAuthServerPipeline.BaseUrl);

        jwt.Claims.Should().Contain(c => c.Type == "hl7_identifier");
        jwt.Claims.Single(c => c.Type == "hl7_identifier").Value.Should().Be("123");




        // sub: unique identifier for user in namespace of issuer, i.e. iss + sub is globally unique

        // TODO: Currently the sub is the code given at access time.  Maybe that is OK?  I could put the clientId in from 
        // backchannel.  But I am not sure I want to show that.  After all it is still globally unique.
        // jwt.Claims.Should().Contain(c => c.Type == "sub");
        // jwt.Claims.Single(c => c.Type == "sub").Value.Should().Be(backChannelClientId);

        // jwt.Claims.Should().Contain(c => c.Type == "sub");
        // jwt.Claims.Single(c => c.Type == "sub").Value.Should().Be(backChannelCode);

        // Todo: Nonce 
        // Todo: Validate claims.  Like missing name and other identity claims.  Maybe add a hl7_identifier
        // Why is idp:TieredOAuth in the returned claims?
        
    }


    /// <summary>
    /// During Tiered OAuth between the client and data holder the udap scope is required 
    /// Client call to /authorize? should request with udap scope.
    /// Without it the idp is undefined according to https://hl7.org/fhir/us/udap-security/user.html#client-authorization-request-to-data-holder
    /// </summary>
    /// <returns></returns>
    [Fact]
    public async Task ClientAuthorize_Missing_udap_scope_between_client_and_dataholder_Test()
    {
        BuildUdapAuthorizationServer();
        BuildUdapIdentityProvider1();

        // Register client with auth server
        var resultDocument = await RegisterClientWithAuthServer();
        _mockAuthorServerPipeline.RemoveSessionCookie();
        _mockAuthorServerPipeline.RemoveLoginCookie();
        resultDocument.Should().NotBeNull();
        resultDocument!.ClientId.Should().NotBeNull();

        var clientId = resultDocument.ClientId!;

        var dynamicIdp = _mockAuthorServerPipeline.ApplicationServices.GetRequiredService<DynamicIdp>();
        dynamicIdp.Name = _mockIdPPipeline.BaseUrl;

        //////////////////////
        // ClientAuthorize
        //////////////////////

        // Data Holder's Auth Server validates Identity Provider's Server software statement

        var clientState = Guid.NewGuid().ToString();

        var clientAuthorizeUrl = _mockAuthorServerPipeline.CreateAuthorizeUrl(
            clientId: clientId,
            responseType: "code",
            scope: "openid user/*.read",
            redirectUri: "https://code_client/callback",
            state: clientState,
            extra: new
            {
                idp = "https://idpserver"
            });

        _mockAuthorServerPipeline.BrowserClient.AllowAutoRedirect = false;
        // The BrowserHandler.cs will normally set the cookie to indicate user signed in.
        // We want to skip that and get a redirect to the login page
        _mockAuthorServerPipeline.BrowserClient.AllowCookies = false;
        var response = await _mockAuthorServerPipeline.BrowserClient.GetAsync(clientAuthorizeUrl);
        response.StatusCode.Should().Be(HttpStatusCode.Redirect, await response.Content.ReadAsStringAsync());
        response.Headers.Location.Should().NotBeNull();
        response.Headers.Location!.AbsoluteUri.Should().Contain("https://server/Account/Login");
        // _testOutputHelper.WriteLine(response.Headers.Location!.AbsoluteUri);
        var queryParams = QueryHelpers.ParseQuery(response.Headers.Location.Query);
        queryParams.Should().Contain(p => p.Key == "ReturnUrl");
        queryParams.Should().NotContain(p => p.Key == "code");
        queryParams.Should().NotContain(p => p.Key == "state");


        // Pull the inner query params from the ReturnUrl
        var returnUrl = queryParams.Single(p => p.Key == "ReturnUrl").Value.ToString();
        returnUrl.Should().StartWith("/connect/authorize/callback?");
        queryParams = QueryHelpers.ParseQuery(returnUrl);
        queryParams.Single(q => q.Key == "scope").Value.ToString().Should().Contain("openid user/*.read");
        queryParams.Single(q => q.Key == "state").Value.Should().BeEquivalentTo(clientState);
        queryParams.Single(q => q.Key == "idp").Value.Should().BeEquivalentTo("https://idpserver");

        var schemes = await _mockAuthorServerPipeline.Resolve<IAuthenticationSchemeProvider>().GetAllSchemesAsync();

        var sb = new StringBuilder();
        sb.Append("https://server/externallogin/challenge?"); // built in UdapAccount/Login/Index.cshtml.cs
        sb.Append("scheme=").Append(schemes.First().Name);
        sb.Append("&returnUrl=").Append(Uri.EscapeDataString(returnUrl));
        clientAuthorizeUrl = sb.ToString();
        

        // response after discovery and registration
        _mockAuthorServerPipeline.BrowserClient.AllowCookies = true; // Need to set the idsrv cookie so calls to /authorize will succeed

        _mockAuthorServerPipeline.BrowserClient.GetXsrfCookie("https://server/federation/udap-tiered/signin",
            new TieredOAuthAuthenticationOptions().CorrelationCookie.Name!).Should().BeNull();

       var exception = await Assert.ThrowsAsync<Exception>(() => _mockAuthorServerPipeline.BrowserClient.GetAsync(clientAuthorizeUrl));
       exception.Message.Should().Be("Missing required udap scope from client for Tiered OAuth");
    }


    /// <summary>
    /// During Tiered OAuth between data holder and IdP the openid and udap scope are required 
    /// Client call to /authorize? should request with udap scope.
    /// https://hl7.org/fhir/us/udap-security/user.html#data-holder-authentication-request-to-idp
    /// </summary>
    /// <returns></returns>
    [Theory]
    [InlineData(new object[] { new string[] { "openid", "email", "profile"}})]
    [InlineData(new object[] { new string[] { "udap", "email", "profile" } })]
    public async Task ClientAuthorize_Missing_udap_or_idp_scope_between_dataholder_and_IdP_Test(string[] scopes)
    {
        // var scopes = new List<string>() { "email", "profile" };
        BuildUdapAuthorizationServer(scopes.ToList());
        BuildUdapIdentityProvider1();

        // Register client with auth server
        var resultDocument = await RegisterClientWithAuthServer();
        _mockAuthorServerPipeline.RemoveSessionCookie();
        _mockAuthorServerPipeline.RemoveLoginCookie();
        resultDocument.Should().NotBeNull();
        resultDocument!.ClientId.Should().NotBeNull();

        var clientId = resultDocument.ClientId!;

        var dynamicIdp = _mockAuthorServerPipeline.ApplicationServices.GetRequiredService<DynamicIdp>();
        dynamicIdp.Name = _mockIdPPipeline.BaseUrl;

        //////////////////////
        // ClientAuthorize
        //////////////////////

        // Data Holder's Auth Server validates Identity Provider's Server software statement

        var clientState = Guid.NewGuid().ToString();

        var clientAuthorizeUrl = _mockAuthorServerPipeline.CreateAuthorizeUrl(
            clientId: clientId,
            responseType: "code",
            scope: "udap openid user/*.read",
            redirectUri: "https://code_client/callback",
            state: clientState,
            extra: new
            {
                idp = "https://idpserver"
            });

        _mockAuthorServerPipeline.BrowserClient.AllowAutoRedirect = false;
        // The BrowserHandler.cs will normally set the cookie to indicate user signed in.
        // We want to skip that and get a redirect to the login page
        _mockAuthorServerPipeline.BrowserClient.AllowCookies = false;
        var response = await _mockAuthorServerPipeline.BrowserClient.GetAsync(clientAuthorizeUrl);
        response.StatusCode.Should().Be(HttpStatusCode.Redirect, await response.Content.ReadAsStringAsync());
        response.Headers.Location.Should().NotBeNull();
        response.Headers.Location!.AbsoluteUri.Should().Contain("https://server/Account/Login");
        // _testOutputHelper.WriteLine(response.Headers.Location!.AbsoluteUri);
        var queryParams = QueryHelpers.ParseQuery(response.Headers.Location.Query);
        queryParams.Should().Contain(p => p.Key == "ReturnUrl");
        queryParams.Should().NotContain(p => p.Key == "code");
        queryParams.Should().NotContain(p => p.Key == "state");
        

        // Pull the inner query params from the ReturnUrl
        var returnUrl = queryParams.Single(p => p.Key == "ReturnUrl").Value.ToString();
        returnUrl.Should().StartWith("/connect/authorize/callback?");
        queryParams = QueryHelpers.ParseQuery(returnUrl);
        queryParams.Single(q => q.Key == "scope").Value.ToString().Should().Contain("udap openid user/*.read");
        queryParams.Single(q => q.Key == "state").Value.Should().BeEquivalentTo(clientState);
        queryParams.Single(q => q.Key == "idp").Value.Should().BeEquivalentTo("https://idpserver");

        var schemes = await _mockAuthorServerPipeline.Resolve<IAuthenticationSchemeProvider>().GetAllSchemesAsync();

        var sb = new StringBuilder();
        sb.Append("https://server/externallogin/challenge?"); // built in UdapAccount/Login/Index.cshtml.cs
        sb.Append("scheme=").Append(schemes.First().Name);
        sb.Append("&returnUrl=").Append(Uri.EscapeDataString(returnUrl));
        clientAuthorizeUrl = sb.ToString();



        //////////////////////////////////
        //
        // IdPDiscovery
        // IdPRegistration
        // IdPAuthAccess
        //
        //////////////////////////////////


        // Auto Dynamic registration between Auth Server and Identity Provider happens here.
        // /Challenge?
        //      ctx.ChallengeAsync -> launch registered scheme.  In this case the TieredOauthAuthenticationHandler
        //         see: OnExternalLoginChallenge and Challenge(props, scheme) in ExternalLogin/Challenge.cshtml.cs or UdapTieredLogin/Challenge.cshtml.cs
        //      Backchannel
        //          Discovery
        //          Auto registration
        //          externalloging/challenge or in the Udap implementation it is the UdapAccount/Login/Index.cshtml.cs.  XSRF cookie is set here.

        // *** We are here after the request to the IdPs /authorize  call.  If the client is registered already then Discovery and Reg is skipped ***
        //
        //          Authentication request (/authorize?)
        //            User logs in at IdP
        //          Authentication response
        //          Token request
        //          Data Holder incorporates user input into authorization decision
        //



        // response after discovery and registration
        _mockAuthorServerPipeline.BrowserClient.AllowCookies =
            true; // Need to set the idsrv cookie so calls to /authorize will succeed

        _mockAuthorServerPipeline.BrowserClient.GetXsrfCookie("https://server/federation/udap-tiered/signin",
            new TieredOAuthAuthenticationOptions().CorrelationCookie.Name!).Should().BeNull();
        var backChannelChallengeResponse = await _mockAuthorServerPipeline.BrowserClient.GetAsync(clientAuthorizeUrl);
        _mockAuthorServerPipeline.BrowserClient.GetXsrfCookie("https://server/federation/udap-tiered/signin",
            new TieredOAuthAuthenticationOptions().CorrelationCookie.Name!).Should().NotBeNull();

        backChannelChallengeResponse.StatusCode.Should().Be(HttpStatusCode.Redirect,
            await backChannelChallengeResponse.Content.ReadAsStringAsync());
        backChannelChallengeResponse.Headers.Location.Should().NotBeNull();
        backChannelChallengeResponse.Headers.Location!.AbsoluteUri.Should()
            .StartWith("https://idpserver/connect/authorize");

        // _testOutputHelper.WriteLine(backChannelChallengeResponse.Headers.Location!.AbsoluteUri);
        QueryHelpers.ParseQuery(backChannelChallengeResponse.Headers.Location.Query).Single(p => p.Key == "client_id")
            .Value.Should().NotBeEmpty();
        var backChannelState = QueryHelpers.ParseQuery(backChannelChallengeResponse.Headers.Location.Query)
            .Single(p => p.Key == "state").Value.ToString();
        backChannelState.Should().NotBeNullOrEmpty();

        var idpClient = _mockIdPPipeline.Clients.Single(c => c.ClientName == "AuthServer Client");
        idpClient.AlwaysIncludeUserClaimsInIdToken.Should().BeTrue();


        Debug.Assert(_mockIdPPipeline.BrowserClient != null, "_mockIdPPipeline.BrowserClient != null");
        var backChannelAuthResult =
            await _mockIdPPipeline.BrowserClient.GetAsync(backChannelChallengeResponse.Headers.Location);
        _testOutputHelper.WriteLine(HttpUtility.UrlDecode(backChannelAuthResult.Headers.Location.Query));

        backChannelAuthResult.StatusCode.Should().Be(HttpStatusCode.Redirect,
            await backChannelAuthResult.Content.ReadAsStringAsync());
        backChannelAuthResult.Headers.Location.Should().NotBeNull();
        backChannelAuthResult.Headers.Location!.AbsoluteUri.Should()
            .StartWith("https://server/federation/udap-tiered/signin"); //signin callback scheme

        var responseParams = QueryHelpers.ParseQuery(backChannelAuthResult.Headers.Location.Query);
        responseParams["error"].Should().BeEquivalentTo("invalid_request");
        responseParams["error_description"].Should().BeEquivalentTo("Missing udap and/or openid scope between data holder and IdP");
        responseParams["scope"].Should().BeEquivalentTo(scopes.ToSpaceSeparatedString());
    }

    private async Task<UdapDynamicClientRegistrationDocument?> RegisterClientWithAuthServer()
    {
        var clientCert = new X509Certificate2("CertStore/issued/fhirLabsApiClientLocalhostCert.pfx", "udap-test");

        var udapClient = _mockAuthorServerPipeline.Resolve<IUdapClient>();

        //
        // Typically the client would validate a server before proceeding to registration.
        //
        udapClient.UdapServerMetaData = new UdapMetadata(Substitute.For<UdapMetadataOptions>(), Substitute.For<HashSet<string>>())
            { RegistrationEndpoint = UdapAuthServerPipeline.RegistrationEndpoint };


        var documentResponse = await udapClient.RegisterAuthCodeClient(
            clientCert,
            "udap openid user/*.read",
            "https://server/UDAP_Ecosystem_Gears.png", 
            new List<string> { "https://code_client/callback" });

        documentResponse.GetError().Should().BeNull();
        
        return documentResponse;
    }
}