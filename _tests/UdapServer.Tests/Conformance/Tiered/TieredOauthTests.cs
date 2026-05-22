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
using System.Text.Json;
using System.Web;
using Duende.IdentityServer;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Test;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using Udap.Client;
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
    private static readonly JsonSerializerOptions IndentedJsonOptions = new JsonSerializerOptions { WriteIndented = true };

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
#if NET9_0_OR_GREATER
        _community1Anchor = X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/caLocalhostCert.cer");
        _community1IntermediateCert = X509CertificateLoader.LoadCertificateFromFile("CertStore/intermediates/intermediateLocalhostCert.cer");

        _community2Anchor = X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/caLocalhostCert2.cer");
        _community2IntermediateCert = X509CertificateLoader.LoadCertificateFromFile("CertStore/intermediates/intermediateLocalhostCert2.cer");
#else
        _community1Anchor = new X509Certificate2("CertStore/anchors/caLocalhostCert.cer");
        _community1IntermediateCert = new X509Certificate2("CertStore/intermediates/intermediateLocalhostCert.cer");

        _community2Anchor = new X509Certificate2("CertStore/anchors/caLocalhostCert2.cer");
        _community2IntermediateCert = new X509Certificate2("CertStore/intermediates/intermediateLocalhostCert2.cer");
#endif
    }

    private void BuildUdapAuthorizationServer(List<string>? tieredOAuthScopes = null)
    {
        _mockAuthorServerPipeline.OnPostConfigureServices += services =>
        {
            services.AddSingleton(new ServerSettings
            {
                ForceStateParamOnAuthorizationCode = true, //false (default)
                RequirePkce = false,
                RequireConsent = false,
                SsraaVersion = SsraaVersion.V1_1
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

            services.Configure<UdapFileCertStoreManifest>(builderContext.Configuration.GetSection(Constants.UdapFileCertStoreManifestSectionName));

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
            Anchors =
            [
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
            ]
        });

        _mockAuthorServerPipeline.Communities.Add(new Community
        {
            Id = 1,
            Name = "udap://idp-community-2",
            Enabled = true,
            Default = true,
            Anchors =
            [
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
            ]
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
            Claims =
            [
                new Claim("name", "Bob Loblaw"),
                new Claim("email", "bob@loblaw.com"),
                new Claim("role", "Attorney")
            ]
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
                    var serverSettings = sp.GetRequiredService<IOptions<ServerSettings>>().Value; // must resolve to trigger the post config at TieredIdpServerSettings
                    serverSettings.DefaultUserScopes = "udap";
                    serverSettings.DefaultSystemScopes = "udap";
                    // ForceStateParamOnAuthorizationCode = false (default)
                    serverSettings.AlwaysIncludeUserClaimsInIdToken = true;
                    serverSettings.RequireConsent = false;
                    serverSettings.RequirePkce = false;
                    serverSettings.SsraaVersion = SsraaVersion.V1_1;
                    return serverSettings;
                });
           

            // This registers Clients as List<Client> so downstream I can pick it up in InMemoryUdapClientRegistrationStore
            // Duende's AddInMemoryClients extension registers as IEnumerable<Client> and is used in InMemoryClientStore as readonly.
            // It was not intended to work with the concept of a dynamic client registration.
            services.AddSingleton(_mockIdPPipeline.Clients);

            //
            // Allow logo resolve back to udap.auth server
            //
            services.AddSingleton<HttpClient>(_ => _mockAuthorServerPipeline.BrowserClient);
        };
        

        _mockIdPPipeline.Initialize(enableLogging: true);
        Debug.Assert(_mockIdPPipeline.BrowserClient != null, "_mockIdPPipeline.BrowserClient != null");
        _mockIdPPipeline.BrowserClient.AllowAutoRedirect = false;

        _mockIdPPipeline.Communities.Add(new Community
        {
            Name = "udap://idp-community-1",
            Enabled = true,
            Default = true,
            Anchors =
            [
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
            ]
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
            Claims =
            [
                new Claim("name", "Bob Loblaw"),
                new Claim("email", "bob@loblaw.com"),
                new Claim("role", "Attorney"),
                new Claim("hl7_identifier", "123")
            ]
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
                    var serverSettings = sp.GetRequiredService<IOptions<ServerSettings>>().Value;
                    serverSettings.DefaultUserScopes = "udap";
                    serverSettings.DefaultSystemScopes = "udap";
                    // ForceStateParamOnAuthorizationCode = false (default)
                    serverSettings.AlwaysIncludeUserClaimsInIdToken = true;
                    serverSettings.RequireConsent = false;
                    serverSettings.RequirePkce = false;
                    serverSettings.SsraaVersion = SsraaVersion.V1_1;
                    return serverSettings;
                });
            

            // This registers Clients as List<Client> so downstream I can pick it up in InMemoryUdapClientRegistrationStore
            // Duende's AddInMemoryClients extension registers as IEnumerable<Client> and is used in InMemoryClientStore as readonly.
            // It was not intended to work with the concept of a dynamic client registration.
            services.AddSingleton(_mockIdPPipeline2.Clients);

            //
            // Allow logo resolve back to udap.auth server
            //
            services.AddSingleton<HttpClient>(_ => _mockAuthorServerPipeline.BrowserClient);
        };

       

        _mockIdPPipeline2.Initialize(enableLogging: true);
        Debug.Assert(_mockIdPPipeline2.BrowserClient != null, "_mockIdPPipeline2.BrowserClient != null");
        _mockIdPPipeline2.BrowserClient.AllowAutoRedirect = false;

        _mockIdPPipeline2.Communities.Add(new Community
        {
            Name = "udap://idp-community-2",
            Enabled = true,
            Default = true,
            Anchors =
            [
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
            ]
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
            Claims =
            [
                new Claim("name", "Bob Loblaw"),
                new Claim("email", "bob@loblaw.com"),
                new Claim("role", "Attorney"),
                new Claim("hl7_identifier", "123")
            ]
        });

        // Allow pipeline to sign in during Login
        _mockIdPPipeline2.Subject = new IdentityServerUser("bob").CreatePrincipal();
    }

    /// <summary>
    /// 
    /// </summary>
    /// <returns></returns>
    [Fact]
    public async Task Tiered_OAuth()
    {
        BuildUdapAuthorizationServer();
        BuildUdapIdentityProvider1();
        

        // Register client with auth server
        var resultDocument = await RegisterClientWithAuthServer();
        _mockAuthorServerPipeline.RemoveSessionCookie();
        _mockAuthorServerPipeline.RemoveLoginCookie();
        Assert.NotNull(resultDocument);
        Assert.NotNull(resultDocument!.ClientId);

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
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.NotNull(response.Headers.Location);
        Assert.Contains("https://server/Account/Login", response.Headers.Location!.AbsoluteUri);
        // _testOutputHelper.WriteLine(response.Headers.Location!.AbsoluteUri);
        var queryParams = QueryHelpers.ParseQuery(response.Headers.Location.Query);
        Assert.Contains(queryParams, p => p.Key == "ReturnUrl");
        Assert.DoesNotContain(queryParams, p => p.Key == "code");
        Assert.DoesNotContain(queryParams, p => p.Key == "state");

        
        // Pull the inner query params from the ReturnUrl
        var returnUrl = queryParams.Single(p => p.Key == "ReturnUrl").Value.ToString();
        Assert.StartsWith("/connect/authorize/callback?", returnUrl);
        queryParams = QueryHelpers.ParseQuery(returnUrl);
        Assert.Contains("udap openid user/*.read", queryParams.Single(q => q.Key == "scope").Value.ToString());
        Assert.Equal(clientState, queryParams.Single(q => q.Key == "state").Value.ToString(), StringComparer.OrdinalIgnoreCase);
        Assert.Equal("https://idpserver", queryParams.Single(q => q.Key == "idp").Value.ToString(), StringComparer.OrdinalIgnoreCase);
        
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

        Assert.Null(_mockAuthorServerPipeline.BrowserClient.GetXsrfCookie("https://server/federation/udap-tiered/signin", new TieredOAuthAuthenticationOptions().CorrelationCookie.Name!));
        var backChannelChallengeResponse = await _mockAuthorServerPipeline.BrowserClient.GetAsync(clientAuthorizeUrl);
        Assert.NotNull(_mockAuthorServerPipeline.BrowserClient.GetXsrfCookie("https://server/federation/udap-tiered/signin", new TieredOAuthAuthenticationOptions().CorrelationCookie.Name!));
        
        Assert.Equal(HttpStatusCode.Redirect, backChannelChallengeResponse.StatusCode);
        Assert.NotNull(backChannelChallengeResponse.Headers.Location);
        Assert.StartsWith("https://idpserver/connect/authorize", backChannelChallengeResponse.Headers.Location!.AbsoluteUri);
        
        // _testOutputHelper.WriteLine(backChannelChallengeResponse.Headers.Location!.AbsoluteUri);
        Assert.True(QueryHelpers.ParseQuery(backChannelChallengeResponse.Headers.Location.Query).Single(p => p.Key == "client_id").Value.Count > 0);
        var backChannelState = QueryHelpers.ParseQuery(backChannelChallengeResponse.Headers.Location.Query).Single(p => p.Key == "state").Value.ToString();
        Assert.False(string.IsNullOrEmpty(backChannelState));
        
        var idpClient = _mockIdPPipeline.Clients.Single(c => c.ClientName == "AuthServer Client");
        Assert.True(idpClient.AlwaysIncludeUserClaimsInIdToken);


        Debug.Assert(_mockIdPPipeline.BrowserClient != null, "_mockIdPPipeline.BrowserClient != null");
        var backChannelAuthResult = await _mockIdPPipeline.BrowserClient.GetAsync(backChannelChallengeResponse.Headers.Location);

        
        Assert.Equal(HttpStatusCode.Redirect, backChannelAuthResult.StatusCode);
        // _testOutputHelper.WriteLine(backChannelAuthResult.Headers.Location!.AbsoluteUri);
        Assert.StartsWith("https://idpserver/Account/Login", backChannelAuthResult.Headers.Location!.AbsoluteUri);

        // Run IdP /Account/Login
        var loginCallbackResult = await _mockIdPPipeline.BrowserClient.GetAsync(backChannelAuthResult.Headers.Location!.AbsoluteUri);
        Assert.Equal(HttpStatusCode.Redirect, loginCallbackResult.StatusCode);
        // _testOutputHelper.WriteLine(loginCallbackResult.Headers.Location!.OriginalString);
        Assert.StartsWith("/connect/authorize/callback?", loginCallbackResult.Headers.Location!.OriginalString);

        // Run IdP /connect/authorize/callback
        var authorizeCallbackResult = await _mockIdPPipeline.BrowserClient.GetAsync(
            $"https://idpserver{loginCallbackResult.Headers.Location!.OriginalString}");
        // _testOutputHelper.WriteLine(authorizeCallbackResult.Headers.Location!.OriginalString);
        Assert.Equal(HttpStatusCode.Redirect, authorizeCallbackResult.StatusCode);
        Assert.NotNull(authorizeCallbackResult.Headers.Location);
        Assert.StartsWith("https://server/federation/udap-tiered/signin?", authorizeCallbackResult.Headers.Location!.AbsoluteUri);

        Assert.True(QueryHelpers.ParseQuery(authorizeCallbackResult.Headers.Location.Query).Single(p => p.Key == "code").Value.Count > 0);

        //
        // Validate backchannel state is the same
        //
        Assert.Equal(_mockAuthorServerPipeline.GetClientState(authorizeCallbackResult), backChannelState, StringComparer.OrdinalIgnoreCase);

        //
        // Ensure client state and back channel state never become the same.
        //
        Assert.NotEqual(backChannelState, clientState);

        Assert.Null(_mockAuthorServerPipeline.GetSessionCookie());
        Assert.Null(_mockAuthorServerPipeline.BrowserClient.GetCookie("https://server", "idsrv"));

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


        Assert.Equal(HttpStatusCode.Redirect, schemeCallbackResult.StatusCode);
        Assert.NotNull(schemeCallbackResult.Headers.Location);
        Assert.StartsWith("/connect/authorize/callback?", schemeCallbackResult.Headers.Location!.OriginalString);
        // _testOutputHelper.WriteLine(schemeCallbackResult.Headers.Location!.OriginalString);
        // Validate Cookies
        Assert.NotNull(_mockAuthorServerPipeline.GetSessionCookie());
        _testOutputHelper.WriteLine(_mockAuthorServerPipeline.GetSessionCookie()!.Value);
        Assert.NotNull(_mockAuthorServerPipeline.BrowserClient.GetCookie("https://server", "idsrv"));
        //TODO assert match State and nonce between Auth Server and IdP

        //
        // Check the IdToken in the back channel.  Ensure the HL7_Identifier is in the claims
        //
        // _testOutputHelper.WriteLine(_mockIdPPipeline.IdToken.ToString()); 
        Assert.NotNull(_mockIdPPipeline.IdToken);
        Assert.Contains(_mockIdPPipeline.IdToken!.Claims, c => c.Type == "hl7_identifier");
        Assert.Equal("123", _mockIdPPipeline.IdToken.Claims.Single(c => c.Type == "hl7_identifier").Value);

        // Run the authServer  https://server/connect/authorize/callback 
        _mockAuthorServerPipeline.BrowserClient.AllowAutoRedirect = false;
        
        var clientCallbackResult = await _mockAuthorServerPipeline.BrowserClient.GetAsync(
                       $"https://server{schemeCallbackResult.Headers.Location!.OriginalString}");

        Assert.Equal(HttpStatusCode.Redirect, clientCallbackResult.StatusCode);
        Assert.NotNull(clientCallbackResult.Headers.Location);
        Assert.StartsWith("https://code_client/callback?", clientCallbackResult.Headers.Location!.AbsoluteUri);
        // _testOutputHelper.WriteLine(clientCallbackResult.Headers.Location!.AbsoluteUri);
        
        
        // Assert match state and nonce between User and Auth Server
        Assert.Equal(_mockAuthorServerPipeline.GetClientState(clientCallbackResult), clientState, StringComparer.OrdinalIgnoreCase);

        queryParams = QueryHelpers.ParseQuery(clientCallbackResult.Headers.Location.Query);
        Assert.Contains(queryParams, p => p.Key == "code");
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
        Assert.NotNull(accessToken);
        Assert.NotNull(accessToken.IdentityToken);
        var jwt = new JwtSecurityToken(accessToken.IdentityToken);
        Assert.NotNull(new JwtSecurityToken(accessToken.AccessToken));

        using var jsonDocument = JsonDocument.Parse(jwt.Payload.SerializeToJson());
        var formattedStatement = JsonSerializer.Serialize(
            jsonDocument,
            IndentedJsonOptions
        );

        var formattedHeader = Base64UrlEncoder.Decode(jwt.EncodedHeader);
        
        _testOutputHelper.WriteLine(formattedHeader);
        _testOutputHelper.WriteLine(formattedStatement);



        // udap.org Tiered 4.3
        // aud: client_id of Resource Holder (matches client_id in Resource Holder request in Step 3.4)
        Assert.Contains(jwt.Claims, c => c.Type == "aud");
        Assert.Equal(clientId, jwt.Claims.Single(c => c.Type == "aud").Value);

        // iss: IdP’s unique identifying URI (matches idp parameter from Step 2)
        Assert.Contains(jwt.Claims, c => c.Type == "iss");
        Assert.Equal(UdapAuthServerPipeline.BaseUrl, jwt.Claims.Single(c => c.Type == "iss").Value);

        Assert.Contains(jwt.Claims, c => c.Type == "hl7_identifier");
        Assert.Equal("123", jwt.Claims.Single(c => c.Type == "hl7_identifier").Value);




        // sub: unique identifier for user in namespace of issuer, i.e. iss + sub is globally unique

        // TODO: Currently the sub is the code given at access time.  Maybe that is OK?  I could put the clientId in from 
        // backchannel.  But I am not sure I want to show that.  After all it is still globally unique.
        // Assert.Contains(jwt.Claims, c => c.Type == "sub");
        // Assert.Equal(backChannelClientId, jwt.Claims.Single(c => c.Type == "sub").Value);

        // Assert.Contains(jwt.Claims, c => c.Type == "sub");
        // Assert.Equal(backChannelCode, jwt.Claims.Single(c => c.Type == "sub").Value);

        // Todo: Nonce 
        // Todo: Validate claims.  Like missing name and other identity claims.  Maybe add a hl7_identifier
        // Why is idp:TieredOAuth in the returned claims?


        /*
         * new Claim("name", "Bob Loblaw"),
                new Claim("email", "bob@loblaw.com"),
                new Claim("role", "Attorney")
         */
    }

    [Fact]
    public async Task Tiered_OAuth_With_Community()
    {
        BuildUdapAuthorizationServer();
        BuildUdapIdentityProvider2();

        // Register client with auth server
        var resultDocument = await RegisterClientWithAuthServer();
        _mockAuthorServerPipeline.RemoveSessionCookie();
        _mockAuthorServerPipeline.RemoveLoginCookie();
        Assert.NotNull(resultDocument);
        Assert.NotNull(resultDocument!.ClientId);

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
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.NotNull(response.Headers.Location);
        Assert.Contains("https://server/Account/Login", response.Headers.Location!.AbsoluteUri);
        // _testOutputHelper.WriteLine(response.Headers.Location!.AbsoluteUri);
        var queryParams = QueryHelpers.ParseQuery(response.Headers.Location.Query);
        Assert.Contains(queryParams, p => p.Key == "ReturnUrl");
        Assert.DoesNotContain(queryParams, p => p.Key == "code");
        Assert.DoesNotContain(queryParams, p => p.Key == "state");


        // Pull the inner query params from the ReturnUrl
        var returnUrl = queryParams.Single(p => p.Key == "ReturnUrl").Value.ToString();
        Assert.StartsWith("/connect/authorize/callback?", returnUrl);
        queryParams = QueryHelpers.ParseQuery(returnUrl);
        Assert.Contains("udap openid user/*.read", queryParams.Single(q => q.Key == "scope").Value.ToString());
        Assert.Equal(clientState, queryParams.Single(q => q.Key == "state").Value.ToString(), StringComparer.OrdinalIgnoreCase);
        Assert.Equal("https://idpserver2?community=udap://idp-community-2", queryParams.Single(q => q.Key == "idp").Value.ToString(), StringComparer.OrdinalIgnoreCase);

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
        
        Assert.Null(_mockAuthorServerPipeline.BrowserClient.GetXsrfCookie("https://server/federation/udap-tiered/signin", new TieredOAuthAuthenticationOptions().CorrelationCookie.Name!));
        var backChannelChallengeResponse = await _mockAuthorServerPipeline.BrowserClient.GetAsync(clientAuthorizeUrl);
        Assert.NotNull(_mockAuthorServerPipeline.BrowserClient.GetXsrfCookie("https://server/federation/udap-tiered/signin", new TieredOAuthAuthenticationOptions().CorrelationCookie.Name!));

        Assert.Equal(HttpStatusCode.Redirect, backChannelChallengeResponse.StatusCode);
        Assert.NotNull(backChannelChallengeResponse.Headers.Location);
        Assert.StartsWith("https://idpserver2/connect/authorize", backChannelChallengeResponse.Headers.Location!.AbsoluteUri);

        // _testOutputHelper.WriteLine(backChannelChallengeResponse.Headers.Location!.AbsoluteUri);
        Assert.True(QueryHelpers.ParseQuery(backChannelChallengeResponse.Headers.Location.Query).Single(p => p.Key == "client_id").Value.Count > 0);
        var backChannelState = QueryHelpers.ParseQuery(backChannelChallengeResponse.Headers.Location.Query).Single(p => p.Key == "state").Value.ToString();
        Assert.False(string.IsNullOrEmpty(backChannelState));


        var idpClient = _mockIdPPipeline2.Clients.Single(c => c.ClientName == "AuthServer Client");
        Assert.True(idpClient.AlwaysIncludeUserClaimsInIdToken);

        Assert.NotNull(_mockIdPPipeline2.BrowserClient);
        var backChannelAuthResult = await _mockIdPPipeline2.BrowserClient!.GetAsync(backChannelChallengeResponse.Headers.Location);


        Assert.Equal(HttpStatusCode.Redirect, backChannelAuthResult.StatusCode);
        // _testOutputHelper.WriteLine(backChannelAuthResult.Headers.Location!.AbsoluteUri);
        Assert.StartsWith("https://idpserver2/Account/Login", backChannelAuthResult.Headers.Location!.AbsoluteUri);

        // Run IdP /Account/Login
        var loginCallbackResult = await _mockIdPPipeline2.BrowserClient.GetAsync(backChannelAuthResult.Headers.Location!.AbsoluteUri);
        Assert.Equal(HttpStatusCode.Redirect, loginCallbackResult.StatusCode);
        // _testOutputHelper.WriteLine(loginCallbackResult.Headers.Location!.OriginalString);
        Assert.StartsWith("/connect/authorize/callback?", loginCallbackResult.Headers.Location!.OriginalString);

        // Run IdP /connect/authorize/callback
        var authorizeCallbackResult = await _mockIdPPipeline2.BrowserClient.GetAsync(
            $"https://idpserver2{loginCallbackResult.Headers.Location!.OriginalString}");
        // _testOutputHelper.WriteLine(authorizeCallbackResult.Headers.Location!.OriginalString);
        Assert.Equal(HttpStatusCode.Redirect, authorizeCallbackResult.StatusCode);
        Assert.NotNull(authorizeCallbackResult.Headers.Location);
        Assert.StartsWith("https://server/federation/udap-tiered/signin?", authorizeCallbackResult.Headers.Location!.AbsoluteUri);

        var backChannelCode = QueryHelpers.ParseQuery(authorizeCallbackResult.Headers.Location.Query).Single(p => p.Key == "code").Value.ToString();
        Assert.NotEmpty(backChannelCode);

        //
        // Validate backchannel state is the same
        //
        Assert.Equal(_mockAuthorServerPipeline.GetClientState(authorizeCallbackResult), backChannelState, StringComparer.OrdinalIgnoreCase);

        //
        // Ensure client state and back channel state never become the same.
        //
        Assert.NotEqual(backChannelState, clientState);

        Assert.Null(_mockAuthorServerPipeline.GetSessionCookie());
        Assert.Null(_mockAuthorServerPipeline.BrowserClient.GetCookie("https://server", "idsrv"));

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


        Assert.Equal(HttpStatusCode.Redirect, schemeCallbackResult.StatusCode);
        Assert.NotNull(schemeCallbackResult.Headers.Location);
        Assert.StartsWith("/connect/authorize/callback?", schemeCallbackResult.Headers.Location!.OriginalString);
        // _testOutputHelper.WriteLine(schemeCallbackResult.Headers.Location!.OriginalString);
        // Validate Cookies
        Assert.NotNull(_mockAuthorServerPipeline.GetSessionCookie());
        // _testOutputHelper.WriteLine(_mockAuthorServerPipeline.GetSessionCookie()!.Value);
        // Assert.NotNull(_mockAuthorServerPipeline.BrowserClient.GetCookie("https://server", "idsrv"));
        //TODO assert match State and nonce between Auth Server and IdP

        //
        // Check the IdToken in the back channel.  Ensure the HL7_Identifier is in the claims
        //
        // _testOutputHelper.WriteLine(_mockIdPPipeline2.IdToken.ToString()); 

        Assert.NotNull(_mockIdPPipeline2.IdToken);
        Assert.Contains(_mockIdPPipeline2.IdToken!.Claims, c => c.Type == "hl7_identifier");
        Assert.Equal("123", _mockIdPPipeline2.IdToken.Claims.Single(c => c.Type == "hl7_identifier").Value);

        // Run the authServer  https://server/connect/authorize/callback 
        _mockAuthorServerPipeline.BrowserClient.AllowAutoRedirect = false;

        var clientCallbackResult = await _mockAuthorServerPipeline.BrowserClient.GetAsync(
                       $"https://server{schemeCallbackResult.Headers.Location!.OriginalString}");

        Assert.Equal(HttpStatusCode.Redirect, clientCallbackResult.StatusCode);
        Assert.NotNull(clientCallbackResult.Headers.Location);
        Assert.StartsWith("https://code_client/callback?", clientCallbackResult.Headers.Location!.AbsoluteUri);
        // _testOutputHelper.WriteLine(clientCallbackResult.Headers.Location!.AbsoluteUri);


        // Assert match state and nonce between User and Auth Server
        Assert.Equal(_mockAuthorServerPipeline.GetClientState(clientCallbackResult), clientState, StringComparer.OrdinalIgnoreCase);

        queryParams = QueryHelpers.ParseQuery(clientCallbackResult.Headers.Location.Query);
        Assert.Contains(queryParams, p => p.Key == "code");
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
        Assert.NotNull(accessToken);
        Assert.NotNull(accessToken.IdentityToken);
        var jwt = new JwtSecurityToken(accessToken.IdentityToken);
        Assert.NotNull(new JwtSecurityToken(accessToken.AccessToken));


        using var jsonDocument = JsonDocument.Parse(jwt.Payload.SerializeToJson());
        var formattedStatement = JsonSerializer.Serialize(
            jsonDocument,
            IndentedJsonOptions
        );

        var formattedHeader = Base64UrlEncoder.Decode(jwt.EncodedHeader);

        _testOutputHelper.WriteLine(formattedHeader);
        _testOutputHelper.WriteLine(formattedStatement);



        // udap.org Tiered 4.3
        // aud: client_id of Resource Holder (matches client_id in Resource Holder request in Step 3.4)
        Assert.Contains(jwt.Claims, c => c.Type == "aud");
        Assert.Equal(clientId, jwt.Claims.Single(c => c.Type == "aud").Value);

        // iss: IdP’s unique identifying URI (matches idp parameter from Step 2)
        Assert.Contains(jwt.Claims, c => c.Type == "iss");
        Assert.Equal(UdapAuthServerPipeline.BaseUrl, jwt.Claims.Single(c => c.Type == "iss").Value);

        Assert.Contains(jwt.Claims, c => c.Type == "hl7_identifier");
        Assert.Equal("123", jwt.Claims.Single(c => c.Type == "hl7_identifier").Value);




        // sub: unique identifier for user in namespace of issuer, i.e. iss + sub is globally unique

        // TODO: Currently the sub is the code given at access time.  Maybe that is OK?  I could put the clientId in from 
        // backchannel.  But I am not sure I want to show that.  After all it is still globally unique.
        // Assert.Contains(jwt.Claims, c => c.Type == "sub");
        // Assert.Equal(backChannelClientId, jwt.Claims.Single(c => c.Type == "sub").Value);

        // Assert.Contains(jwt.Claims, c => c.Type == "sub");
        // Assert.Equal(backChannelCode, jwt.Claims.Single(c => c.Type == "sub").Value);

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
        Assert.NotNull(resultDocument);
        Assert.NotNull(resultDocument!.ClientId);

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
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.NotNull(response.Headers.Location);
        Assert.Contains("https://server/Account/Login", response.Headers.Location!.AbsoluteUri);
        // _testOutputHelper.WriteLine(response.Headers.Location!.AbsoluteUri);
        var queryParams = QueryHelpers.ParseQuery(response.Headers.Location.Query);
        Assert.Contains(queryParams, p => p.Key == "ReturnUrl");
        Assert.DoesNotContain(queryParams, p => p.Key == "code");
        Assert.DoesNotContain(queryParams, p => p.Key == "state");


        // Pull the inner query params from the ReturnUrl
        var returnUrl = queryParams.Single(p => p.Key == "ReturnUrl").Value.ToString();
        Assert.StartsWith("/connect/authorize/callback?", returnUrl);
        queryParams = QueryHelpers.ParseQuery(returnUrl);
        Assert.Contains("openid user/*.read", queryParams.Single(q => q.Key == "scope").Value.ToString());
        Assert.Equal(clientState, queryParams.Single(q => q.Key == "state").Value.ToString(), StringComparer.OrdinalIgnoreCase);
        Assert.Equal("https://idpserver", queryParams.Single(q => q.Key == "idp").Value.ToString(), StringComparer.OrdinalIgnoreCase);

        var schemes = await _mockAuthorServerPipeline.Resolve<IAuthenticationSchemeProvider>().GetAllSchemesAsync();

        var sb = new StringBuilder();
        sb.Append("https://server/externallogin/challenge?"); // built in UdapAccount/Login/Index.cshtml.cs
        sb.Append("scheme=").Append(schemes.First().Name);
        sb.Append("&returnUrl=").Append(Uri.EscapeDataString(returnUrl));
        clientAuthorizeUrl = sb.ToString();
        

        // response after discovery and registration
        _mockAuthorServerPipeline.BrowserClient.AllowCookies = true; // Need to set the idsrv cookie so calls to /authorize will succeed

        Assert.Null(_mockAuthorServerPipeline.BrowserClient.GetXsrfCookie("https://server/federation/udap-tiered/signin",
            new TieredOAuthAuthenticationOptions().CorrelationCookie.Name!));

       var exception = await Assert.ThrowsAsync<Exception>(() => _mockAuthorServerPipeline.BrowserClient.GetAsync(clientAuthorizeUrl));
       Assert.Equal("Missing required udap scope from client for Tiered OAuth", exception.Message);
    }


    /// <summary>
    /// During Tiered OAuth between data holder and IdP the openid and udap scope are required 
    /// Client call to /authorize? should request with udap scope.
    /// https://hl7.org/fhir/us/udap-security/user.html#data-holder-authentication-request-to-idp
    /// </summary>
    /// <returns></returns>
    [Theory]
    [InlineData([new[] { "openid", "email", "profile"}])]
    [InlineData([new[] { "udap", "email", "profile" }])]
    public async Task ClientAuthorize_Missing_udap_or_idp_scope_between_dataholder_and_IdP_Test(string[] scopes)
    {
        // var scopes = new List<string>() { "email", "profile" };
        BuildUdapAuthorizationServer(scopes.ToList());
        BuildUdapIdentityProvider1();

        // Register client with auth server
        var resultDocument = await RegisterClientWithAuthServer();
        _mockAuthorServerPipeline.RemoveSessionCookie();
        _mockAuthorServerPipeline.RemoveLoginCookie();
        Assert.NotNull(resultDocument);
        Assert.NotNull(resultDocument!.ClientId);

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
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.NotNull(response.Headers.Location);
        Assert.Contains("https://server/Account/Login", response.Headers.Location!.AbsoluteUri);
        // _testOutputHelper.WriteLine(response.Headers.Location!.AbsoluteUri);
        var queryParams = QueryHelpers.ParseQuery(response.Headers.Location.Query);
        Assert.Contains(queryParams, p => p.Key == "ReturnUrl");
        Assert.DoesNotContain(queryParams, p => p.Key == "code");
        Assert.DoesNotContain(queryParams, p => p.Key == "state");
        

        // Pull the inner query params from the ReturnUrl
        var returnUrl = queryParams.Single(p => p.Key == "ReturnUrl").Value.ToString();
        Assert.StartsWith("/connect/authorize/callback?", returnUrl);
        queryParams = QueryHelpers.ParseQuery(returnUrl);
        Assert.Contains("udap openid user/*.read", queryParams.Single(q => q.Key == "scope").Value.ToString());
        Assert.Equal(clientState, queryParams.Single(q => q.Key == "state").Value.ToString(), StringComparer.OrdinalIgnoreCase);
        Assert.Equal("https://idpserver", queryParams.Single(q => q.Key == "idp").Value.ToString(), StringComparer.OrdinalIgnoreCase);

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

        Assert.Null(_mockAuthorServerPipeline.BrowserClient.GetXsrfCookie("https://server/federation/udap-tiered/signin",
            new TieredOAuthAuthenticationOptions().CorrelationCookie.Name!));
        var backChannelChallengeResponse = await _mockAuthorServerPipeline.BrowserClient.GetAsync(clientAuthorizeUrl);
        Assert.NotNull(_mockAuthorServerPipeline.BrowserClient.GetXsrfCookie("https://server/federation/udap-tiered/signin",
            new TieredOAuthAuthenticationOptions().CorrelationCookie.Name!));

        Assert.Equal(HttpStatusCode.Redirect, backChannelChallengeResponse.StatusCode);
        Assert.NotNull(backChannelChallengeResponse.Headers.Location);
        Assert.StartsWith("https://idpserver/connect/authorize", backChannelChallengeResponse.Headers.Location!.AbsoluteUri);

        // _testOutputHelper.WriteLine(backChannelChallengeResponse.Headers.Location!.AbsoluteUri);
        Assert.True(QueryHelpers.ParseQuery(backChannelChallengeResponse.Headers.Location.Query).Single(p => p.Key == "client_id").Value.Count > 0);
        var backChannelState = QueryHelpers.ParseQuery(backChannelChallengeResponse.Headers.Location.Query)
            .Single(p => p.Key == "state").Value.ToString();
        Assert.False(string.IsNullOrEmpty(backChannelState));

        var idpClient = _mockIdPPipeline.Clients.Single(c => c.ClientName == "AuthServer Client");
        Assert.True(idpClient.AlwaysIncludeUserClaimsInIdToken);


        Debug.Assert(_mockIdPPipeline.BrowserClient != null, "_mockIdPPipeline.BrowserClient != null");
        var backChannelAuthResult =
            await _mockIdPPipeline.BrowserClient.GetAsync(backChannelChallengeResponse.Headers.Location);
        _testOutputHelper.WriteLine(HttpUtility.UrlDecode(backChannelAuthResult.Headers.Location?.Query));

        Assert.Equal(HttpStatusCode.Redirect, backChannelAuthResult.StatusCode);
        Assert.NotNull(backChannelAuthResult.Headers.Location);
        Assert.StartsWith("https://server/federation/udap-tiered/signin", backChannelAuthResult.Headers.Location!.AbsoluteUri); //signin callback scheme

        var responseParams = QueryHelpers.ParseQuery(backChannelAuthResult.Headers.Location.Query);
        Assert.Equal("invalid_request", responseParams["error"].ToString(), StringComparer.OrdinalIgnoreCase);
        Assert.Equal("Missing udap and/or openid scope between data holder and IdP", responseParams["error_description"].ToString(), StringComparer.OrdinalIgnoreCase);
        Assert.Equal(scopes.ToSpaceSeparatedString(), responseParams["scope"].ToString(), StringComparer.OrdinalIgnoreCase);
    }

    private async Task<UdapDynamicClientRegistrationDocument?> RegisterClientWithAuthServer()
    {
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirLabsApiClientLocalhostCert.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirLabsApiClientLocalhostCert.pfx", "udap-test");
#endif

        var udapClient = _mockAuthorServerPipeline.Resolve<IUdapClient>();

        //
        // Typically the client would validate a server before proceeding to registration.
        //
        udapClient.UdapServerMetadata = new UdapMetadata(Substitute.For<UdapMetadataOptions>())
            { RegistrationEndpoint = UdapAuthServerPipeline.RegistrationEndpoint };


        var documentResponse = await udapClient.RegisterAuthCodeClient(
            clientCert,
            "udap openid user/*.read",
            "https://server/UDAP_Ecosystem_Gears.png", 
            new List<string> { "https://code_client/callback" });

        Assert.Null(documentResponse.GetError());
        
        return documentResponse;
    }
}
