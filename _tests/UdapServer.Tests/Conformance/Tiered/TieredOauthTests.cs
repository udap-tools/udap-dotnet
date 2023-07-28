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
using System.Text;
using System.Text.Json;
using Duende.IdentityServer;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Test;
using FluentAssertions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Udap.Client.Configuration;
using Udap.Common;
using Udap.Common.Models;
using Udap.Model;
using Udap.Model.Registration;
using Udap.Model.Statement;
using Udap.Server.Configuration;
using Udap.Server.Models;
using Udap.Util.Extensions;
using UdapServer.Tests.Common;
using Xunit.Abstractions;

namespace UdapServer.Tests.Conformance.Tiered;

[Collection("Udap.Idp")]
public class TieredOauthTests
{
    private readonly ITestOutputHelper _testOutputHelper;

    private UdapAuthServerPipeline _mockAuthorServerPipeline = new UdapAuthServerPipeline();
    private UdapIdentityServerPipeline _mockIdPPipeline = new UdapIdentityServerPipeline();
    
    private IAuthenticationSchemeProvider _schemeProvider;

    public TieredOauthTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
        var sureFhirLabsAnchor = new X509Certificate2("CertStore/anchors/caLocalhostCert.cer");
        var intermediateCert = new X509Certificate2("CertStore/intermediates/intermediateLocalhostCert.cer");

        var idpAnchor1 = new X509Certificate2("CertStore/anchors/caLocalhostCert.cer");
        var idpIntermediate1 = new X509Certificate2("CertStore/intermediates/intermediateLocalhostCert.cer");

        BuildUdapAuthorizationServer(sureFhirLabsAnchor, intermediateCert);
        BuildUdapIdentityProvider(idpAnchor1, idpIntermediate1);
    }

    private void BuildUdapAuthorizationServer(X509Certificate2 sureFhirLabsAnchor, X509Certificate2 intermediateCert)
    {
        _mockAuthorServerPipeline.OnPostConfigureServices += s =>
        {
            s.AddSingleton<ServerSettings>(new ServerSettings
            {
                ServerSupport = ServerSupport.Hl7SecurityIG,
                IdPMappings = new List<IdPMapping>
                {
                    new IdPMapping()
                    {
                        Scheme = "TieredOAuth",  // default name
                        IdpBaseUrl = "https://idpserver"
                    }
                }
                // DefaultUserScopes = "udap",
                // DefaultSystemScopes = "udap"
                // ForceStateParamOnAuthorizationCode = false (default)
            });

            s.AddSingleton<IOptionsMonitor<UdapClientOptions>>(new OptionsMonitorForTests<UdapClientOptions>(
                new UdapClientOptions
                {
                    ClientName = "AuthServer Client",
                    Contacts = new HashSet<string> { "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com" }
                })
            );
        };

        _mockAuthorServerPipeline.OnPreConfigureServices += (builderContext, services) =>
        {
            // This registers Clients as List<Client> so downstream I can pick it up in InMemoryUdapClientRegistrationStore
            // Duende's AddInMemoryClients extension registers as IEnumerable<Client> and is used in InMemoryClientStore as readonly.
            // It was not intended to work with the concept of a dynamic client registration.
            services.AddSingleton(_mockAuthorServerPipeline.Clients);

            services.Configure<UdapFileCertStoreManifest>(builderContext.Configuration.GetSection(Udap.Common.Constants.UDAP_FILE_STORE_MANIFEST));

            services.AddAuthentication()
            //
            // By convention the scheme name should match the community name in UdapFileCertStoreManifest
            // to allow discovery of the IdPBaseUrl
            //
            .AddTieredOAuthForTests(options =>
            {
                options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                options.AuthorizationEndpoint = "https://idpserver/connect/authorize";
                options.TokenEndpoint = "https://idpserver/connect/token";
                options.IdPBaseUrl = "https://idpserver";
            }, _mockIdPPipeline); // point backchannel to the IdP

           
            services.AddAuthorization(); // required for TieredOAuth Testing

            using var serviceProvider = services.BuildServiceProvider();

            _schemeProvider = serviceProvider.GetRequiredService<IAuthenticationSchemeProvider>();
            
        };  

        _mockAuthorServerPipeline.OnPostConfigure += app =>
        {
            app.UseAuthorization(); // required for TieredOAuth Testing
        };



        _mockAuthorServerPipeline.Initialize(enableLogging: true);
        _mockAuthorServerPipeline.BrowserClient.AllowAutoRedirect = false;
        

        _mockAuthorServerPipeline.Communities.Add(new Community
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

       
        // _mockAuthorServerPipeline.



        _mockAuthorServerPipeline.IdentityScopes.Add(new IdentityResources.OpenId());
        _mockAuthorServerPipeline.IdentityScopes.Add(new IdentityResources.Profile());
        _mockAuthorServerPipeline.IdentityScopes.Add(new UdapIdentityResources.Udap());

        _mockAuthorServerPipeline.ApiScopes.Add(new ApiScope("user/*.read"));

        _mockAuthorServerPipeline.Users.Add(new TestUser
        {
            SubjectId = "bob",
            Username = "bob",
            Claims = new Claim[]
            {
                new Claim("name", "Bob Loblaw"),
                new Claim("email", "bob@loblaw.com"),
                new Claim("role", "Attorney")
            }
        });
    }

    private void BuildUdapIdentityProvider(X509Certificate2 sureFhirLabsAnchor, X509Certificate2 intermediateCert)
    {
        _mockIdPPipeline.OnPostConfigureServices += s =>
        {
            s.AddSingleton<ServerSettings>(new ServerSettings
            {
                ServerSupport = ServerSupport.UDAP,
                DefaultUserScopes = "udap",
                DefaultSystemScopes = "udap",
                // ForceStateParamOnAuthorizationCode = false (default)
            });
        };

        _mockIdPPipeline.OnPreConfigureServices += (builderContext, services) =>
        {
            // This registers Clients as List<Client> so downstream I can pick it up in InMemoryUdapClientRegistrationStore
            // Duende's AddInMemoryClients extension registers as IEnumerable<Client> and is used in InMemoryClientStore as readonly.
            // It was not intended to work with the concept of a dynamic client registration.
            services.AddSingleton(_mockIdPPipeline.Clients);

        };

        _mockIdPPipeline.Initialize(enableLogging: true);
        _mockIdPPipeline.BrowserClient.AllowAutoRedirect = false;

        _mockIdPPipeline.Communities.Add(new Community
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

        _mockIdPPipeline.IdentityScopes.Add(new IdentityResources.OpenId());
        _mockIdPPipeline.IdentityScopes.Add(new IdentityResources.Profile());
        _mockIdPPipeline.IdentityScopes.Add(new UdapIdentityResources.Udap());
        _mockIdPPipeline.IdentityScopes.Add(new IdentityResources.Email());

        _mockIdPPipeline.Users.Add(new TestUser
        {
            SubjectId = "bob",
            Username = "bob",
            Claims = new Claim[]
            {
                new Claim("name", "Bob Loblaw"),
                new Claim("email", "bob@loblaw.com"),
                new Claim("role", "Attorney")
            }
        });

        // Allow pipeline to sign in during Login
        _mockIdPPipeline.Subject = new IdentityServerUser("bob").CreatePrincipal();
    }

    [Fact]
    public async Task ShouldReturnAuthorizationCode()
    {
        // Register client with auth server
        var resultDocument = await RegisterClientWithAuthServer();
        resultDocument.Should().NotBeNull();
        resultDocument!.ClientId.Should().NotBeNull();

        // Data Holder's Auth Server validates Identity Provider's Server software statement

        var state = Guid.NewGuid().ToString();

        var url = _mockAuthorServerPipeline.CreateAuthorizeUrl(
            clientId: resultDocument!.ClientId!,
            responseType: "code",
            scope: "udap openid user/*.read",
            redirectUri: "https://code_client/callback",
            state: state,
            extra: new
            {
                idp = "https://idpserver"
            });

        _mockAuthorServerPipeline.BrowserClient.AllowAutoRedirect = false;
        // The BrowserHandler.cs will normally set the cookie to indicate user signed in.
        // We want to skip that and get a redirect to the login page
        _mockAuthorServerPipeline.BrowserClient.AllowCookies = false;

        var response = await _mockAuthorServerPipeline.BrowserClient.GetAsync(url);

        response.StatusCode.Should().Be(HttpStatusCode.Redirect, await response.Content.ReadAsStringAsync());
        response.Headers.Location.Should().NotBeNull();
        response.Headers.Location!.AbsoluteUri.Should().Contain("https://server/Account/Login");
        // _testOutputHelper.WriteLine(response.Headers.Location!.AbsoluteUri);
        var queryParams = QueryHelpers.ParseQuery(response.Headers.Location.Query);
        queryParams.Should().Contain(p => p.Key == "ReturnUrl");
        queryParams.Should().NotContain(p => p.Key == "code");

        // Pull the inner query params from the ReturnUrl
        var returnUrl = queryParams.Single(p => p.Key == "ReturnUrl").Value.ToString();
        returnUrl.Should().StartWith("/connect/authorize/callback?");
        queryParams = QueryHelpers.ParseQuery(returnUrl);
        queryParams.Single(q => q.Key == "scope").Value.ToString().Should().Contain("udap openid user/*.read");
        queryParams.Single(q => q.Key == "state").Value.Should().BeEquivalentTo(state);
        queryParams.Single(q => q.Key == "idp").Value.Should().BeEquivalentTo("https://idpserver");



        
        var schemes = await _schemeProvider.GetAllSchemesAsync();
   
        var sb = new StringBuilder();
        sb.Append("https://server/externallogin/challenge?"); // built in UdapAccount/Login/Index.cshtml.cs
        sb.Append("scheme=").Append(schemes.First().Name);
        sb.Append("&returnUrl=").Append(Uri.EscapeDataString(returnUrl));
        url = sb.ToString();

        // Auto Dynamic registration between Auth Server and Identity Provider happens here.
        // /Challenge?
        //      ctx.ChallengeAsync -> launch registered scheme.  In this case the TieredOauthAuthenticationHandler
        //         see: OnExternalLoginChallenge and Challenge(props, scheme) in ExternalLogin/Challenge.cshtml.cs or UdapTieredLogin/Challenge.cshtml.cs
        //      Backchannel
        //          Discovery
        //          Auto registration
        // *** We are here after the next line of code ***
        //
        //          Authentication request (/authorize?)
        //            User logs in at IdP
        //          Authentication response
        //          Token request
        //          Data Holder incorporates user input into authorization decision
        //


        // response after discovery and registration
        _mockAuthorServerPipeline.BrowserClient.AllowCookies = true; // Need to set the idsrv cookie so calls to /authorize will succeed
        var backChannelChallengeResponse = await _mockAuthorServerPipeline.BrowserClient.GetAsync(url);

        backChannelChallengeResponse.StatusCode.Should().Be(HttpStatusCode.Redirect, await backChannelChallengeResponse.Content.ReadAsStringAsync());
        backChannelChallengeResponse.Headers.Location.Should().NotBeNull();
        backChannelChallengeResponse.Headers.Location!.AbsoluteUri.Should().Contain("https://idpserver/connect/authorize");
        // _testOutputHelper.WriteLine(backChannelResponse.Headers.Location!.AbsoluteUri);

        var backChannelAuthResult = await _mockIdPPipeline.BrowserClient.GetAsync(backChannelChallengeResponse.Headers.Location);
        backChannelAuthResult.StatusCode.Should().Be(HttpStatusCode.Redirect, await backChannelAuthResult.Content.ReadAsStringAsync());
        // _testOutputHelper.WriteLine(backChannelAuthResult.Headers.Location!.AbsoluteUri);
        backChannelAuthResult.Headers.Location!.AbsoluteUri.Should().Contain("https://idpserver/Account/Login");

        var logingCallbackResult = await _mockIdPPipeline.BrowserClient.GetAsync(backChannelAuthResult.Headers.Location!.AbsoluteUri);
        logingCallbackResult.StatusCode.Should().Be(HttpStatusCode.Redirect, await backChannelAuthResult.Content.ReadAsStringAsync());
         _testOutputHelper.WriteLine(logingCallbackResult.Headers.Location!.OriginalString);

        // var schemeCallbackResult = await _mockIdPPipeline.BrowserClient.GetAsync(logingCallbackResult.Headers.Location!.OriginalString);
        // _testOutputHelper.WriteLine(schemeCallbackResult.Headers.Location!.OriginalString);
    }

    private async Task<UdapDynamicClientRegistrationDocument?> RegisterClientWithAuthServer()
    {
        var clientCert = new X509Certificate2("CertStore/issued/fhirLabsApiClientLocalhostCert.pfx", "udap-test");

        await _mockAuthorServerPipeline.LoginAsync("bob");

        var document = UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock tiered test")
            .WithLogoUri("https://example.com/logo.png")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("udap openid user/*.read")
            .WithResponseTypes(new List<string> { "code" })
            .WithRedirectUrls(new List<string> { "https://code_client/callback" })
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

        var response = await _mockAuthorServerPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        response.StatusCode.Should().Be(HttpStatusCode.Created);
        var resultDocument = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();

        return resultDocument;
    }
}
