#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

#pragma warning disable


using System.Net;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Web;
using Duende.IdentityServer;
using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.ResponseHandling;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Test;
using FluentAssertions;
using Google.Api;
using IdentityModel;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Udap.Auth.Server.Pages;
using Udap.Client.Client;
using Udap.Common;
using Udap.Common.Certificates;
using Udap.Common.Models;
using Udap.Model;
using Udap.Server.Configuration.DependencyInjection;
using Udap.Server.Hosting.DynamicProviders.Oidc;
using Udap.Server.Hosting.DynamicProviders.Store;
using Udap.Server.Registration;
using Udap.Server.ResponseHandling;
using Udap.Server.Security.Authentication.TieredOAuth;
using UnitTests.Common;
using AuthorizeResponse = IdentityModel.Client.AuthorizeResponse;
using Constants = Udap.Server.Constants;

namespace UdapServer.Tests.Common;

public class UdapAuthServerPipeline
{
    public const string BaseUrl = "https://server";
    public const string LoginPage = BaseUrl + "/account/login";
    public const string LogoutPage = BaseUrl + "/account/logout";
    public const string ConsentPage = BaseUrl + "/account/consent";
    public const string ErrorPage = BaseUrl + "/home/error";

    public const string DeviceAuthorization = BaseUrl + "/connect/deviceauthorization";
    public const string DiscoveryEndpoint = BaseUrl + "/.well-known/openid-configuration";
    public const string DiscoveryKeysEndpoint = BaseUrl + "/.well-known/openid-configuration/jwks";
    public const string AuthorizeEndpoint = BaseUrl + "/connect/authorize";
    public const string BackchannelAuthenticationEndpoint = BaseUrl + "/connect/ciba";
    public const string TokenEndpoint = BaseUrl + "/connect/token";
    public const string RevocationEndpoint = BaseUrl + "/connect/revocation";
    public const string UserInfoEndpoint = BaseUrl + "/connect/userinfo";
    public const string IntrospectionEndpoint = BaseUrl + "/connect/introspect";
    public const string IdentityTokenValidationEndpoint = BaseUrl + "/connect/identityTokenValidation";
    public const string EndSessionEndpoint = BaseUrl + "/connect/endsession";
    public const string EndSessionCallbackEndpoint = BaseUrl + "/connect/endsession/callback";
    public const string CheckSessionEndpoint = BaseUrl + "/connect/checksession";
    public const string RegistrationEndpoint = BaseUrl + "/connect/register";

    public const string FederatedSignOutPath = "/signout-oidc";
    public const string FederatedSignOutUrl = BaseUrl + FederatedSignOutPath;


    public IdentityServerOptions Options { get; set; }
    public List<Client> Clients { get; set; } = new List<Client>();
    public List<OidcProvider> OidcProviders { get; set; } = new List<OidcProvider>();
    public List<IdentityResource> IdentityScopes { get; set; } = new List<IdentityResource>();
    public List<ApiResource> ApiResources { get; set; } = new List<ApiResource>();
    public List<ApiScope> ApiScopes { get; set; } = new List<ApiScope>();
    public List<TestUser> Users { get; set; } = new List<TestUser>();
    public  TestUserStore? UserStore { get; set; }
    public List<Community> Communities { get; set; } = new List<Community>();
    public TestServer Server { get; set; }
    public HttpMessageHandler Handler { get; set; }

    public BrowserClient BrowserClient { get; set; }
    public HttpClient BackChannelClient { get; set; }

    public MockMessageHandler BackChannelMessageHandler { get; set; } = new MockMessageHandler();
    public MockMessageHandler JwtRequestMessageHandler { get; set; } = new MockMessageHandler();

    public TestEventService EventService = new TestEventService();

    public event Action<WebHostBuilderContext, IServiceCollection> OnPreConfigureServices = (ctx, services) => { };
    public event Action<IServiceCollection> OnPostConfigureServices = services => { };
    public event Action<IApplicationBuilder> OnPreConfigure = app => { };
    public event Action<IApplicationBuilder> OnPostConfigure = app => { };

    public Func<HttpContext, Task<bool>> OnFederatedSignout;

    public void Initialize(string basePath = null, bool enableLogging = false)
    {
        var builder = new WebHostBuilder();
        builder.ConfigureServices(ConfigureServices);
        builder.Configure(app=>
        {
            if (basePath != null)
            {
                app.Map(basePath, map =>
                {
                    ConfigureApp(map);
                });
            }
            else
            {
                ConfigureApp(app);
            }
        });

        builder.ConfigureAppConfiguration(configure => configure.AddJsonFile("appsettings.Auth.json"));

        if (enableLogging)
        {
            builder.ConfigureLogging((ctx, b) =>
            {
                b.AddConsole(c => c.LogToStandardErrorThreshold = LogLevel.Debug);
                b.SetMinimumLevel(LogLevel.Trace);
            });
        }
        
        Server = new TestServer(builder);

        Handler = Server.CreateHandler();
            
        BrowserClient = new BrowserClient(new BrowserHandler(Handler));
        
        BackChannelClient = new HttpClient(Handler);

    }

    public void ConfigureServices(WebHostBuilderContext builder, IServiceCollection services)
    {
        
        OnPreConfigureServices(builder, services);

        services.AddSingleton<DynamicIdp>();

        // services.AddAuthentication(opts =>
        // {
        //     opts.AddScheme("external", scheme =>
        //     {
        //         scheme.DisplayName = "External";
        //         scheme.HandlerType = typeof(MockExternalAuthenticationHandler);
        //     });
        // });
        services.AddTransient<MockExternalAuthenticationHandler>(svcs =>
        {
            var handler = new MockExternalAuthenticationHandler(svcs.GetRequiredService<IHttpContextAccessor>());
            if (OnFederatedSignout != null) handler.OnFederatedSignout = OnFederatedSignout;
            return handler;
        });
        
        services.AddSingleton<ITrustAnchorStore>(sp =>
            new TrustAnchorFileStore(
                sp.GetRequiredService<IOptionsMonitor<UdapFileCertStoreManifest>>(),
                new Mock<ILogger<TrustAnchorFileStore>>().Object));


        services.AddUdapServer(BaseUrl, "FhirLabsApi")
            .AddUdapInMemoryApiScopes(ApiScopes)
            .AddInMemoryUdapCertificates(Communities)
            .AddUdapResponseGenerators();
            // .AddTieredOAuthDynamicProvider();
            //.AddSmartV2Expander();


        services.AddIdentityServer(options =>
            {
                options.Events = new EventsOptions
                {
                    RaiseErrorEvents = true,
                    RaiseFailureEvents = true,
                    RaiseInformationEvents = true,
                    RaiseSuccessEvents = true
                };
                options.KeyManagement.Enabled = false;
                Options = options;
            })

            .AddInMemoryClients(Clients)
            .AddInMemoryIdentityResources(IdentityScopes)
            .AddInMemoryApiResources(ApiResources)
            .AddTestUsers(Users)
            .AddInMemoryOidcProviders(OidcProviders)
            .AddInMemoryCaching()
            .AddIdentityProviderStoreCache<UdapInMemoryIdentityProviderStore>()
            .AddDeveloperSigningCredential(persistKey: false);
            

        // BackChannelMessageHandler is used by .AddTieredOAuthForTest()
        // services.AddHttpClient(IdentityServerConstants.HttpClients.BackChannelLogoutHttpClient)
        //     .AddHttpMessageHandler(() => BackChannelMessageHandler);

        services.AddHttpClient(IdentityServerConstants.HttpClients.JwtRequestUriHttpClient)
            .AddHttpMessageHandler(() => JwtRequestMessageHandler);

        //
        // Do not check revocation.  If I decided to include revocation I would need 
        // to host another dotnet service during test.  Or if I implemented a crl caching
        // feature then I could pre-populate the cache.  
        // On Linux the cache does have my CRLs.  $HOME/.dotnet/corefx/cryptography/crls
        // So I can see that I could actually copy the crls there and ensure
        // RevocationMode is offline.  I would have to do the same for windows.
        // Good post here
        // https://stackoverflow.com/questions/55653143/is-there-a-way-to-check-and-clean-certificate-revocation-list-cache-for-asp-net

        services.AddSingleton(sp => new TrustChainValidator(
            new X509ChainPolicy
            {
                VerificationFlags = X509VerificationFlags.IgnoreWrongUsage,
                RevocationFlag = X509RevocationFlag.ExcludeRoot,
                RevocationMode = X509RevocationMode.NoCheck // This is the change unit testing with no revocation endpoint to host the revocation list.
            }, sp.GetRequiredService<ILogger<TrustChainValidator>>()));

        OnPostConfigureServices(services);
    }

    public void ConfigureApp(IApplicationBuilder app)
    {
        ApplicationServices = app.ApplicationServices;

        OnPreConfigure(app);

        app.UseUdapServer();
        app.UseIdentityServer();
        
        // UI endpoints
        app.Map(Constants.UIConstants.DefaultRoutePaths.Login.EnsureLeadingSlash(), path =>
        {
            path.Run(ctx => OnLogin(ctx));
        });
        app.Map(Constants.UIConstants.DefaultRoutePaths.Logout.EnsureLeadingSlash(), path =>
        {
            path.Run(ctx => OnLogout(ctx));
        });
        app.Map(Constants.UIConstants.DefaultRoutePaths.Consent.EnsureLeadingSlash(), path =>
        {
            path.Run(ctx => OnConsent(ctx));
        });
        app.Map("/custom", path =>
        {
            path.Run(ctx => OnCustom(ctx));
        });
        app.Map(Constants.UIConstants.DefaultRoutePaths.Error.EnsureLeadingSlash(), path =>
        {
            path.Run(ctx => OnError(ctx));
        });
        
        app.Map("/connect/register", path =>
        {
            path.Run(ctx => OnRegister(ctx));
        });
                
        app.Map("/externallogin/challenge", path =>
        {
            path.Run(ctx => OnExternalLoginChallenge(ctx));
        });

        app.Map("/externallogin/callback", path =>
        {
            path.Run(async ctx => await OnExternalLoginCallback(ctx,  new Mock<ILogger>().Object));
        });

        OnPostConfigure(app);
    }
    
    public bool LoginWasCalled { get; set; }
    public string LoginReturnUrl { get; set; }
    public AuthorizationRequest LoginRequest { get; set; }
    public ClaimsPrincipal Subject { get; set; }

    private async Task OnRegister(HttpContext ctx)
    {
        await Register(ctx);
    }

    private async Task Register(HttpContext ctx)
    {
        var regEndpoint = ctx.RequestServices.GetRequiredService<UdapDynamicClientRegistrationEndpoint>();
        await regEndpoint.Process(ctx, CancellationToken.None);
    }

    private async Task OnExternalLoginChallenge(HttpContext ctx)
    {
        //TODO: factor this code into library code and share with the Challenge.cshtml.cs file
        var interactionService = ctx.RequestServices.GetRequiredService<IIdentityServerInteractionService>();
        var returnUrl = ctx.Request.Query["returnUrl"].FirstOrDefault();
        
        if (interactionService.IsValidReturnUrl(returnUrl) == false)
        {
            throw new Exception("invalid return URL");
        }

        var scheme = ctx.Request.Query["scheme"];
        ;
        var props = new AuthenticationProperties
        {
            RedirectUri = "/externallogin/callback",

            Items =
            {
                { "returnUrl", returnUrl },
                { "scheme", scheme },
            }
        };
        
        var _udapClient = ctx.RequestServices.GetRequiredService<IUdapClient>();
        var originalRequestParams = HttpUtility.ParseQueryString(returnUrl);
        var idp = (originalRequestParams.GetValues("idp") ?? throw new InvalidOperationException()).Last();

        var parts = idp.Split(new[] { '?' }, StringSplitOptions.RemoveEmptyEntries);

        if (parts.Length > 1)
        {
            props.Parameters.Add(UdapConstants.Community, parts[1]); 
        }
        
        var idpUri = new Uri(idp);
        var idpBaseUrl = idpUri.Scheme + Uri.SchemeDelimiter + idpUri.Host + idpUri.LocalPath;
        var request = new DiscoveryDocumentRequest
        {
            Address = idpBaseUrl,
            Policy = new IdentityModel.Client.DiscoveryPolicy()
            {
                EndpointValidationExcludeList = new List<string> { OidcConstants.Discovery.RegistrationEndpoint }
            }
        };

        var openIdConfig = await _udapClient.ResolveOpenIdConfig(request);

        // TODO: Properties will be protected in state in the BuildchallengeUrl.  Need to trim out some of these
        // during the protect process.
        props.Parameters.Add(UdapConstants.Discovery.AuthorizationEndpoint, openIdConfig.AuthorizeEndpoint);
        props.Parameters.Add(UdapConstants.Discovery.TokenEndpoint, openIdConfig.TokenEndpoint);
        props.Parameters.Add("idpBaseUrl", idpBaseUrl.TrimEnd('/'));

        // When calling ChallengeAsync your handler will be called if it is registered.
        await ctx.ChallengeAsync(scheme, props);
    }

    private async Task OnExternalLoginCallback(HttpContext ctx, ILogger logger)
    {
        //TODO: factor this code into library code and share with the Callback.cshtml.cs file

        var interactionService = ctx.RequestServices.GetRequiredService<IIdentityServerInteractionService>();


        // read external identity from the temporary cookie
        var result = await ctx.AuthenticateAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);
        if (result?.Succeeded != true)
        {
            throw new Exception("External authentication error");
        }

        var externalUser = result.Principal;

        if (logger.IsEnabled(LogLevel.Debug))
        {
            var externalClaims = externalUser.Claims.Select(c => $"{c.Type}: {c.Value}");
            logger.LogDebug("External claims: {@claims}", externalClaims);
        }

        // lookup our user and external provider info
        // try to determine the unique id of the external user (issued by the provider)
        // the most common claim type for that are the sub claim and the NameIdentifier
        // depending on the external provider, some other claim type might be used
        var userIdClaim = externalUser.FindFirst(JwtClaimTypes.Subject) ??
                          externalUser.FindFirst(ClaimTypes.NameIdentifier) ??
                          throw new Exception("Unknown userid");

        var provider = result.Properties.Items["scheme"];
        var providerUserId = userIdClaim.Value;

        // find external user
        var user = UserStore.FindByExternalProvider(provider, providerUserId);
        if (user == null)
        {
            // this might be where you might initiate a custom workflow for user registration
            // in this sample we don't show how that would be done, as our sample implementation
            // simply auto-provisions new external user
            //
            // remove the user id claim so we don't include it as an extra claim if/when we provision the user
            var claims = externalUser.Claims.ToList();
            claims.Remove(userIdClaim);
            user = UserStore.AutoProvisionUser(provider, providerUserId, claims.ToList());
        }

        // this allows us to collect any additional claims or properties
        // for the specific protocols used and store them in the local auth cookie.
        // this is typically used to store data needed for signout from those protocols.
        var additionalLocalClaims = new List<Claim>();
        var localSignInProps = new AuthenticationProperties();
        CaptureExternalLoginContext(result, additionalLocalClaims, localSignInProps);

        // issue authentication cookie for user
        var isuser = new IdentityServerUser(user.SubjectId)
        {
            DisplayName = user.Username,
            IdentityProvider = provider,
            AdditionalClaims = additionalLocalClaims
        };

        await ctx.SignInAsync(isuser, localSignInProps);

        // delete temporary cookie used during external authentication
        await ctx.SignOutAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);

        // retrieve return URL
        var returnUrl = result.Properties.Items["returnUrl"] ?? "~/";

        // check if external login is in the context of an OIDC request
        var context = await interactionService.GetAuthorizationContextAsync(returnUrl);
        await EventService.RaiseAsync(new UserLoginSuccessEvent(provider, providerUserId, user.SubjectId, user.Username, true, context?.Client.ClientId));

        if (context != null)
        {
            if (context.IsNativeClient())
            {
                // The client is native, so this change in how to
                // return the response is for better UX for the end user.
                //this.LoadingPage(returnUrl, ctx);
            }
        }

        ctx.Response.Redirect(returnUrl);
    }
    

    // if the external login is OIDC-based, there are certain things we need to preserve to make logout work
    // this will be different for WS-Fed, SAML2p or other protocols
    private void CaptureExternalLoginContext(AuthenticateResult externalResult, List<Claim> localClaims, AuthenticationProperties localSignInProps)
    {
        // if the external system sent a session id claim, copy it over
        // so we can use it for single sign-out
        var sid = externalResult.Principal.Claims.FirstOrDefault(x => x.Type == JwtClaimTypes.SessionId);
        if (sid != null)
        {
            localClaims.Add(new Claim(JwtClaimTypes.SessionId, sid.Value));
        }

        // if the external provider issued an id_token, we'll keep it for signout
        var idToken = externalResult.Properties.GetTokenValue("id_token");
        if (idToken != null)
        {
            localSignInProps.StoreTokens(new[] { new AuthenticationToken { Name = "id_token", Value = idToken } });
        }
    }

    private async Task OnLogin(HttpContext ctx)
    {
        LoginWasCalled = true;
        await ReadLoginRequest(ctx);
        await IssueLoginCookie(ctx);
    }

    private async Task ReadLoginRequest(HttpContext ctx)
    {
        var interaction = ctx.RequestServices.GetRequiredService<IIdentityServerInteractionService>();
        LoginReturnUrl = ctx.Request.Query[Options.UserInteraction.LoginReturnUrlParameter].FirstOrDefault();
        LoginRequest = await interaction.GetAuthorizationContextAsync(LoginReturnUrl);
    }

    private async Task IssueLoginCookie(HttpContext ctx)
    {
        if (Subject != null)
        {
            var props = new AuthenticationProperties();
            await ctx.SignInAsync(Subject, props);
            Subject = null;
            var url = ctx.Request.Query[Options.UserInteraction.LoginReturnUrlParameter].FirstOrDefault();
            if (url != null)
            {
                ctx.Response.Redirect(url);
            }
        }
    }

    public bool LogoutWasCalled { get; set; }
    public LogoutRequest LogoutRequest { get; set; }

    private async Task OnLogout(HttpContext ctx)
    {
        LogoutWasCalled = true;
        await ReadLogoutRequest(ctx);
        await ctx.SignOutAsync();
    }

    private async Task ReadLogoutRequest(HttpContext ctx)
    {
        var interaction = ctx.RequestServices.GetRequiredService<IIdentityServerInteractionService>();
        LogoutRequest = await interaction.GetLogoutContextAsync(ctx.Request.Query["logoutId"].FirstOrDefault());
    }

    public bool ConsentWasCalled { get; set; }
    public AuthorizationRequest? ConsentRequest { get; set; }
    public ConsentResponse? ConsentResponse { get; set; }

    private async Task OnConsent(HttpContext ctx)
    {
        ConsentWasCalled = true;
        await ReadConsentMessage(ctx);
        await CreateConsentResponse(ctx);
    }
    private async Task ReadConsentMessage(HttpContext ctx)
    {
        var interaction = ctx.RequestServices.GetRequiredService<IIdentityServerInteractionService>();
        ConsentRequest = await interaction.GetAuthorizationContextAsync(ctx.Request.Query["returnUrl"].FirstOrDefault());
    }
    private async Task CreateConsentResponse(HttpContext ctx)
    {
        if (ConsentRequest != null && ConsentResponse != null)
        {
            var interaction = ctx.RequestServices.GetRequiredService<IIdentityServerInteractionService>();
            await interaction.GrantConsentAsync(ConsentRequest, ConsentResponse);
            ConsentResponse = null;

            var url = ctx.Request.Query[Options.UserInteraction.ConsentReturnUrlParameter].FirstOrDefault();
            if (url != null)
            {
                ctx.Response.Redirect(url);
            }
        }
    }

    public bool CustomWasCalled { get; set; }
    public AuthorizationRequest CustomRequest { get; set; }

    private async Task OnCustom(HttpContext ctx)
    {
        CustomWasCalled = true;
        var interaction = ctx.RequestServices.GetRequiredService<IIdentityServerInteractionService>();
        CustomRequest = await interaction.GetAuthorizationContextAsync(ctx.Request.Query[Options.UserInteraction.ConsentReturnUrlParameter].FirstOrDefault());
    }

    public bool ErrorWasCalled { get; set; }
    public ErrorMessage ErrorMessage { get; set; }
    public IServiceProvider ApplicationServices { get; private set; }

    private async Task OnError(HttpContext ctx)
    {
        ErrorWasCalled = true;
        await ReadErrorMessage(ctx);
    }

    private async Task ReadErrorMessage(HttpContext ctx)
    {
        var interaction = ctx.RequestServices.GetRequiredService<IIdentityServerInteractionService>();
        ErrorMessage = await interaction.GetErrorContextAsync(ctx.Request.Query["errorId"].FirstOrDefault());
    }

    /* helpers */
    public async Task LoginAsync(ClaimsPrincipal subject)
    {
        var old = BrowserClient.AllowAutoRedirect;
        BrowserClient.AllowAutoRedirect = false;

        Subject = subject;
        await BrowserClient.GetAsync(LoginPage);

        BrowserClient.AllowAutoRedirect = old;
    }

    public async Task LoginAsync(string subject)
    {
        await LoginAsync(new IdentityServerUser(subject).CreatePrincipal());
    }
    public async Task LogoutAsync()
    {
        var old = BrowserClient.AllowAutoRedirect;
        BrowserClient.AllowAutoRedirect = false;

        await BrowserClient.GetAsync(LogoutPage);

        BrowserClient.AllowAutoRedirect = old;
    }

    public void RemoveLoginCookie()
    {
        BrowserClient.RemoveCookie(BaseUrl, IdentityServerConstants.DefaultCookieAuthenticationScheme);
    }
    public void RemoveSessionCookie()
    {
        BrowserClient.RemoveCookie(BaseUrl, IdentityServerConstants.DefaultCheckSessionCookieName);
    }
    public Cookie? GetSessionCookie()
    {
        return BrowserClient.GetCookie(BaseUrl, IdentityServerConstants.DefaultCheckSessionCookieName);
    }

    public string CreateAuthorizeUrl(
        string clientId = null,
        string responseType = null,
        string scope = null,
        string redirectUri = null,
        string state = null,
        string nonce = null,
        string loginHint = null,
        string acrValues = null,
        string responseMode = null,
        string codeChallenge = null,
        string codeChallengeMethod = null,
        object extra = null)
    {
        var url = new RequestUrl(AuthorizeEndpoint).CreateAuthorizeUrl(
            clientId: clientId,
            responseType: responseType,
            scope: scope,
            redirectUri: redirectUri,
            state: state,
            nonce: nonce,
            loginHint: loginHint,
            acrValues: acrValues,
            responseMode: responseMode,
            codeChallenge: codeChallenge,
            codeChallengeMethod: codeChallengeMethod,
            extra: Parameters.FromObject(extra));
        return url;
    }

    public AuthorizeResponse ParseAuthorizationResponseUrl(string url)
    {
        return new AuthorizeResponse(url);
    }

    public async Task<AuthorizeResponse> RequestAuthorizationEndpointAsync(
        string clientId,
        string responseType,
        string scope = null,
        string redirectUri = null,
        string state = null,
        string nonce = null,
        string loginHint = null,
        string acrValues = null,
        string responseMode = null,
        string codeChallenge = null,
        string codeChallengeMethod = null,
        object extra = null)
    {
        var old = BrowserClient.AllowAutoRedirect;
        BrowserClient.AllowAutoRedirect = false;

        var url = CreateAuthorizeUrl(clientId, responseType, scope, redirectUri, state, nonce, loginHint, acrValues, responseMode, codeChallenge, codeChallengeMethod, extra);
        var result = await BrowserClient.GetAsync(url);
        result.StatusCode.Should().Be(HttpStatusCode.Found);

        BrowserClient.AllowAutoRedirect = old;

        var redirect = result.Headers.Location.ToString();
        if (redirect.StartsWith(IdentityServerPipeline.ErrorPage))
        {
            // request error page in pipeline so we can get error info
            await BrowserClient.GetAsync(redirect);

            // no redirect to client
            return null;
        }

        return new AuthorizeResponse(redirect);
    }

    public T Resolve<T>()
    {
        // create throw-away scope
        return ApplicationServices.CreateScope().ServiceProvider.GetRequiredService<T>();
    }

    public string? GetClientState(HttpResponseMessage response)
    {
        var queryParams = QueryHelpers.ParseQuery(response.Headers.Location.OriginalString);
        queryParams.TryGetValue("state", out var state);
        return state.SingleOrDefault();
    }
}

public class DynamicIdp
{
    public string Name { get; set; }
}