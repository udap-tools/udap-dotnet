// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.


using Duende.IdentityServer;
using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Test;
using FluentAssertions;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Duende.IdentityServer.Validation;
using Udap.Common.Certificates;
using Udap.Common.Models;
using Udap.Server;
using Udap.Server.Configuration;
using Udap.Server.Configuration.DependencyInjection.BuilderExtensions;
using Udap.Server.Registration;
using Udap.Server.Services;
using Udap.Server.Services.Default;
using Udap.Server.Validation.Default;


namespace UdapServer.Tests.Common;

public class UdapIdentityServerPipeline
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
    public List<IdentityResource> IdentityScopes { get; set; } = new List<IdentityResource>();
    public List<ApiResource> ApiResources { get; set; } = new List<ApiResource>();
    public List<ApiScope> ApiScopes { get; set; } = new List<ApiScope>();
    public List<TestUser> Users { get; set; } = new List<TestUser>();
    public List<Community> Communities { get; set; } = new List<Community>();
    public List<RootCertificate> RootCertificates { get; set; } = new List<RootCertificate>();

    public TestServer Server { get; set; }
    public HttpMessageHandler Handler { get; set; }

    public BrowserClient BrowserClient { get; set; }
    public HttpClient BackChannelClient { get; set; }

    public MockMessageHandler BackChannelMessageHandler { get; set; } = new MockMessageHandler();
    public MockMessageHandler JwtRequestMessageHandler { get; set; } = new MockMessageHandler();

    public event Action<IServiceCollection> OnPreConfigureServices = services => { };
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

        if (enableLogging)
        {
            builder.ConfigureLogging((ctx, b) => b.AddConsole());
        }

        Server = new TestServer(builder);
        Handler = Server.CreateHandler();
            
        BrowserClient = new BrowserClient(new BrowserHandler(Handler));
        // BackChannelClient = new HttpClient(Handler);

    }

    public void ConfigureServices(IServiceCollection services)
    {

        OnPreConfigureServices(services);

        services.AddAuthentication(opts =>
        {
            opts.AddScheme("external", scheme =>
            {
                scheme.DisplayName = "External";
                scheme.HandlerType = typeof(MockExternalAuthenticationHandler);
            });
        });
        services.AddTransient<MockExternalAuthenticationHandler>(svcs =>
        {
            var handler = new MockExternalAuthenticationHandler(svcs.GetRequiredService<IHttpContextAccessor>());
            if (OnFederatedSignout != null) handler.OnFederatedSignout = OnFederatedSignout;
            return handler;
        });

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
            .AddInMemoryApiScopes(ApiScopes)
            .AddTestUsers(Users)
            .AddDeveloperSigningCredential(persistKey: false)

            .AddUdapDiscovery(BaseUrl)
            .AddUdapServerConfiguration()
            .AddInMemoryUdapCertificates(Communities, RootCertificates);

        services.AddHttpClient(IdentityServerConstants.HttpClients.BackChannelLogoutHttpClient)
            .AddHttpMessageHandler(() => BackChannelMessageHandler);

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
    public AuthorizationRequest ConsentRequest { get; set; }
    public ConsentResponse ConsentResponse { get; set; }

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
    public Cookie GetSessionCookie()
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
}

