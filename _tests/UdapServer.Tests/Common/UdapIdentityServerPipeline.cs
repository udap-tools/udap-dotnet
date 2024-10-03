#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

// Original code from:
// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

#pragma warning disable

using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
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
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Udap.Common;
using Udap.Common.Certificates;
using Udap.Common.Models;
using Udap.Server.Configuration.DependencyInjection;
using Udap.Server.Registration;
using Udap.Server.Security.Authentication.TieredOAuth;
using Constants = Udap.Server.Constants;

namespace UdapServer.Tests.Common;

public class UdapIdentityServerPipeline
{
    public string BaseUrl => _baseUrl;
    private readonly string _baseUrl = "https://idpserver";
    private readonly string? _appSettingsFile;

    public readonly string LoginPage;
    public readonly string LogoutPage;
    public readonly string ConsentPage;
    public readonly string ErrorPage;
    public readonly string DeviceAuthorization;
    public readonly string DiscoveryEndpoint;
    public readonly string DiscoveryKeysEndpoint;
    public readonly string AuthorizeEndpoint;
    public readonly string BackchannelAuthenticationEndpoint;
    public readonly string TokenEndpoint;
    public readonly string RevocationEndpoint;
    public readonly string UserInfoEndpoint;
    public readonly string IntrospectionEndpoint;
    public readonly string IdentityTokenValidationEndpoint;
    public readonly string EndSessionEndpoint;
    public readonly string EndSessionCallbackEndpoint;
    public readonly string CheckSessionEndpoint;
    public readonly string RegistrationEndpoint;
    public readonly string FederatedSignOutPath;
    public readonly string FederatedSignOutUrl;

    public UdapIdentityServerPipeline(string? baseUrl = null, string? appSettingsFile = null)
    {
        _baseUrl = baseUrl ?? _baseUrl;
        _appSettingsFile = appSettingsFile;
    
        LoginPage = BaseUrl + "/account/login";
        LogoutPage = BaseUrl + "/account/logout";
        ConsentPage = BaseUrl + "/account/consent";
        ErrorPage = BaseUrl + "/home/error";

        DeviceAuthorization = BaseUrl + "/connect/deviceauthorization";
        DiscoveryEndpoint = BaseUrl + "/.well-known/openid-configuration";
        DiscoveryKeysEndpoint = BaseUrl + "/.well-known/openid-configuration/jwks";
        AuthorizeEndpoint = BaseUrl + "/connect/authorize";
        BackchannelAuthenticationEndpoint = BaseUrl + "/connect/ciba";
        TokenEndpoint = BaseUrl + "/connect/token";
        RevocationEndpoint = BaseUrl + "/connect/revocation";
        UserInfoEndpoint = BaseUrl + "/connect/userinfo";
        IntrospectionEndpoint = BaseUrl + "/connect/introspect";
        IdentityTokenValidationEndpoint = BaseUrl + "/connect/identityTokenValidation";
        EndSessionEndpoint = BaseUrl + "/connect/endsession";
        EndSessionCallbackEndpoint = BaseUrl + "/connect/endsession/callback";
        CheckSessionEndpoint = BaseUrl + "/connect/checksession";
        RegistrationEndpoint = BaseUrl + "/connect/register";
        FederatedSignOutPath = "/signout-oidc";
        FederatedSignOutUrl = BaseUrl + FederatedSignOutPath;
    }

    

    public IdentityServerOptions? Options { get; set; }
    public List<Client> Clients { get; set; } = new List<Client>();
    public List<IdentityResource> IdentityScopes { get; set; } = new List<IdentityResource>();
    public List<ApiResource> ApiResources { get; set; } = new List<ApiResource>();
    public List<ApiScope> ApiScopes { get; set; } = new List<ApiScope>();
    public List<TestUser> Users { get; set; } = new List<TestUser>();
    public List<Community> Communities { get; set; } = new List<Community>();
    public TestServer? Server { get; set; }
    public HttpMessageHandler? Handler { get; set; }

    public BrowserClient? BrowserClient { get; set; }
    public HttpClient? BackChannelClient { get; set; }

    public MockMessageHandler BackChannelMessageHandler { get; set; } = new MockMessageHandler();
    public MockMessageHandler JwtRequestMessageHandler { get; set; } = new MockMessageHandler();

    public event Action<WebHostBuilderContext, IServiceCollection> OnPreConfigureServices = (_, _) => { };
    public event Action<IServiceCollection> OnPostConfigureServices = _ => { };
    public event Action<IApplicationBuilder> OnPreConfigure = _ => { };
    public event Action<IApplicationBuilder> OnPostConfigure = _ => { };

    public Func<HttpContext, Task<bool>>? OnFederatedSignout;
   

    public void Initialize(string? basePath = null, bool enableLogging = false)
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

        builder.ConfigureAppConfiguration(configure => configure.AddJsonFile(_appSettingsFile ?? "appsettings.Idp1.json"));

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

        services.AddUdapServerAsIdentityProvider(baseUrl: BaseUrl)
            .AddInMemoryUdapCertificates(Communities);

        if (services.All(x => x.ServiceType != typeof(IPrivateCertificateStore)))
        {
            services.Configure<UdapFileCertStoreManifest>(
                builder.Configuration.GetSection(Udap.Common.Constants.UDAP_FILE_STORE_MANIFEST));

            services.TryAddSingleton<IPrivateCertificateStore>(sp =>
                new IssuedCertificateStore(
                    sp.GetRequiredService<IOptionsMonitor<UdapFileCertStoreManifest>>(),
                    sp.GetRequiredService<ILogger<IssuedCertificateStore>>()));
        }


        services.AddIdentityServer(options =>
            {
                options.Events = new EventsOptions
                {
                    RaiseErrorEvents = true,
                    RaiseFailureEvents = true,
                    RaiseInformationEvents = true,
                    RaiseSuccessEvents = true
                };

                Options = options;
            })
            .AddInMemoryClients(Clients)
            .AddInMemoryIdentityResources(IdentityScopes)
            .AddInMemoryApiResources(ApiResources)
            .AddInMemoryApiScopes(ApiScopes)
            .AddTestUsers(Users);
            

        services.AddUdapMetadataServer(builder.Configuration);

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

        app.Use(async (ctx, next) =>
        {
            //
            // Enabled response buffering so that I can read the response body
            //
            ctx.Request.EnableBuffering();

            if (ctx.Request.Path == "/connect/token")
            {
                var originalBody = ctx.Response.Body;

                if (ctx.Response.StatusCode == (int)HttpStatusCode.OK)
                {
                    
                    try
                    {
                        using var memStream = new MemoryStream();
                        ctx.Response.Body = memStream;
                        await next.Invoke(ctx);
                        memStream.Position = 0;
                        var responseBody = await new StreamReader(memStream).ReadToEndAsync();
                        try
                        {
                            var jsonDoc = JsonDocument.Parse(responseBody!).RootElement;
                            IdToken = new JwtSecurityToken(jsonDoc.GetString("id_token"));
                            memStream.Position = 0;
                            await memStream.CopyToAsync(originalBody);
                        }
                        catch(Exception ex)
                        {
                            using var errorMemStream = new MemoryStream(Encoding.UTF8.GetBytes(responseBody));
                            memStream.Position = 0;
                            await errorMemStream.CopyToAsync(originalBody);
                        }
                       
                    }
                    finally {
                        ctx.Response.Body = originalBody;
                    }

                    return;
                }
            }

            await next(ctx);
        });

        app.UseUdapMetadataServer();
        app.UseUdapIdPServer();
        app.UseIdentityServer();

        

        // UI endpoints
        app.Map(Constants.UIConstants.DefaultRoutePaths.Login.EnsureLeadingSlash()!, path =>
        {
            path.Run(ctx => OnLogin(ctx));
        });
        app.Map(Constants.UIConstants.DefaultRoutePaths.Logout.EnsureLeadingSlash()!, path =>
        {
            path.Run(ctx => OnLogout(ctx));
        });
        app.Map(Constants.UIConstants.DefaultRoutePaths.Consent.EnsureLeadingSlash()!, path =>
        {
            path.Run(ctx => OnConsent(ctx));
        });
        app.Map("/custom", path =>
        {
            path.Run(ctx => OnCustom(ctx));
        });
        app.Map(Constants.UIConstants.DefaultRoutePaths.Error.EnsureLeadingSlash()!, path =>
        {
            path.Run(ctx => OnError(ctx));
        });
        
        app.Map("/connect/register", path =>
        {
            path.Run(ctx => OnRegister(ctx));
        });

        app.Map("/connect/register", path =>
        {
            path.Run(ctx => OnRegister(ctx));
        });

        app.Map("/externallogin/challenge", path =>
        {
            path.Run(ctx => OnExternalLoginChallenge(ctx));
        });
        
        OnPostConfigure(app);
    }
    
    public bool LoginWasCalled { get; set; }
    public string? LoginReturnUrl { get; set; }
    public AuthorizationRequest? LoginRequest { get; set; }
    public ClaimsPrincipal? Subject { get; set; }

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
        var interactionService = ctx.RequestServices.GetRequiredService<IIdentityServerInteractionService>();
        var returnUrl = ctx.Request.Query["returnUrl"].FirstOrDefault();
        
        if (interactionService.IsValidReturnUrl(returnUrl) == false)
        {
            throw new Exception("invalid return URL");
        }

        var scheme = ctx.Request.Query["scheme"].FirstOrDefault();
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

        // When calling ChallengeAsync your handler will be called if it is registered.
        await ctx.ChallengeAsync(TieredOAuthAuthenticationDefaults.AuthenticationScheme, props);
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
    public LogoutRequest? LogoutRequest { get; set; }

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
    public AuthorizationRequest? CustomRequest { get; set; }

    private async Task OnCustom(HttpContext ctx)
    {
        CustomWasCalled = true;
        var interaction = ctx.RequestServices.GetRequiredService<IIdentityServerInteractionService>();
        CustomRequest = await interaction.GetAuthorizationContextAsync(ctx.Request.Query[Options.UserInteraction.ConsentReturnUrlParameter].FirstOrDefault());
    }

    public bool ErrorWasCalled { get; set; }
    public ErrorMessage? ErrorMessage { get; set; }
    public IServiceProvider? ApplicationServices { get; private set; }

    /// <summary>
    /// Record the backchannel Identity Token during Tiered OAuth
    /// </summary>
    public JwtSecurityToken? IdToken { get; set; }

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
}

