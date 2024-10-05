#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using AspNetCoreRateLimit;
using Duende.IdentityServer;
using Duende.IdentityServer.EntityFramework.DbContexts;
using Duende.IdentityServer.EntityFramework.Stores;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.EntityFrameworkCore;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using Serilog;
using Udap.Client.Configuration;
using Udap.Common;
using Udap.Server.Configuration;
using Udap.Server.DbContexts;
using Udap.Server.Security.Authentication.TieredOAuth;

namespace Udap.Auth.Server;

internal static class HostingExtensions
{
    public static WebApplication ConfigureServices(this WebApplicationBuilder builder)
    {
        // if (! int.TryParse(Environment.GetEnvironmentVariable("ASPNETCORE_HTTPS_PORT"), out int sslPort))
        // {
        //     sslPort = 5002;
        // }


        // TODO: Maybe build a .ProtectKeysWithCertificate extension method for use on GCP to grab the cert from the secret manager.
        // otherwise the keys are not protected.  This is more of an ASP.NET GCP hosted concern and not a UDAP concern. 
        // Yes, I would like to revisit this. 
        // https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/configuration/overview?view=aspnetcore-6.0#protectkeyswith
        builder.Services.AddDataProtection()
            .PersistKeysToDbContext<UdapDbContext>();
        

        var provider = builder.Configuration.GetValue("provider", "Pgsql");

        var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
        Log.Logger.Debug($"ConnectionString:: {connectionString}");

        builder.Services.AddHttpLogging(o =>
        {
            o.ResponseHeaders.Add(ForwardedHeadersDefaults.XForwardedProtoHeaderName);
        });

        builder.Services.AddOptions();
        builder.Services.AddMemoryCache();
        builder.Services.Configure<IpRateLimitOptions>(builder.Configuration.GetSection("IpRateLimiting"));
        builder.Services.AddInMemoryRateLimiting();
        builder.Services.AddHttpContextAccessor();
        builder.Services.AddRazorPages();

        
        
        builder.Services.Configure<UdapClientOptions>(builder.Configuration.GetSection("UdapClientOptions"));

        builder.Services.AddUdapServer(
                options =>
                {
                    var udapServerOptions = builder.Configuration.GetOption<ServerSettings>("ServerSettings");
                    options.DefaultSystemScopes = udapServerOptions.DefaultSystemScopes;
                    options.DefaultUserScopes = udapServerOptions.DefaultUserScopes;
                    options.ForceStateParamOnAuthorizationCode = udapServerOptions.ForceStateParamOnAuthorizationCode;
                    options.LogoRequired = udapServerOptions.LogoRequired;
                    options.RequireConsent = udapServerOptions.RequireConsent;
                    options.AllowRememberConsent = udapServerOptions.AllowRememberConsent;
                },
                // udapClientOptions =>
                // {
                //     var appSettings = builder.Configuration.GetOption<UdapClientOptions>("UdapClientOptions");
                //     udapClientOptions.ClientName = "Udap.Auth.SecuredControls";
                //     udapClientOptions.Contacts = new HashSet<string>
                //         { "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com" };
                //     udapClientOptions.Headers = appSettings.Headers;
                // },
                storeOptionAction: options =>
                    _ = provider switch
                    {
                        "Sqlite" => options.UdapDbContext = b =>
                            b.UseSqlite(connectionString,
                                dbOpts => dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName)),

                        "SqlServer" => options.UdapDbContext = b =>
                            b.UseSqlServer(connectionString,
                                dbOpts => dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName)),

                        "Pgsql" => options.UdapDbContext = b =>
                            b.UseNpgsql(connectionString,
                                dbOpts => dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName)),

                        _ => throw new Exception($"Unsupported provider: {provider}")
                    })
            .AddUdapResponseGenerators()
            .AddSmartV2Expander();



        builder.Services.Configure<UdapFileCertStoreManifest>(builder.Configuration.GetSection(Constants.UDAP_FILE_STORE_MANIFEST));


        var identityServer = builder.Services.AddIdentityServer(options =>
            {
                // https://docs.duendesoftware.com/identityserver/v6/fundamentals/resources/api_scopes#authorization-based-on-scopes
                options.EmitStaticAudienceClaim = true;
                options.UserInteraction.LoginUrl = "/udapaccount/login";
                options.UserInteraction.LogoutUrl = "/udapaccount/logout";
                // options.KeyManagement.Enabled = false;
                options.InputLengthRestrictions.Scope = 7000;
                
            });
            // .AddSigningCredential(new X509Certificate2("./CertStore/issued/fhirLabsApiClientLocalhostCert.pfx", "udap-test"), UdapConstants.SupportedAlgorithm.RS256)
            // .AddSigningCredential(new X509Certificate2("./CertStore/issued/fhirLabsApiClientLocalhostCert.pfx", "udap-test"), UdapConstants.SupportedAlgorithm.RS384)

            if (provider == "Pgsql")
            {
                identityServer
                    .AddConfigurationStore<NpgsqlConfigurationDbContext>(options =>
                        options.ConfigureDbContext = b =>
                            b.UseNpgsql(connectionString,
                                dbOpts => dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName))
                    )
                    .AddOperationalStore<NpgsqlPersistedGrantDbContext>(options =>
                        options.ConfigureDbContext = b =>
                            b.UseNpgsql(connectionString,
                                dbOpts => dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName))
                    );
            }
            else
            {
                identityServer
                    .AddConfigurationStore<ConfigurationDbContext>(options =>
                        _ = provider switch
                        {
                            "Sqlite" => options.ConfigureDbContext = b =>
                                b.UseSqlite(connectionString,
                                    dbOpts => dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName)),

                            "SqlServer" => options.ConfigureDbContext = b =>
                                b.UseSqlServer(connectionString,
                                    dbOpts => dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName)),

                            _ => throw new Exception($"Unsupported provider: {provider}")
                        })
                    .AddOperationalStore<PersistedGrantDbContext>(options =>
                        _ = provider switch
                        {
                            "Sqlite" => options.ConfigureDbContext = b =>
                                b.UseSqlite(connectionString,
                                    dbOpts => dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName)),

                            "SqlServer" => options.ConfigureDbContext = b =>
                                b.UseSqlServer(connectionString,
                                    dbOpts => dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName)),

                            _ => throw new Exception($"Unsupported provider: {provider}")
                        });
            }

            identityServer
                .AddResourceStore<ResourceStore>()
                .AddClientStore<ClientStore>()
                //TODO remove
                .AddTestUsers(TestUsers.Users);
                // .AddIdentityProviderStore<UdapIdentityProviderStore>();  // last to register wins. Uhg!

        //
        // Don't cache in this example project.  It can hide bugs such as the dynamic UDAP Tiered OAuth Provider
        // options properties as the OIDC handshake bounces from machine to machine.  When caching is enabled
        // TieredOAuthOptions are retained even after the redirect.  This works until you are scaled up.  
        // So best to not cache so we can catch logic errors in integration testing.
        //
        // .AddInMemoryCaching()
        // .AddIdentityProviderStoreCache<UdapIdentityProviderStore>();   // last to register wins. Uhg!


        builder.Services.AddAuthentication()
            .AddTieredOAuth(options =>
            {
                options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
            });

        builder.Services.AddSingleton<IRateLimitConfiguration, RateLimitConfiguration>();

        //
        // You don't need this unless you are down with OTEL
        //
        builder.Services.AddOpenTelemetry()
            .WithTracing(traceBuilder =>
            {
                traceBuilder
                    .AddSource(IdentityServerConstants.Tracing.Basic)
                    .AddSource(IdentityServerConstants.Tracing.Cache)
                    .AddSource(IdentityServerConstants.Tracing.Services)
                    .AddSource(IdentityServerConstants.Tracing.Stores)
                    .AddSource(IdentityServerConstants.Tracing.Validation)

                    .SetResourceBuilder(
                        ResourceBuilder.CreateDefault()
                            .AddService("Udap.Idp.Main"))

                    //.SetSampler(new AlwaysOnSampler())
                    .AddHttpClientInstrumentation()
                    .AddAspNetCoreInstrumentation()
                    .AddSqlClientInstrumentation()
                    // .AddConsoleExporter();
                    .AddOtlpExporter(otlpOptions =>
                    {
                        otlpOptions.Endpoint = new Uri("http://localhost:4317");
                    });
            });

        
        // builder.Services.AddHttpLogging(options =>
        // {
        //     options.LoggingFields = HttpLoggingFields.All;
        // });


        return builder.Build();
    }

    public static WebApplication ConfigurePipeline(this WebApplication app, string[] args)
    {
        // app.Use(async (context, next) =>
        // {
        //     if (context.Request.Path.Value != null &&
        //         context.Request.Path.Value.Contains("connect/authorize"))
        //     {
        //         var requestParams = context.Request.Query;
        //
        //         if (requestParams.Any())
        //         {
        //             if (requestParams.TryGetValue("idp", out var idp))
        //             {
        //                 context.Request.Path = "/Account/Login";
        //             }
        //         }
        //     }
        //     await next();
        // });

        if (Environment.GetEnvironmentVariable("GCLOUD_PROJECT") != null)
        {
            app.Use((ctx, next) =>
            {
                var header = ctx.Request.Headers[ForwardedHeadersDefaults.XForwardedProtoHeaderName].FirstOrDefault();
                if (header != null)
                {
                    ctx.Request.Scheme = header;
                }

                return next();
            });
        }
        
        app.UseHttpLogging();

        if (!args.Any(a => a.Contains("skipRateLimiting")))
        {
            app.UseIpRateLimiting();
        }

        if (!app.Environment.IsDevelopment())
        {
            app.UseHsts();
        }

        app.UseSerilogRequestLogging();

        if (app.Environment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }

        // uncomment if you want to add a UI
        app.UseStaticFiles();
        app.UseRouting();

        app.UseUdapServer();
        app.UseIdentityServer();


        // uncomment if you want to add a UI
        app.UseAuthorization();
        app.MapRazorPages().RequireAuthorization();
        
        return app;
    }
}