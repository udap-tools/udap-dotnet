#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using AspNetCoreRateLimit;
using Duende.IdentityServer;
using Duende.IdentityServer.EntityFramework.Stores;
using Google.Cloud.SecretManager.V1;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using Serilog;
using Udap.Client.Client;
using Udap.Common;
using Udap.Common.Certificates;
using Udap.Server.Configuration;
using Udap.Server.Security.Authentication.TieredOAuth;

namespace Udap.Idp;

internal static class HostingExtensions
{
    public static WebApplication ConfigureServices(this WebApplicationBuilder builder, string[] args)
    {
        // if (! int.TryParse(Environment.GetEnvironmentVariable("ASPNETCORE_HTTPS_PORT"), out int sslPort))
        // {
        //     sslPort = 5002;
        // }

        var provider = builder.Configuration.GetValue("provider", "SqlServer");
        
        string connectionString;

        var dbChoice = Environment.GetEnvironmentVariable("GCPDeploy") == "true" ? "gcp_db" : "DefaultConnection";


        // foreach (DictionaryEntry environmentVariable in Environment.GetEnvironmentVariables())
        // {
        //     Log.Logger.Information($"{environmentVariable.Key} :: {environmentVariable.Value}");
        // }
        //Ugly but works so far.
        if (Environment.GetEnvironmentVariable("GCLOUD_PROJECT") != null)
        {
            // Log.Logger.Information("Loading connection string from gcp_db");
            // connectionString = Environment.GetEnvironmentVariable("gcp_db");
            // Log.Logger.Information($"Loaded connection string, length:: {connectionString?.Length}");

            Log.Logger.Information("Creating client");
            var client = SecretManagerServiceClient.Create();

            const string secretResource = "projects/288013792534/secrets/gcp_db/versions/latest";

            Log.Logger.Information("Requesting {secretResource");
            // Call the API.
            AccessSecretVersionResponse result = client.AccessSecretVersion(secretResource);

            // Convert the payload to a string. Payloads are bytes by default.
            String payload = result.Payload.Data.ToStringUtf8();

            connectionString = payload;
        }
        else
        {
            connectionString = builder.Configuration.GetConnectionString(dbChoice);
        }

        

        Log.Logger.Debug($"ConnectionString:: {connectionString}");
        
        builder.Services.AddOptions();
        builder.Services.AddMemoryCache();
        builder.Services.Configure<IpRateLimitOptions>(builder.Configuration.GetSection("IpRateLimiting"));
        builder.Services.AddInMemoryRateLimiting();
        builder.Services.AddHttpContextAccessor();
        builder.Services.AddRazorPages();
        
        builder.Services.AddIdentityServer(options =>
            {
                // https://docs.duendesoftware.com/identityserver/v6/fundamentals/resources/api_scopes#authorization-based-on-scopes
                options.EmitStaticAudienceClaim = true;
                options.InputLengthRestrictions.Scope =
                    7000; //TODO: Very large!  Again I need to solve the policy/community/certification concept
                // options.UserInteraction.LoginUrl = "/joe";
            })
            .AddServerSideSessions()
            .AddConfigurationStore(options =>
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
            .AddOperationalStore(options =>
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

            .AddResourceStore<ResourceStore>()
            .AddClientStore<ClientStore>()
            //TODO remove
            .AddTestUsers(TestUsers.Users)
            
            .AddUdapServer(
                options =>
                    {
                        var udapServerOptions = builder.Configuration.GetOption<ServerSettings>("ServerSettings");
                        options.DefaultSystemScopes = udapServerOptions.DefaultSystemScopes;
                        options.DefaultUserScopes = udapServerOptions.DefaultUserScopes;
                        options.ServerSupport = udapServerOptions.ServerSupport;
                        options.ForceStateParamOnAuthorizationCode = udapServerOptions.ForceStateParamOnAuthorizationCode;
                    },
                udapClientOptions =>
                {
                    udapClientOptions.ClientName = "Udap.Auth.SecuredControls";
                    udapClientOptions.Contacts = new HashSet<string>
                        { "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com" };
                },
                options =>
                    _ = provider switch
                    {
                        "Sqlite" => options.UdapDbContext = b =>
                            b.UseSqlite(connectionString,
                                dbOpts => dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName)),

                        "SqlServer" => options.UdapDbContext = b =>
                            b.UseSqlServer(connectionString,
                                dbOpts => dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName)),

                        _ => throw new Exception($"Unsupported provider: {provider}")
                    });


        //
        // Special IPrivateCertificateStore for Google Cloud Deploy
        // 
        //
        // TODO: UdapFileCertStoreManifest doesn't have a good abstratction story for transitioning to other storage 
        builder.Services.Configure<UdapFileCertStoreManifest>(GetUdapFileCertStoreManifest(builder));
        


        builder.Services.AddAuthentication()
            .AddTieredOAuth(options =>
            {
                options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                // options.Events.OnRedirectToAuthorizationEndpoint
                // {
                //     
                // };
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
            app.Use(async (ctx, next) =>
            {
                ctx.Request.Scheme = ctx.Request.Headers[ForwardedHeadersDefaults.XForwardedProtoHeaderName];

                await next();
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

    static IConfigurationSection GetUdapFileCertStoreManifest(WebApplicationBuilder webApplicationBuilder)
    {
        //Ugly but works so far.
        if (Environment.GetEnvironmentVariable("GCLOUD_PROJECT") != null)
        {
            // Log.Logger.Information("Loading connection string from gcp_db");
            // connectionString = Environment.GetEnvironmentVariable("gcp_db");
            // Log.Logger.Information($"Loaded connection string, length:: {connectionString?.Length}");

            Log.Logger.Information("Creating client");
            var client = SecretManagerServiceClient.Create();

            var secretResource = "projects/288013792534/secrets/UdapFileCertStoreManifest/versions/latest";

            Log.Logger.Information("Requesting {secretResource");
            // Call the API.
            var result = client.AccessSecretVersion(secretResource);

            // Convert the payload to a string. Payloads are bytes by default.
            var stream = new MemoryStream(result.Payload.Data.ToByteArray());


            webApplicationBuilder.Configuration.AddJsonStream(stream);
        }

        return webApplicationBuilder.Configuration.GetSection(Common.Constants.UDAP_FILE_STORE_MANIFEST);
    }
}