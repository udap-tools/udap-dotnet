#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer;
using Duende.IdentityServer.EntityFramework.Stores;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using Udap.Common;
using Udap.Common.Certificates;
using Udap.Identity.Provider;
using Udap.Server.Configuration;
using Udap.Server.DbContexts;

namespace Udap.Idp;

internal static class HostingExtensions
{
    public static WebApplication ConfigureServices(this WebApplicationBuilder builder, string[] args)
    {
        // if (! int.TryParse(Environment.GetEnvironmentVariable("ASPNETCORE_HTTPS_PORT"), out int sslPort))
        // {
        //     sslPort = 5002;
        // }

        builder.Services.AddDataProtection()
            .PersistKeysToDbContext<UdapDbContext>();

        var provider = builder.Configuration.GetValue("provider", "SqlServer");

        var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
        Log.Logger.Debug($"ConnectionString:: {connectionString}");

        builder.Services.AddHttpLogging(o => { });
        builder.Services.AddOptions();
        builder.Services.AddMemoryCache();
        builder.Services.AddHttpContextAccessor();
        builder.Services.AddRazorPages();


        builder.Services.AddUdapServerAsIdentityProvider(
                options =>
                {
                    var udapServerOptions = builder.Configuration.GetOption<ServerSettings>("ServerSettings");
                    options.DefaultSystemScopes = udapServerOptions.DefaultSystemScopes;
                    options.DefaultUserScopes = udapServerOptions.DefaultUserScopes;
                    options.ForceStateParamOnAuthorizationCode = udapServerOptions.ForceStateParamOnAuthorizationCode;
                    options.LogoRequired = udapServerOptions.LogoRequired;
                    options.AlwaysIncludeUserClaimsInIdToken = udapServerOptions.AlwaysIncludeUserClaimsInIdToken;
                    options.RequireConsent = udapServerOptions.RequireConsent;
                    options.AllowRememberConsent = udapServerOptions.AllowRememberConsent;
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

                        "Pgsql" => options.UdapDbContext = b =>
                            b.UseNpgsql(connectionString,
                                dbOpts => dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName)),

                        _ => throw new Exception($"Unsupported provider: {provider}")
                    })
            .AddPrivateFileStore();

        
        builder.Services.Configure<UdapFileCertStoreManifest>(builder.Configuration.GetSection(Common.Constants.UDAP_FILE_STORE_MANIFEST));
        builder.Services.AddSingleton<IPrivateCertificateStore>(sp =>
            new IssuedCertificateStore(
                sp.GetRequiredService<IOptionsMonitor<UdapFileCertStoreManifest>>(),
                sp.GetRequiredService<ILogger<IssuedCertificateStore>>()));

        builder.Services.AddUdapMetadataServer(builder.Configuration);

        var identityServer = builder.Services.AddIdentityServer(options =>
            {
                // https://docs.duendesoftware.com/identityserver/v6/fundamentals/resources/api_scopes#authorization-based-on-scopes
                options.EmitStaticAudienceClaim = true;
            })
            .AddServerSideSessions();

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
                .AddConfigurationStore(options =>
                    _ = provider switch
                    {
                        "Sqlite" => options.ConfigureDbContext = b =>
                            b.UseSqlite(connectionString,
                                dbOpts => dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName)),

                        "SqlServer" => options.ConfigureDbContext = b =>
                            b.UseSqlServer(connectionString,
                                dbOpts => dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName)),


                        "Pgsql" => options.ConfigureDbContext = b =>
                            b.UseNpgsql(connectionString,
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

                        "Pgsql" => options.ConfigureDbContext = b =>
                            b.UseNpgsql(connectionString,
                                dbOpts => dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName)),

                        _ => throw new Exception($"Unsupported provider: {provider}")
                    });
        }

        identityServer
            .AddResourceStore<ResourceStore>()
            .AddClientStore<ClientStore>()
            //TODO remove
            .AddTestUsers(TestUsers.Users);


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
        if (Environment.GetEnvironmentVariable("GCLOUD_PROJECT") != null)
        {
            app.Use(async (ctx, next) =>
            {
                var header = ctx.Request.Headers[ForwardedHeadersDefaults.XForwardedProtoHeaderName].FirstOrDefault();
                if (header != null)
                {
                    ctx.Request.Scheme = header;
                }

                await next();
            });
        }
        
        app.UseHttpLogging();

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

        app.UseUdapMetadataServer();
        app.UseUdapIdPServer();
        app.UseIdentityServer();
        
        
        // uncomment if you want to add a UI
        app.UseAuthorization();
        app.MapRazorPages().RequireAuthorization();
        
        return app;
    }
}