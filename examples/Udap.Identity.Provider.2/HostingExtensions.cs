#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer;
using Duende.IdentityServer.EntityFramework.Stores;
using Google.Cloud.SecretManager.V1;
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
        
        string connectionString;

        var dbChoice = Environment.GetEnvironmentVariable("GCPDeploy") == "true" ? "gcp_db_Idp2" : "DefaultConnection";

        //Ugly but works so far.
        if (Environment.GetEnvironmentVariable("GCLOUD_PROJECT") != null)
        {
            Log.Logger.Information("Creating client");
            var client = SecretManagerServiceClient.Create();

            const string secretResource = "projects/288013792534/secrets/gcp_db_Idp2/versions/latest";

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
        builder.Services.AddHttpContextAccessor();
        builder.Services.AddRazorPages();
        
        builder.Services.AddIdentityServer(options =>
            {
                // https://docs.duendesoftware.com/identityserver/v6/fundamentals/resources/api_scopes#authorization-based-on-scopes
                options.EmitStaticAudienceClaim = true;
                options.InputLengthRestrictions.Scope =
                    7000; //TODO: Very large!  Again I need to solve the policy/community/certification concept
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
            .AddUdapServerAsIdentityProvider(
                options =>
                    {
                        var udapServerOptions = builder.Configuration.GetOption<ServerSettings>("ServerSettings");
                        options.DefaultSystemScopes = udapServerOptions.DefaultSystemScopes;
                        options.DefaultUserScopes = udapServerOptions.DefaultUserScopes;
                        options.ServerSupport = udapServerOptions.ServerSupport;
                        options.ForceStateParamOnAuthorizationCode = udapServerOptions.ForceStateParamOnAuthorizationCode;
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
        // Add Metadata Server
        // Special IPrivateCertificateStore for Google Cloud Deploy
        // 
        //
        // builder.Services.Configure<UdapFileCertStoreManifest>(GetUdapFileCertStoreManifest(builder));
        builder.Services.Configure<UdapFileCertStoreManifest>(builder.Configuration.GetSection(Common.Constants.UDAP_FILE_STORE_MANIFEST));
        builder.Services.AddSingleton<IPrivateCertificateStore>(sp =>
            new IssuedCertificateStore(
                sp.GetRequiredService<IOptionsMonitor<UdapFileCertStoreManifest>>(),
                sp.GetRequiredService<ILogger<IssuedCertificateStore>>(),
                "FhirLabsApi"));

        builder.Services.AddUdapMetadataServer(builder.Configuration);


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
                ctx.Request.Scheme = ctx.Request.Headers[ForwardedHeadersDefaults.XForwardedProtoHeaderName];

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


    // static IConfigurationSection GetUdapFileCertStoreManifest(WebApplicationBuilder webApplicationBuilder)
    // {
    //     //Ugly but works so far.
    //     if (Environment.GetEnvironmentVariable("GCLOUD_PROJECT") != null)
    //     {
    //         Log.Logger.Information("Creating client");
    //         var client = SecretManagerServiceClient.Create();
    //
    //         var secretResource = "projects/288013792534/secrets/UdapFileCertStoreManifest/versions/latest";
    //
    //         Log.Logger.Information("Requesting {secretResource");
    //         // Call the API.
    //         var result = client.AccessSecretVersion(secretResource);
    //
    //         // Convert the payload to a string. Payloads are bytes by default.
    //         var stream = new MemoryStream(result.Payload.Data.ToByteArray());
    //
    //
    //         webApplicationBuilder.Configuration.AddJsonStream(stream);
    //     }
    //
    //     return webApplicationBuilder.Configuration.GetSection(Common.Constants.UDAP_FILE_STORE_MANIFEST);
    // }
}