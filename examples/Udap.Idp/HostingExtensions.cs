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
using Duende.IdentityServer.Validation;
using Google.Cloud.SecretManager.V1;
using Microsoft.AspNetCore.HttpLogging;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Primitives;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using Serilog;
using Udap.Server.Configuration;
using Udap.Server.Configuration.DependencyInjection;
using Udap.Server.Extensions;
using Udap.Server.Configuration.DependencyInjection.BuilderExtensions;
using Udap.Server.Registration;
using Udap.Server.Services;
using Udap.Server.Services.Default;
using Udap.Server.Validation.Default;

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

        string dbChoice;
        string connectionString;

        dbChoice = Environment.GetEnvironmentVariable("GCPDeploy") == "true" ? "gcp_db" : "DefaultConnection";


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

            var secretResource = "projects/288013792534/secrets/gcp_db/versions/latest";

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

        var settings = builder.Configuration.GetOption<ServerSettings>("ServerSettings");

        Log.Logger.Information($"ConnectionString:: {connectionString}");
        // needed to load configuration from appsettings.json
        builder.Services.AddOptions();

        // needed to store rate limit counters and ip rules
        builder.Services.AddMemoryCache();

        //load general configuration from appsettings.json
        builder.Services.Configure<IpRateLimitOptions>(builder.Configuration.GetSection("IpRateLimiting"));
        
        // inject counter and rules stores
        builder.Services.AddInMemoryRateLimiting();

        builder.Services.AddHttpContextAccessor();

        // uncomment if you want to add a UI
        builder.Services.AddRazorPages();

        var migrationsAssembly = typeof(Program).Assembly.GetName().Name;
        builder.Services.AddIdentityServer(options =>
            {
                // https://docs.duendesoftware.com/identityserver/v6/fundamentals/resources/api_scopes#authorization-based-on-scopes
                options.EmitStaticAudienceClaim = true;

                options.InputLengthRestrictions.Scope = 7000;  //TODO: Very large!  Again I need to solve the policy/community/certification concept
            })
            .AddConfigurationStore(options =>
                _ = provider switch
                {
                    "Sqlite" => options.ConfigureDbContext = b =>
                        b.UseSqlite(connectionString, dbOpts => dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName)),

                    "SqlServer" => options.ConfigureDbContext = b =>
                        b.UseSqlServer(connectionString, dbOpts => dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName)),

                    _ => throw new Exception($"Unsupported provider: {provider}")
                })
            .AddOperationalStore(options =>
                _ = provider switch
                {
                    "Sqlite" => options.ConfigureDbContext = b =>
                        b.UseSqlite(connectionString, dbOpts => dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName)),

                    "SqlServer" => options.ConfigureDbContext = b =>
                        b.UseSqlServer(connectionString, dbOpts => dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName)),

                    _ => throw new Exception($"Unsupported provider: {provider}")
                })
            // .AddInMemoryIdentityResources(Config.IdentityResources)
            // .AddInMemoryApiScopes(Config.ApiScopes)
            // .AddInMemoryClients(Config.Clients)

            .AddResourceStore<ResourceStore>()
            .AddClientStore<ClientStore>()
            .AddUdapJwtBearerClientAuthentication()
            // .AddJwtBearerClientAuthentication()
            //TODO remove
            .AddTestUsers(TestUsers.Users)
            .AddUdapDiscovery()
            .AddUdapServerConfiguration()
            .AddUdapConfigurationStore(options =>
            _ = provider switch
            {
                "Sqlite" => options.UdapDbContext = b =>
                    b.UseSqlite(connectionString, dbOpts => dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName)),

                "SqlServer" => options.UdapDbContext = b =>
                b.UseSqlServer(connectionString, dbOpts => dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName)),

                _ => throw new Exception($"Unsupported provider: {provider}")
            });

        builder.AddUdapServerSettings();

        // TODO
        // Override default ClientSecretValidator.  Not the ideal solution.  But I will need to spend some time creating PRs to Duende to allow Udap validation 
        // to work with the standard api.  It is close but not quite there.  I had to add a IScopeService to the validator to give me a way to pick up scopes
        // from the saved scopes in the ClientScopes table.  They are resolved and inserted into the HttpContext.Request.  
        //
        builder.Services.AddTransient<IClientSecretValidator, UdapClientSecretValidator>();
        builder.Services.AddSingleton<IScopeService, DefaultScopeService>();
        








        // builder.Services.AddAuthentication()









        // configuration (resolvers, counter key builders)
        builder.Services.AddSingleton<IRateLimitConfiguration, RateLimitConfiguration>();

        // builder.Services.AddTransient<IClientSecretValidator, AlwaysPassClientValidator>();


        builder.Services.AddOpenTelemetryTracing(builder =>
        {
            builder
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

        builder.Services.AddHttpLogging(options =>
        {
            options.LoggingFields = HttpLoggingFields.All;
        });

        return builder.Build();
    }
    
    public static WebApplication ConfigurePipeline(this WebApplication app, string[] args)
    {
        app.UseHttpLogging();

        if (!args.Any(a => a.Contains("skipRateLimiting")))
        {
            app.UseIpRateLimiting();
        }

        if (!app.Environment.IsDevelopment())
        {
            app.UseForwardedHeaders();
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

        app.MapPost("/connect/register", 
                async (
                    HttpContext httpContext, 
                    [FromServices] UdapDynamicClientRegistrationEndpoint endpoint, 
                    CancellationToken token) =>
        {
            //TODO:  Tests and response codes needed...    httpContext.Response
            await endpoint.Process(httpContext, token);
        })
        .AllowAnonymous()
        .Produces(StatusCodes.Status201Created)
        .Produces(StatusCodes.Status401Unauthorized);

        // uncomment if you want to add a UI
        app.UseAuthorization();
        app.MapRazorPages().RequireAuthorization();

        return app;
    }
}