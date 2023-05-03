# Udap.Server

![UDAP logo](https://avatars.githubusercontent.com/u/77421324?s=48&v=4)

## 📦 This package

This package is intended to be used with Duende's Identity Server.  Duende must be licensed if you are using it for anything more than testing and you make more than 1 million dollars a year.  I am willing to build samples using other identity providers.  Keep in mind `Udap.Server` is meant to add auto registration only.  Then it relies on Identity Server for identity rather than build a complete identity provider server.  There is great value Duende provides that would take a very long time to get correct.  

This package contains a few extension methods and two endpoints.  The first endpoint is an UDAP metadata endpoint, implementing Duende's IEndpointHandler interface allowing /.well-known/udap to render metadata.  The only thing of interest in this endpoint is the registration_endpoint which points to the next endpoint, `UdapDynamicClientRegistrationEndpoint`.  This code is a simple endpoint called as a delegate using the dotnet minimal api technique.  

Program.cs could look like this.

**TODO**
Work to do here to demonstrate how to use.

- Update readme
- Instructions on creating database.  `dotnet run /seed` from Udap.Idp.Admin
- Need to finish loading root CAs into database
- Add and test other DBs like SQL, PostgreSql and CockroachDB.  Maybe Windows Store? :smirk:

```csharp

using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Serilog;
using Udap.Server;
using Udap.Server.Extensions;
using Udap.Server.Registration;

namespace Udap.Idp;

internal static class HostingExtensions
{
    public static WebApplication ConfigureServices(this WebApplicationBuilder builder)
    {
        if (! int.TryParse(Environment.GetEnvironmentVariable("ASPNETCORE_HTTPS_PORT"), out int sslPort))
        {
            sslPort = 5002;
        }

        var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

        // uncomment if you want to add a UI
        builder.Services.AddRazorPages();

        var migrationsAssembly = typeof(Program).Assembly.GetName().Name;
        builder.Services.AddIdentityServer(options =>
            {
                // https://docs.duendesoftware.com/identityserver/v6/fundamentals/resources/api_scopes#authorization-based-on-scopes
                options.EmitStaticAudienceClaim = true;
            })
            .AddConfigurationStore(options =>
            {
                options.ConfigureDbContext = b => b.UseSqlite(connectionString,
                    sql => sql.MigrationsAssembly(migrationsAssembly));
            })
            .AddOperationalStore(options =>
            {
                options.ConfigureDbContext = b => b.UseSqlite(connectionString,
                    sql => sql.MigrationsAssembly(migrationsAssembly));
            })
            .AddInMemoryIdentityResources(Config.IdentityResources)
            .AddInMemoryApiScopes(Config.ApiScopes)
            .AddInMemoryClients(Config.Clients)
            //TODO remove
            .AddTestUsers(TestUsers.Users)
            .AddUdapDiscovery()
            .AddUdapServerConfiguration()
            .AddUdapConfigurationStore(options =>
            {
                options.UdapDbContext = b => b.UseSqlite(connectionString,
                    sql => sql.MigrationsAssembly(typeof(UdapDiscoveryEndpoint).Assembly.FullName));
            });

        return builder.Build();
    }
    
    public static WebApplication ConfigurePipeline(this WebApplication app)
    { 
        app.UseSerilogRequestLogging();
    
        if (app.Environment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }

        // uncomment if you want to add a UI
        app.UseStaticFiles();
        app.UseRouting();
            
        app.UseIdentityServer();

        app.MapPost("/connect/register",
        async (
            HttpContext httpContext,
            [FromServices] UdapDynamicClientRegistrationEndpoint endpoint,
            CancellationToken token) =>
        {
            await endpoint.Process(httpContext, token);
        })
        .AllowAnonymous()
        .Produces(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status204NoContent)
        .Produces(StatusCodes.Status400BadRequest);

 

        // uncomment if you want to add a UI
        app.UseAuthorization();
        app.MapRazorPages().RequireAuthorization();

        return app;
    }
}


```
