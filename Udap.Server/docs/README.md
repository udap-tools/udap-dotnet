# Udap.Server

![UDAP logo](https://avatars.githubusercontent.com/u/77421324?s=48&v=4)

## 📦 Nuget Package: [Udap.Server](https://www.nuget.org/packages?q=udap.server)

This package is intended to be used with Duende's Identity Server.  Duende must be licensed if you are using it for anything more than testing and you make more than 1 million dollars a year.  I am willing to build samples using other identity providers.  Keep in mind `Udap.Server` is meant to add auto registration only.  Then it relies on Identity Server for identity rather than build a complete identity provider server.  There is great value Duende provides that would take a very long time to get correct.

This package contains a few extension methods and two endpoints.  The first endpoint is an UDAP metadata endpoint, implementing Duende's IEndpointHandler interface allowing /.well-known/udap to render metadata.  The items of interest in the metadata is the registration_endpoint which points to the next endpoint; `UdapDynamicClientRegistrationEndpoint`.  This code is a simple endpoint called as a delegate using the dotnet minimal api technique.  All of this is configured by adding the ```AddUdapServer()``` extension method to the Identity Server pipeline.

**Assumptions:**  An Identity Sever exists is backed by a relational database.  Use [Udap.Auth.Server](./../examples/Udap.Auth.Server/) as an example.  I may revisit this in the future and build an in memory version but this reference implementation. For now it assumes a relational database is deployed.

## Full Example

Below is a full example.  Alternatively the [2023 FHIR® DevDays Tutorial](udap-devdays-2023) is another great way to learn how to use ```Udap.Server```.

```csharp

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddIdentityServer()
    .AddConfigurationStore(options =>
    {
        options.ConfigureDbContext = b => b.UseSqlite(connectionString,
            dbOpts => dbOpts.MigrationsAssembly(migrationsAssembly));
    })
    .AddOperationalStore(options =>
    {
        options.ConfigureDbContext = b => b.UseSqlite(connectionString,
            dbOpts => dbOpts.MigrationsAssembly(migrationsAssembly));

    })
    .AddResourceStore<ResourceStore>()
    .AddClientStore<ClientStore>()
    .AddTestUsers(TestUsers.Users)
    .AddUdapServer(
        options =>
        {
            var udapServerOptions = builder.Configuration.GetOption<ServerSettings>("ServerSettings");
            options.DefaultSystemScopes = udapServerOptions.DefaultSystemScopes;
            options.DefaultUserScopes = udapServerOptions.DefaultUserScopes;
            options.ServerSupport = udapServerOptions.ServerSupport;
            options.ForceStateParamOnAuthorizationCode = udapServerOptions.
                ForceStateParamOnAuthorizationCode;
        },
        options =>
            options.UdapDbContext = b =>
                b.UseSqlite(connectionString,
                    dbOpts =>
                        dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName)),
        baseUrl: "https://localhost:5002/connect/register"
    );

  var app = builder.Build();

  // uncomment if you want to add a UI
  app.UseStaticFiles();
  app.UseRouting();

  app.UseUdapServer();
  app.UseIdentityServer();

  // uncomment if you want to add a UI
  app.UseAuthorization();
  app.MapRazorPages().RequireAuthorization();

  app.Run;

```

## Udap.Auth.Server Database Configuration

For your convenience a EF Migrations Project called [UdapDb.SqlServer](/migrations/UdapDb.SqlServer/) can deploy the database schema.  Run from Visual Studio using the UdapDb profile (/properties/launchSettings.json).  This project will create all the Udap tables and Duende Identity tables.  It will seed data needed for running local system tests.  See the SeedData.cs for details.

If you need another database such as PostgreSQL I could be motivated to create one.

Not the [UdapDb.SqlServer](/migrations/UdapDb.SqlServer/) project includes two migrations for Duende's Identity Server tables.  I have not put anytime into migrating a schema.  At this point my pattern is to just delete the database and re-create it.  At some point I will version this and start migrating officially.

## UDAP Authorization Server Examples

- [Udap.Auth.Server](./../examples/Udap.Auth.Server/)
- [Udap.Auth.Server Deployed](https://securedcontrols.net/.well-known/udap)

- FHIR® is the registered trademark of HL7 and is used with the permission of HL7. Use of the FHIR trademark does not constitute endorsement of the contents of this repository by HL7.
- UDAP® and the UDAP gear logo, ecosystem gears, and green lock designs are trademarks of UDAP.org. UDAP Draft Specifications are referenced and displayed in parts of this source code to document specification implementation.
