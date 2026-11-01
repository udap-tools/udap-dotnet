#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

// Runs the UDAP example servers locally, each on its own *.dev.localhost name (see README.md).
// Browsers, curl and .NET resolve *.localhost to loopback, and the ASP.NET dev cert covers *.dev.localhost,
// so there is no hosts file to edit and no certificate to generate for HTTPS.

using Microsoft.Extensions.Configuration;
using Udap.AppHost;

var builder = DistributedApplication.CreateBuilder(args);

// ── PostgreSQL and pgAdmin ──────────────────────────────────────────────────
// Persistent containers, identified by name. The names come from configuration (appsettings.json, overridden
// in user secrets), so this AppHost can share a Postgres and pgAdmin you already run for other projects:
// Aspire reuses a container whose name and spec match instead of creating a new one. See README.md.
var postgresConfig = builder.Configuration.GetSection("Postgres");
var pgAdminConfig = builder.Configuration.GetSection("PgAdmin");

// The password parameter is generated on first run and saved to this AppHost's user secrets
// (Parameters:postgres-password). To share an existing container, set it to that container's password.
var postgres = builder.AddPostgres("postgres")
    .WithImageTag(postgresConfig["ImageTag"] ?? "17.6")
    .WithContainerName(postgresConfig["ContainerName"] ?? "udap-postgres")
    .WithDataVolume(postgresConfig["DataVolume"] ?? "udap-postgres-data")
    .WithLifetime(ContainerLifetime.Persistent);

if (pgAdminConfig.GetValue("Enabled", true))
{
    builder.AddSharedPgAdmin(pgAdminConfig, postgres);
}

var authDb = postgres.AddDatabase("udap-auth-db", databaseName: "Udap.Auth.db");
var idp1Db = postgres.AddDatabase("udap-idp1-db", databaseName: "Udap.Identity.Provider.db");
var idp2Db = postgres.AddDatabase("udap-idp2-db", databaseName: "Udap.Identity.Provider2.db");

// ── Migrations and seed data ────────────────────────────────────────────────
// migrations/UdapDb.Postgres applies the schema and seeds the clients, communities and trust anchors (from
// _tests/Udap.PKI.Generator/certstores), then exits. Each server waits for its seeder to complete.
var authSeed = builder.AddUdapDbSeeder("udap-auth-db-seed", "Local_Auth_Migrate", authDb, "DefaultConnection");
var idp1Seed = builder.AddUdapDbSeeder("udap-idp1-db-seed", "Local_Idp1_Migrate", idp1Db, "db_identity_provider");
var idp2Seed = builder.AddUdapDbSeeder("udap-idp2-db-seed", "Local_Idp2_Migrate", idp2Db, "db_identity_provider2");

// ── Servers ─────────────────────────────────────────────────────────────────
// Each binds the applicationUrl of the named launch profile, so the ports and names here match a plain
// `dotnet run` of the same project.

// Serves the CRLs and intermediate certificates the local test certificates point at (CDP and AIA).
var certServer = builder.AddProject<Projects.Udap_Certificates_Server>("udap-cert-server", "udap.certificates.server.devdays")
    .WithDevHost("udap-cert-server.dev.localhost");

var authServer = builder.AddProject<Projects.Udap_Auth_Server>("udap-auth-server", "Localhost")
    .WithDevHost("udap-auth-server.dev.localhost")
    .WithReference(authDb, "DefaultConnection")
    .WaitForCompletion(authSeed)
    .WaitFor(certServer);

builder.AddProject<Projects.Udap_Identity_Provider>("udap-idp1", "Localhost")
    .WithDevHost("udap-idp1.dev.localhost")
    .WithReference(idp1Db, "DefaultConnection")
    .WaitForCompletion(idp1Seed)
    .WaitFor(certServer);

builder.AddProject<Projects.Udap_Identity_Provider__2>("udap-idp2", "Localhost")
    .WithDevHost("udap-idp2.dev.localhost")
    .WithReference(idp2Db, "DefaultConnection")
    .WaitForCompletion(idp2Seed)
    .WaitFor(certServer);

builder.AddProject<Projects.FhirLabsApi>("udap-fhirlabs-api", "FhirLabsApi_Localhost")
    .WithDevHost("udap-fhirlabs-api.dev.localhost")
    .WaitFor(authServer);

// Started from the dashboard when needed. The proxies front backends that are not part of this AppHost
// (see each project's appsettings), and the admin UI is only needed to edit the auth server's data.
// Its Google login is kept apart from the machine's usual gcloud login: see WithSeparateGcloudLogin.
builder.AddProject<Projects.Udap_Proxy_Server>("udap-proxy", "https")
    .WithDevHost("udap-proxy.dev.localhost")
    .WithSeparateGcloudLogin(builder.Configuration.GetSection("UdapProxy"))
    .WithExplicitStart();

builder.AddProject<Projects.Tefca_Proxy_Server>("udap-tefca-proxy", "https")
    .WithDevHost("udap-tefca-proxy.dev.localhost")
    .WithExplicitStart();

builder.AddProject<Projects.mTLS_Proxy_Server>("udap-mtls-proxy", "https")
    .WithDevHost("udap-mtls-proxy.dev.localhost")
    .WithExplicitStart();

builder.AddProject<Projects.Udap_Auth_Server_Admin>("udap-auth-admin", "Udap.Idp.Admin")
    .WithDevHost("udap-auth-admin.dev.localhost")
    .WithReference(authDb, "DefaultConnection")
    .WaitForCompletion(authSeed)
    .WithExplicitStart();

// ── UdapEd ──────────────────────────────────────────────────────────────────
// The UDAP test client (https://github.com/JoeShook/UdapEd), from its published container image, for
// discovery, registration, tokens and Tiered OAuth against the servers above.
var udapEdConfig = builder.Configuration.GetSection("UdapEd");
if (udapEdConfig.GetValue("Enabled", true))
{
    builder.AddUdapEd(udapEdConfig)
        .WaitFor(authServer);
}

builder.Build().Run();
