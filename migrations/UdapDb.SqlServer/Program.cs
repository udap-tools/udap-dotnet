#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.EntityFrameworkCore;
using Serilog;
using Udap.Server.Options;
using UdapDb;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateBootstrapLogger();

Log.Information("Starting up");

var builder = WebApplication.CreateBuilder(args);
// Log.Logger.Information(string.Join(',', args));
// Add services to the container.


var connStrName = Environment.GetEnvironmentVariable("ConnStrName");
var connectionString = builder.Configuration.GetConnectionString(connStrName);

builder.Services.AddSingleton(new UdapConfigurationStoreOptions());

builder.Services.AddUdapDbContext(options =>
{
    options.UdapDbContext = db => db.UseSqlServer(connStrName,
        sql => sql.MigrationsAssembly(typeof(Program).Assembly.FullName));
});

var app = builder.Build();

if (connStrName.Equals("db_identity_provider", StringComparison.OrdinalIgnoreCase))
{
    await SeedDataIdentityProvider.EnsureSeedData(
        connectionString,
        "../../../../../_tests/Udap.PKI.Generator/certstores",
        Log.Logger);
}
if (connStrName.Equals("db_identity_provider2", StringComparison.OrdinalIgnoreCase))
{
    await SeedDataIdentityProvider2.EnsureSeedData(
        connectionString,
        "../../../../../_tests/Udap.PKI.Generator/certstores",
        Log.Logger);
}
else if (connStrName.Equals("DefaultConnection", StringComparison.OrdinalIgnoreCase))
{
    await SeedDataAuthServer.EnsureSeedData(
        connectionString,
        "../../../../../_tests/Udap.PKI.Generator/certstores",
        Log.Logger);
}
else if (connStrName.Equals("gcp_db", StringComparison.OrdinalIgnoreCase))
{
    await Seed_GCP_Auth_Server.EnsureSeedData(
        connectionString,
        "../../../../../_tests/Udap.PKI.Generator/certstores",
        Log.Logger);
}
else if (connStrName.Equals("gcp_db_Idp1", StringComparison.OrdinalIgnoreCase))
{
    await Seed_GCP_Idp1.EnsureSeedData(
        connectionString,
        "../../../../../_tests/Udap.PKI.Generator/certstores",
        Log.Logger);
}
else if (connStrName.Equals("gcp_db_Idp2", StringComparison.OrdinalIgnoreCase))
{
    await Seed_GCP_Idp2.EnsureSeedData(
        connectionString,
        "../../../../../_tests/Udap.PKI.Generator/certstores",
        Log.Logger);
}

// Configure the HTTP request pipeline.

await app.RunAsync(new CancellationTokenSource(500).Token);


namespace UdapDb
{
    public partial class Program { }
}