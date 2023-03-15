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

string dbChoice;

dbChoice = Environment.GetEnvironmentVariable("GCPDeploy") == "true" ? "gcp_db" : "db";

var connectionString = builder.Configuration.GetConnectionString(dbChoice);

builder.Services.AddSingleton(new UdapConfigurationStoreOptions());

builder.Services.AddUdapDbContext(options =>
{
    options.UdapDbContext = db => db.UseSqlServer(connectionString,
        sql => sql.MigrationsAssembly(typeof(Program).Assembly.FullName));
});

var app = builder.Build();

await SeedData.EnsureSeedData(
    connectionString,
    "../../../../../_tests/Udap.PKI.Generator/certstores",
    Log.Logger);

// Configure the HTTP request pipeline.

await app.RunAsync(new CancellationTokenSource(500).Token);


namespace UdapDb
{
    public partial class Program { }
}