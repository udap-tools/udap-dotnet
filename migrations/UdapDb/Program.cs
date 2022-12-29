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
using Udap.Server.Extensions;
using Udap.Server.Options;
using UdapDb;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateBootstrapLogger();

Log.Information("Starting up");

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

string dbChoice;

dbChoice = Environment.GetEnvironmentVariable("GCPDeploy") == "true" ? "gcp_db" : "db";

var connectionString = builder.Configuration.GetConnectionString(dbChoice);

builder.Services.AddSingleton(new UdapConfigurationStoreOptions());

//
// TODO: work on multiple provider later:
// https://learn.microsoft.com/en-us/ef/core/managing-schemas/migrations/providers?tabs=dotnet-core-cli
//
builder.Services.AddUdapDbContext(options =>
    {
        // options.UdapDbContext = b =>
        //     b.UseSqlite(connectionString, dbOpts => dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName));
        options.UdapDbContext = b =>
            b.UseSqlServer(connectionString, dbOpts => dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName));
    });

var app = builder.Build();

await SeedData.EnsureSeedData(
    connectionString,
    "../../../../../_tests/Udap.PKI.Generator/certstores",
    Log.Logger);

// Configure the HTTP request pipeline.

return 0;

app.Run();


namespace UdapDb
{
    public partial class Program { }
}