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

var connectionString = builder.Configuration.GetConnectionString("db");
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

SeedData.EnsureSeedData(
    connectionString,
    "../../../../../_tests/Udap.PKI.Generator/certstores",
    Log.Logger);

// Configure the HTTP request pipeline.


app.Run();


namespace UdapDb
{
    public partial class Program { }
}