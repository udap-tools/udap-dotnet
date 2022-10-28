using Microsoft.EntityFrameworkCore;
using Udap.Server.Extensions;
using Udap.Server.Options;
using UdapDb;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

var connectionString = builder.Configuration.GetConnectionString("db");
builder.Services.AddSingleton(new UdapConfigurationStoreOptions());

builder.Services.AddUdapDbContext(options =>
    {
        options.UdapDbContext = b =>
            b.UseSqlite(connectionString, dbOpts => dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName));
    });

var app = builder.Build();

SeedData.EnsureSeedData(app.Services);

// Configure the HTTP request pipeline.


app.Run();