﻿/*
 Copyright (c) Joseph Shook. All rights reserved.
 Authors:
    Joseph Shook   Joseph.Shook@Surescripts.com

 See LICENSE in the project root for license information.
*/

using Microsoft.EntityFrameworkCore;
using MudBlazor.Services;
using Polly;
using Serilog;
using Udap.Auth.Server.Admin.Services;
using Udap.Auth.Server.Admin.Services.DataBase;
using Udap.Auth.Server.Admin.Services.State;
using Udap.Server.DbContexts;
using Udap.Server.Entities;
using ILogger = Serilog.ILogger;

namespace Udap.Auth.Server.Admin;

public static class HostingExtensions
{
    public static WebApplication ConfigureServices(this WebApplicationBuilder builder)
    {
        string dbChoice;

        dbChoice = Environment.GetEnvironmentVariable("GCPDeploy") == "true" ? "gcp_db" : "DefaultConnection";

        var connectionString = builder.Configuration.GetConnectionString(dbChoice);

        // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen();

        builder.Services.AddControllers();
        builder.Services.AddProblemDetails();
        builder.Services.AddAutoMapper(typeof(Program));
        builder.Services.AddRazorPages();
        builder.Services.AddServerSideBlazor();
        
        builder.Services.AddUdapDbContext<UdapDbContext>(options =>
        {
            // options.UdapDbContext = b => b.UseSqlite(connectionString)
            //     .LogTo(Console.WriteLine, LogLevel.Information);

            // options.UdapDbContext = b => b.UseSqlServer(connectionString)
            //     .LogTo(Console.WriteLine, LogLevel.Information);

            options.UdapDbContext = b => b.UseNpgsql(connectionString)
                .LogTo(Console.WriteLine, LogLevel.Information);
        });

        builder.Services.AddScoped<ICommunityService, CommunityService>();
        builder.Services.AddScoped<IAnchorService, AnchorService>();
        builder.Services.AddScoped<IIntermediateCertificateService, IntermediateCertificateService>();
        builder.Services.AddScoped<IUdapAdminCommunityValidator, UdapAdminCommunityValidator>();
        builder.Services.AddScoped<IUdapCertificateValidator<Anchor>, UdapAdminAnchorValidator>();
        builder.Services.AddScoped<IUdapCertificateValidator<Intermediate>, UdapAdminRootCertificateValidator>();

        var httpClientBuilder = builder.Services.AddHttpClient<ApiService>(client =>
        {
            bool isInDockerContainer = (Environment.GetEnvironmentVariable("DOTNET_RUNNING_IN_CONTAINER") == "true");

            if (isInDockerContainer)
            {
                client.BaseAddress = new Uri("http://localhost:8080");
            }
            else
            {
                client.BaseAddress = new Uri(Environment.GetEnvironmentVariable("ASPNETCORE_URLS")?.Split(';').FirstOrDefault() ?? string.Empty);
            } 
        });

        if (! builder.Environment.IsDevelopment())
        {
            httpClientBuilder.AddTransientHttpErrorPolicy(builder => builder.WaitAndRetryAsync(new[]
            {
                TimeSpan.FromSeconds(1),
                TimeSpan.FromSeconds(5)
            }));
        }
        

        builder.Services.AddMudServices();
        builder.Services.AddSingleton<CommunityState>();
        
        return builder.Build();
    }

    public static WebApplication ConfigurePipeline(this WebApplication app)
    {
        app.UseSerilogRequestLogging();

        if (!app.Environment.IsDevelopment())
        {
            app.UseExceptionHandler("/Error");
            // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
            app.UseHsts();
        }

        // app.UseWhen(context => context.Request.Path.StartsWithSegments("/api"), applicationBuilder =>
        // {
            app.UseExceptionHandler();
            app.UseStatusCodePages();
        // });
        
        if (app.Environment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
            app.UseSwagger();
            app.UseSwaggerUI(c =>
            {
                c.SwaggerEndpoint("v1/swagger.json", "Udap.Idp.Admin v1");
            });
        }
        
        app.UseHttpsRedirection();
        app.UseStaticFiles();
        app.UseRouting();
        app.MapBlazorHub();
        app.MapFallbackToPage("/_Host");

        app.MapControllers();  //Needed for WebApi controller attribute routing.
        
        return app;
    }

    public static bool PrepDataBase(this WebApplicationBuilder builder, string[] args, ILogger logger)
    {
        if (args.Contains("/seed"))
        {
            var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
            Log.Information("Seeding database...");
            SeedData.EnsureSeedData(connectionString, args[1], logger);
            Log.Information("Done seeding database.");

            return true;
        }
        
        return false;
    }
}
