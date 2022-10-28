/*
 Copyright (c) Joseph Shook. All rights reserved.
 Authors:
    Joseph Shook   Joseph.Shook@Surescripts.com

 See LICENSE in the project root for license information.
*/


using Duende.IdentityServer.EntityFramework.DbContexts;
using Duende.IdentityServer.EntityFramework.Storage;
using Microsoft.EntityFrameworkCore;
using Udap.Server;
using Udap.Server.DbContexts;
using Udap.Server.Entitiies;
using Udap.Server.Extensions;
using Udap.Server.Registration;
using ILogger = Serilog.ILogger;

namespace Udap.Idp.Admin;

public static class SeedData
{
    public static void EnsureSeedData(string connectionString, ILogger logger)
    {
        var services = new ServiceCollection();

        services.AddOperationalDbContext(options =>
        {
            options.ConfigureDbContext = db => db.UseSqlite(connectionString,
                sql => sql.MigrationsAssembly(typeof(SeedData).Assembly.FullName));
        });
        services.AddConfigurationDbContext(options =>
        {
            options.ConfigureDbContext = db => db.UseSqlite(connectionString,
                sql => sql.MigrationsAssembly(typeof(SeedData).Assembly.FullName));
        });

        services.AddScoped<IUdapClientRegistrationStore, UdapClientRegistrationStore>();
        services.AddUdapDbContext(options =>
        {
            options.UdapDbContext = db => db.UseSqlite(connectionString,
                sql => sql.MigrationsAssembly(typeof(UdapDiscoveryEndpoint).Assembly.FullName));
        });

        using var serviceProvider = services.BuildServiceProvider();
        using var scope = serviceProvider.GetRequiredService<IServiceScopeFactory>().CreateScope();

        scope.ServiceProvider.GetService<PersistedGrantDbContext>()?.Database.Migrate();
        scope.ServiceProvider.GetService<ConfigurationDbContext>()?.Database.Migrate();

        var udapContext = scope.ServiceProvider.GetService<UdapDbContext>();
        udapContext.Database.Migrate();

        var clientRegistrationStore = scope.ServiceProvider.GetRequiredService<IUdapClientRegistrationStore>();


        if (!udapContext.Communities.Any(c => c.Name == "http://localhost"))
        {
            var community = new Community { Name = "http://localhost" };
            community.Enabled = true;
            community.Default = false;
            udapContext.Communities.Add(community);
            udapContext.SaveChanges();
        }

        if (!udapContext.Communities.Any(c => c.Name == "udap://surefhir.labs"))
        {
            var community = new Community { Name = "udap://surefhir.labs" };
            community.Enabled = true;
            community.Default = true;
            udapContext.Communities.Add(community);
            udapContext.SaveChanges();
        }

        // var assemblyPath = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);

        // if (!clientRegistrationStore.GetAnchors("http://localhost").Result.Any())
        // {
        //     var anchorLocalhostCert = new X509Certificate2(
        //         Path.Combine(assemblyPath, "TestCerts/anchorLocalhostCert.cer"));
        //
        //     var commnity = udapContext.Communities.Single(c => c.Name == "http://localhost");
        //
        //     udapContext.Anchors.Add(new Anchor
        //     {
        //         BeginDate = anchorLocalhostCert.NotBefore,
        //         EndDate = anchorLocalhostCert.NotAfter,
        //         Name = anchorLocalhostCert.Subject,
        //         Community = commnity,
        //         X509Certificate = anchorLocalhostCert.ToPemFormat(),
        //         Thumbprint = anchorLocalhostCert.Thumbprint,
        //         Enabled = true
        //     });
        //
        //     udapContext.SaveChanges();
        // }
        //
        //
        // if (!clientRegistrationStore.GetAnchors("udap://surefhir.labs").Result.Any())
        // {
        //     var SureFhirLabs_Anchor = new X509Certificate2(
        //         Path.Combine(assemblyPath, "./TestCerts/SureFhirLabs_Anchor.cer"));
        //
        //     var commnity = udapContext.Communities.Single(c => c.Name == "udap://surefhir.labs");
        //
        //     udapContext.Anchors.Add(new Anchor
        //     {
        //         BeginDate = SureFhirLabs_Anchor.NotBefore,
        //         EndDate = SureFhirLabs_Anchor.NotAfter,
        //         Name = SureFhirLabs_Anchor.Subject,
        //         Community = commnity,
        //         X509Certificate = SureFhirLabs_Anchor.ToPemFormat(),
        //         Thumbprint = SureFhirLabs_Anchor.Thumbprint,
        //         Enabled = true
        //     });
        //
        //     udapContext.SaveChanges();
        // }
    }
}
