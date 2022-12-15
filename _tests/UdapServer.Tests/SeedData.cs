#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using Duende.IdentityServer.EntityFramework.DbContexts;
using Duende.IdentityServer.EntityFramework.Storage;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Serilog;
using Udap.Common.Extensions;
using Udap.Idp;
using Udap.Server;
using Udap.Server.DbContexts;
using Udap.Server.Entities;
using Udap.Server.Extensions;
using Udap.Server.Registration;

namespace UdapServer.Tests;

public static class SeedData
{
    public static void EnsureSeedData(string connectionString, ILogger logger)
    {
        var services = new ServiceCollection();

        services.AddLogging();
        // services.AddDbContext<ApplicationDbContext>(options =>
        //     options.UseSqlite(connectionString, o => o.MigrationsAssembly(typeof(Program).Assembly.FullName)));
        //
        // services.AddIdentity<ApplicationUser, IdentityRole>()
        //     .AddEntityFrameworkStores<ApplicationDbContext>()
        //     .AddDefaultTokenProviders();

        services.AddOperationalDbContext(options =>
        {
            options.ConfigureDbContext = db => db.UseSqlite(connectionString,
                sql => sql.MigrationsAssembly(typeof(Program).Assembly.FullName));
        });
        services.AddConfigurationDbContext(options =>
        {
            options.ConfigureDbContext = db => db.UseSqlite(connectionString,
                sql => sql.MigrationsAssembly(typeof(Program).Assembly.FullName));
        });

        services.AddScoped<IUdapClientRegistrationStore, UdapClientRegistrationStore>();
        services.AddUdapDbContext(options =>
        {
            options.UdapDbContext = db => db.UseSqlite(connectionString,
                sql => sql.MigrationsAssembly(typeof(UdapDiscoveryEndpoint).Assembly.FullName));
        });

        using var serviceProvider = services.BuildServiceProvider();
        using var scope = serviceProvider.GetRequiredService<IServiceScopeFactory>().CreateScope();


        // var context = scope.ServiceProvider.GetService<ApplicationDbContext>();
        // context?.Database.Migrate();

        scope.ServiceProvider.GetService<PersistedGrantDbContext>()?.Database.Migrate();
        scope.ServiceProvider.GetService<ConfigurationDbContext>()?.Database.Migrate();


        var udapContext = scope.ServiceProvider.GetRequiredService<UdapDbContext>();
        udapContext.Database.Migrate();

        var clientRegistrationStore = scope.ServiceProvider.GetRequiredService<IUdapClientRegistrationStore>();


        if (!udapContext.Communities.Any(c => c.Name == "http://localhost"))
        {
            var community = new Community { Name = "http://localhost" };
            community.Enabled = true;
            community.Default = true;
            udapContext.Communities.Add(community);
            udapContext.SaveChanges();
        }

        if (!udapContext.Communities.Any(c => c.Name == "udap://surefhir.labs"))
        {
            var community = new Community { Name = "udap://surefhir.labs" };
            community.Enabled = true;
            udapContext.Communities.Add(community);
            udapContext.SaveChanges();
        }

        var assemblyPath = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);

        var x509Certificate2Collection = clientRegistrationStore.GetRootCertificates().Result;
        if (x509Certificate2Collection != null && !x509Certificate2Collection.Any())
        {
            var rootCert = new X509Certificate2(
                Path.Combine(assemblyPath!, "CertStore/roots/caLocalhostCert.cer"));

            udapContext.RootCertificates.Add(new RootCertificate
            {
                BeginDate = rootCert.NotBefore,
                EndDate = rootCert.NotAfter,
                Name = rootCert.Subject,
                X509Certificate = rootCert.ToPemFormat(),
                Thumbprint = rootCert.Thumbprint,
                Enabled = true
            });

            udapContext.SaveChanges();
        }

        if (!clientRegistrationStore.GetAnchors("http://localhost").Result.Any())
        {
            var anchorLocalhostCert = new X509Certificate2(
                Path.Combine(assemblyPath!, "CertStore/anchors/anchorLocalhostCert.cer"));

            var commnity = udapContext.Communities.Single(c => c.Name == "http://localhost");

            udapContext.Anchors.Add(new Anchor
            {
                BeginDate = anchorLocalhostCert.NotBefore,
                EndDate = anchorLocalhostCert.NotAfter,
                Name = anchorLocalhostCert.Subject,
                Community = commnity,
                X509Certificate = anchorLocalhostCert.ToPemFormat(),
                Thumbprint = anchorLocalhostCert.Thumbprint,
                Enabled = true
            });

            udapContext.SaveChanges();
        }


        if (!clientRegistrationStore.GetAnchors("udap://surefhir.labs").Result.Any())
        {
            var SureFhirLabs_Anchor = new X509Certificate2(
                Path.Combine(assemblyPath!, "./CertStore/anchors/SureFhirLabs_Anchor.cer"));

            var commnity = udapContext.Communities.Single(c => c.Name == "udap://surefhir.labs");

            udapContext.Anchors.Add(new Anchor
            {
                BeginDate = SureFhirLabs_Anchor.NotBefore,
                EndDate = SureFhirLabs_Anchor.NotAfter,
                Name = SureFhirLabs_Anchor.Subject,
                Community = commnity,
                X509Certificate = SureFhirLabs_Anchor.ToPemFormat(),
                Thumbprint = SureFhirLabs_Anchor.Thumbprint,
                Enabled = true
            });

            udapContext.SaveChanges();
        }
    }
}
