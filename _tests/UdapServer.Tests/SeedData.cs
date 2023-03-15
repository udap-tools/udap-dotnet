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
using Duende.IdentityServer.EntityFramework.Mappers;
using Duende.IdentityServer.EntityFramework.Storage;
using Duende.IdentityServer.Models;
using Hl7.Fhir.Model;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Serilog;
using Udap.Idp;
using Udap.Server.DbContexts;
using Udap.Server.Entities;
using Udap.Server.Storage.Stores;
using Udap.Server.Stores;
using Udap.Util.Extensions;

namespace UdapServer.Tests;

public static class SeedData
{
    public static void EnsureSeedData(string connectionString, ILogger logger)
    {
        var services = new ServiceCollection();

        services.AddLogging();

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
                sql => sql.MigrationsAssembly(typeof(Program).Assembly.FullName));
        });

        using var serviceProvider = services.BuildServiceProvider();
        using var scope = serviceProvider.GetRequiredService<IServiceScopeFactory>().CreateScope();


        // var context = scope.ServiceProvider.GetService<ApplicationDbContext>();
        // context?.Database.Migrate();

        var udapContext = scope.ServiceProvider.GetRequiredService<UdapDbContext>();
        udapContext.Database.EnsureCreated();

        var configDbContext = scope.ServiceProvider.GetRequiredService<ConfigurationDbContext>();

        scope.ServiceProvider.GetService<PersistedGrantDbContext>()?.Database.Migrate();
        scope.ServiceProvider.GetService<ConfigurationDbContext>()?.Database.Migrate();


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


        //
        // Anchors
        //
        if (!clientRegistrationStore.GetAnchors("http://localhost").Result.Any())
        {
            var anchorLocalhostCert = new X509Certificate2(
                Path.Combine(assemblyPath!, "CertStore/intermediates/intermediateLocalhostCert.cer"));

            var commnity = udapContext.Communities.Single(c => c.Name == "http://localhost");

            var anchor = new Anchor
            {
                BeginDate = anchorLocalhostCert.NotBefore,
                EndDate = anchorLocalhostCert.NotAfter,
                Name = anchorLocalhostCert.Subject,
                Community = commnity,
                X509Certificate = anchorLocalhostCert.ToPemFormat(),
                Thumbprint = anchorLocalhostCert.Thumbprint,
                Enabled = true
            };

            udapContext.Anchors.Add(anchor);

            //
            // Intermediates
            //
            var x509Certificate2Collection = clientRegistrationStore.GetIntermediateCertificates().Result;
            if (x509Certificate2Collection != null && !x509Certificate2Collection.Any())
            {
                var rootCert = new X509Certificate2(
                    Path.Combine(assemblyPath!, "CertStore/roots/caLocalhostCert.cer"));

                udapContext.IntermediateCertificates.Add(new IntermediateCertificate
                {
                    BeginDate = rootCert.NotBefore,
                    EndDate = rootCert.NotAfter,
                    Name = rootCert.Subject,
                    X509Certificate = rootCert.ToPemFormat(),
                    Thumbprint = rootCert.Thumbprint,
                    Enabled = true,
                    Anchor = anchor
                });

                udapContext.SaveChanges();
            }

        }




        if (!clientRegistrationStore.GetAnchors("udap://surefhir.labs").Result.Any())
        {
            var SureFhirLabs_Anchor = new X509Certificate2(
                Path.Combine(assemblyPath!, "./CertStore/intermediates/SureFhirLabs_Intermediate.cer"));

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

        var seedScopes = new List<string>();

        foreach (var resName in ModelInfo.SupportedResources)
        {
            seedScopes.Add($"system/{resName}.*");
            seedScopes.Add($"system/{resName}.read");
        }

        var apiScopes = configDbContext.ApiScopes
            .Where(s => s.Enabled)
            .Select(s => s.Name)
            .ToList();

        foreach (var scopeName in seedScopes)
        {
            if (!apiScopes.Contains(scopeName))
            {
                var apiScope = new ApiScope(scopeName);
                configDbContext.ApiScopes.Add(apiScope.ToEntity());
            }
        }

        configDbContext.SaveChanges();

        if (configDbContext.ApiScopes.All(s => s.Name != "udap"))
        {
            var apiScope = new ApiScope("udap");
            configDbContext.ApiScopes.Add(apiScope.ToEntity());

            configDbContext.SaveChanges();
        }

    }
}
