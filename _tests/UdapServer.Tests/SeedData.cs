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
using Udap.Server.DbContexts;
using Udap.Server.Entities;
using Udap.Server.Storage.Stores;
using Udap.Server.Stores;
using Udap.Util.Extensions;
using Task = System.Threading.Tasks.Task;

namespace UdapServer.Tests;

public static class SeedData
{
    public static async Task EnsureSeedData(string connectionString, ILogger logger)
    {
        var services = new ServiceCollection();

        services.AddLogging();

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
                sql => sql.MigrationsAssembly(typeof(SeedData).Assembly.FullName));
        });

        await using var serviceProvider = services.BuildServiceProvider();
        using var scope = serviceProvider.GetRequiredService<IServiceScopeFactory>().CreateScope();


        // var context = scope.ServiceProvider.GetService<ApplicationDbContext>();
        // context?.Database.Migrate();

        var udapContext = scope.ServiceProvider.GetRequiredService<UdapDbContext>();
        await udapContext.Database.EnsureCreatedAsync();

        var configDbContext = scope.ServiceProvider.GetRequiredService<ConfigurationDbContext>();

        await scope.ServiceProvider.GetService<PersistedGrantDbContext>()?.Database.MigrateAsync();
        await scope.ServiceProvider.GetService<ConfigurationDbContext>()?.Database.MigrateAsync();


        var clientRegistrationStore = scope.ServiceProvider.GetRequiredService<IUdapClientRegistrationStore>();


        if (!udapContext.Communities.Any(c => c.Name == "http://localhost"))
        {
            var community = new Community { Name = "http://localhost" };
            community.Enabled = true;
            community.Default = true;
            udapContext.Communities.Add(community);
            await udapContext.SaveChangesAsync();
        }

        if (!udapContext.Communities.Any(c => c.Name == "udap://fhirlabs.net"))
        {
            var community = new Community { Name = "udap://fhirlabs.net" };
            community.Enabled = true;
            udapContext.Communities.Add(community);
            await udapContext.SaveChangesAsync();
        }

        var assemblyPath = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);


        //
        // Anchors
        //
        if (!clientRegistrationStore.GetAnchors("http://localhost").Result.Any())
        {
            var anchorLocalhostCert = new X509Certificate2(
                Path.Combine(assemblyPath!, "CertStore/anchors/caWeatherApiLocalhostCert.cer"));

            var community = udapContext.Communities.Single(c => c.Name == "http://localhost");

            var anchor = new Anchor
            {
                BeginDate = anchorLocalhostCert.NotBefore,
                EndDate = anchorLocalhostCert.NotAfter,
                Name = anchorLocalhostCert.Subject,
                Community = community,
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
                    Path.Combine(assemblyPath!, "CertStore/intermediates/intermediateWeatherApiLocalhostCert.cer"));

                udapContext.IntermediateCertificates.Add(new Intermediate
                {
                    BeginDate = rootCert.NotBefore,
                    EndDate = rootCert.NotAfter,
                    Name = rootCert.Subject,
                    X509Certificate = rootCert.ToPemFormat(),
                    Thumbprint = rootCert.Thumbprint,
                    Enabled = true,
                    Anchor = anchor
                });

                await udapContext.SaveChangesAsync();
            }

        }



        //
        // Anchors
        //
        if (!clientRegistrationStore.GetAnchors("udap://fhirlabs.net").Result.Any())
        {
            var sureFhirLabsAnchor = new X509Certificate2(
                Path.Combine(assemblyPath!, "CertStore/anchors/SureFhirLabs_CA.cer"));

            var community = udapContext.Communities.Single(c => c.Name == "udap://fhirlabs.net");

            var anchor = new Anchor
            {
                BeginDate = sureFhirLabsAnchor.NotBefore,
                EndDate = sureFhirLabsAnchor.NotAfter,
                Name = sureFhirLabsAnchor.Subject,
                Community = community,
                X509Certificate = sureFhirLabsAnchor.ToPemFormat(),
                Thumbprint = sureFhirLabsAnchor.Thumbprint,
                Enabled = true
            };
                
            udapContext.Anchors.Add(anchor);
            await udapContext.SaveChangesAsync();
            
            //
            // Intermediates
            //
            var x509Certificate2Collection = clientRegistrationStore.GetIntermediateCertificates().Result;
            if (x509Certificate2Collection != null && !x509Certificate2Collection.Any())
            {
                var rootCert = new X509Certificate2(
                    Path.Combine(assemblyPath!, "CertStore/intermediates/SureFhirLabs_Intermediate.cer"));

                udapContext.IntermediateCertificates.Add(new Intermediate
                {
                    BeginDate = rootCert.NotBefore,
                    EndDate = rootCert.NotAfter,
                    Name = rootCert.Subject,
                    X509Certificate = rootCert.ToPemFormat(),
                    Thumbprint = rootCert.Thumbprint,
                    Enabled = true,
                    Anchor = anchor
                });

                await udapContext.SaveChangesAsync();
            }
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
        
        await configDbContext.SaveChangesAsync();
        
        if (configDbContext.ApiScopes.All(s => s.Name != "udap"))
        {
            var apiScope = new ApiScope("udap");
            configDbContext.ApiScopes.Add(apiScope.ToEntity());
        
            await configDbContext.SaveChangesAsync();
        }

    }
}
