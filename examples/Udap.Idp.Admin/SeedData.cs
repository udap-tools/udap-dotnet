/*
 Copyright (c) Joseph Shook. All rights reserved.
 Authors:
    Joseph Shook   Joseph.Shook@Surescripts.com

 See LICENSE in the project root for license information.
*/


using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using Duende.IdentityServer.EntityFramework.DbContexts;
using Duende.IdentityServer.EntityFramework.Mappers;
using Duende.IdentityServer.EntityFramework.Storage;
using Duende.IdentityServer.Models;
using Hl7.Fhir.Model;
using Microsoft.EntityFrameworkCore;
using Serilog;
using Udap.Server;
using Udap.Server.DbContexts;
using Udap.Server.Entities;
using Udap.Server.Storage.Stores;
using Udap.Server.Stores;
using Udap.Util.Extensions;
using ILogger = Serilog.ILogger;

namespace Udap.Idp.Admin;

public static class SeedData
{
    /// <summary>
    /// Load some test dat
    /// </summary>
    /// <param name="connectionString"></param>
    /// <param name="certStoreBasePath">Test certs base path</param>
    /// <param name="logger"></param>
    public static void EnsureSeedData(string connectionString, string certStoreBasePath, ILogger logger)
    {
        var services = new ServiceCollection();

        services.AddLogging(c => c.AddSerilog());

        services.AddOperationalDbContext(options =>
        {
            // options.ConfigureDbContext = db => db.UseSqlite(connectionString,
            //     sql => sql.MigrationsAssembly(typeof(SeedData).Assembly.FullName));
            options.ConfigureDbContext = db => db.UseSqlServer(connectionString,
                sql => sql.MigrationsAssembly(typeof(SeedData).Assembly.FullName));
        });
        services.AddConfigurationDbContext(options =>
        {
            // options.ConfigureDbContext = db => db.UseSqlite(connectionString,
            //     sql => sql.MigrationsAssembly(typeof(SeedData).Assembly.FullName));
            options.ConfigureDbContext = db => db.UseSqlServer(connectionString,
                sql => sql.MigrationsAssembly(typeof(SeedData).Assembly.FullName));
        });

        services.AddScoped<IUdapClientRegistrationStore, UdapClientRegistrationStore>();
        services.AddUdapDbContext(options =>
        {
            // options.UdapDbContext = db => db.UseSqlite(connectionString,
            //     sql => sql.MigrationsAssembly(typeof(UdapDiscoveryEndpoint).Assembly.FullName));
            options.UdapDbContext = db => db.UseSqlServer(connectionString,
                sql => sql.MigrationsAssembly(typeof(UdapDiscoveryEndpoint).Assembly.FullName));
        });

        using var serviceProvider = services.BuildServiceProvider();
        using var scope = serviceProvider.GetRequiredService<IServiceScopeFactory>().CreateScope();

        scope.ServiceProvider.GetRequiredService<PersistedGrantDbContext>().Database.Migrate();
        var configDbContext = scope.ServiceProvider.GetRequiredService<ConfigurationDbContext>();
        configDbContext.Database.Migrate();

        var udapContext = scope.ServiceProvider.GetRequiredService<UdapDbContext>();
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

        if (!udapContext.Communities.Any(c => c.Name == "udap://fhirlabs.net"))
        {
            var community = new Community { Name = "udap://fhirlabs.net" };
            community.Enabled = true;
            community.Default = true;
            udapContext.Communities.Add(community);
            udapContext.SaveChanges();
        }

        var assemblyPath = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);

        var x509Certificate2Collection = clientRegistrationStore.GetIntermediateCertificates().Result;
        if (x509Certificate2Collection != null && !x509Certificate2Collection.Any())
        {
            var rootCert = new X509Certificate2(
                Path.Combine(assemblyPath!, certStoreBasePath, "surefhirlabs_community/SureFhirLabs_CA.cer"));

            udapContext.IntermediateCertificates.Add(new Intermediate
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
                Path.Combine(assemblyPath!, certStoreBasePath, "localhost_community/anchorLocalhostCert.cer"));
        
            var community = udapContext.Communities.Single(c => c.Name == "http://localhost");
        
            udapContext.Anchors.Add(new Anchor
            {
                BeginDate = anchorLocalhostCert.NotBefore,
                EndDate = anchorLocalhostCert.NotAfter,
                Name = anchorLocalhostCert.Subject,
                Community = community,
                X509Certificate = anchorLocalhostCert.ToPemFormat(),
                Thumbprint = anchorLocalhostCert.Thumbprint,
                Enabled = true
            });
        
            udapContext.SaveChanges();
        }
        
        
        if (!clientRegistrationStore.GetAnchors("udap://fhirlabs.net").Result.Any())
        {
            var sureFhirLabsAnchor = new X509Certificate2(
                Path.Combine(assemblyPath!, certStoreBasePath, "surefhirlabs_community/intermediates/SureFhirLabs_Intermediate.cer"));
        
            var commnity = udapContext.Communities.Single(c => c.Name == "udap://fhirlabs.net");
        
            udapContext.Anchors.Add(new Anchor
            {
                BeginDate = sureFhirLabsAnchor.NotBefore,
                EndDate = sureFhirLabsAnchor.NotAfter,
                Name = sureFhirLabsAnchor.Subject,
                Community = commnity,
                X509Certificate = sureFhirLabsAnchor.ToPemFormat(),
                Thumbprint = sureFhirLabsAnchor.Thumbprint,
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
    }
}
