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
using Duende.IdentityServer;
using Duende.IdentityServer.EntityFramework.DbContexts;
using Duende.IdentityServer.EntityFramework.Mappers;
using Duende.IdentityServer.EntityFramework.Storage;
using Duende.IdentityServer.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Serilog;
using Udap.Common.Extensions;
using Udap.Server.DbContexts;
using Udap.Server.Entities;
using Udap.Server.Storage.Stores;
using Udap.Server.Stores;
using Udap.Util.Extensions;
using Task = System.Threading.Tasks.Task;

namespace UdapServer.Tests;

public static class SeedData
{
    // ReSharper disable once UnusedParameter.Global
#pragma warning disable IDE0060 // Remove unused parameter
    public static async Task EnsureSeedData(string connectionString, ILogger logger)
#pragma warning restore IDE0060 // Remove unused parameter
    {
        var services = new ServiceCollection();

        services.AddLogging();

        services.AddOperationalDbContext(options =>
        {
            options.ConfigureDbContext = db => db.UseSqlite(connectionString,
                sql => sql.MigrationsAssembly(typeof(SeedData).Assembly.FullName))
                // Added when upgrading from net8.0 to net9.0 instead of generating migrations when nothing has changed.
                .ConfigureWarnings(warnings => warnings.Ignore(RelationalEventId.PendingModelChangesWarning));
        });
        services.AddConfigurationDbContext(options =>
        {
            options.ConfigureDbContext = db => db.UseSqlite(connectionString,
                sql => sql.MigrationsAssembly(typeof(SeedData).Assembly.FullName))
                .ConfigureWarnings(warnings => warnings.Ignore(RelationalEventId.PendingModelChangesWarning));
        });

        services.AddScoped<IUdapClientRegistrationStore, UdapClientRegistrationStore>();
        services.AddUdapDbContext(options =>
        {
            options.UdapDbContext = db => db.UseSqlite(connectionString,
                sql => sql.MigrationsAssembly(typeof(SeedData).Assembly.FullName))
                .ConfigureWarnings(warnings => warnings.Ignore(RelationalEventId.PendingModelChangesWarning));
        });

        await using var serviceProvider = services.BuildServiceProvider();
        using var scope = serviceProvider.GetRequiredService<IServiceScopeFactory>().CreateScope();


        // var context = scope.ServiceProvider.GetService<ApplicationDbContext>();
        // context?.Database.Migrate();

        var udapContext = scope.ServiceProvider.GetRequiredService<UdapDbContext>();
        await udapContext.Database.EnsureCreatedAsync();

        var configDbContext = scope.ServiceProvider.GetRequiredService<ConfigurationDbContext>();

        await scope.ServiceProvider.GetRequiredService<PersistedGrantDbContext>().Database.MigrateAsync();
        await scope.ServiceProvider.GetRequiredService<ConfigurationDbContext>().Database.MigrateAsync();


        var clientRegistrationStore = scope.ServiceProvider.GetRequiredService<IUdapClientRegistrationStore>();


        if (!udapContext.Communities.Any(c => c.Name == "http://localhost"))
        {
            var community = new Community
            {
                Name = "http://localhost",
                Enabled = true,
                Default = true
            };
            udapContext.Communities.Add(community);
            await udapContext.SaveChangesAsync();
        }

        if (!udapContext.Communities.Any(c => c.Name == "udap://fhirlabs.net"))
        {
            var community = new Community
            {
                Name = "udap://fhirlabs.net",
                Enabled = true
            };
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

        //
        // openid
        //
        if (configDbContext.IdentityResources.All(i => i.Name != IdentityServerConstants.StandardScopes.OpenId))
        {
            var identityResource = new IdentityResources.OpenId();
            configDbContext.IdentityResources.Add(identityResource.ToEntity());

            await configDbContext.SaveChangesAsync();
        }


        Func<string, bool> treatmentSpecification = r => r is "Patient" or "AllergyIntolerance" or "Condition" or "Encounter";
        var scopeProperties = new Dictionary<string, string>();
        scopeProperties.Add("smart_version", "v1");

        await SeedFhirScopes(configDbContext, Hl7ModelInfoExtensions.BuildHl7FhirV1Scopes(new List<string>(){"patient", "user"}, treatmentSpecification), scopeProperties);
        await SeedFhirScopes(configDbContext, Hl7ModelInfoExtensions.BuildHl7FhirV1Scopes("system", treatmentSpecification), scopeProperties);

        scopeProperties = new Dictionary<string, string>();
        scopeProperties.Add("smart_version", "v2");
        await SeedFhirScopes(configDbContext, Hl7ModelInfoExtensions.BuildHl7FhirV2Scopes(new List<string>() { "patient", "user" }, treatmentSpecification), scopeProperties);
        await SeedFhirScopes(configDbContext, Hl7ModelInfoExtensions.BuildHl7FhirV2Scopes("system", treatmentSpecification), scopeProperties);
        
    }

    private static async Task SeedFhirScopes(
        ConfigurationDbContext configDbContext,
        HashSet<string> seedScopes,
        Dictionary<string, string> scopeProperties)
    {
        var apiScopes = configDbContext.ApiScopes
            .Include(s => s.Properties)
            .Select(s => s)
            .ToList();

        foreach (var scopeName in seedScopes.Where(s => s.StartsWith("system")))
        {
            if (!apiScopes.Any(s =>
                    s.Name == scopeName && s.Properties.Exists(p => p.Key == "udap_prefix" && p.Value == "system")))
            {
                var apiScope = new ApiScope(scopeName)
                {
                    ShowInDiscoveryDocument = false
                };

                if (apiScope.Name.StartsWith("system/*."))
                {
                    apiScope.ShowInDiscoveryDocument = true;
                    apiScope.Enabled = false;
                }

                apiScope.Properties.Add("udap_prefix", "system");

                foreach (var scopeProperty in scopeProperties)
                {
                    apiScope.Properties.Add(scopeProperty.Key, scopeProperty.Value);
                }

                configDbContext.ApiScopes.Add(apiScope.ToEntity());
            }
        }

        foreach (var scopeName in seedScopes.Where(s => s.StartsWith("user")))
        {
            if (!apiScopes.Any(s =>
                    s.Name == scopeName && s.Properties.Exists(p => p.Key == "udap_prefix" && p.Value == "user")))
            {
                var apiScope = new ApiScope(scopeName)
                {
                    ShowInDiscoveryDocument = false
                };

                if (apiScope.Name.StartsWith("user/*."))
                {
                    apiScope.ShowInDiscoveryDocument = true;
                    apiScope.Enabled = false;
                }

                apiScope.Properties.Add("udap_prefix", "user");

                foreach (var scopeProperty in scopeProperties)
                {
                    apiScope.Properties.Add(scopeProperty.Key, scopeProperty.Value);
                }

                configDbContext.ApiScopes.Add(apiScope.ToEntity());
            }
        }

        foreach (var scopeName in seedScopes.Where(s => s.StartsWith("patient")))
        {
            if (!apiScopes.Any(s => s.Name == scopeName && s.Properties.Exists(p => p.Key == "udap_prefix" && p.Value == "patient")))
            {
                var apiScope = new ApiScope(scopeName)
                {
                    ShowInDiscoveryDocument = false
                };

                if (apiScope.Name.StartsWith("patient/*."))
                {
                    apiScope.ShowInDiscoveryDocument = true;
                    apiScope.Enabled = false;
                }

                apiScope.Properties.Add("udap_prefix", "patient");

                foreach (var scopeProperty in scopeProperties)
                {
                    apiScope.Properties.Add(scopeProperty.Key, scopeProperty.Value);
                }

                configDbContext.ApiScopes.Add(apiScope.ToEntity());
            }
        }

        await configDbContext.SaveChangesAsync();

    }
}
