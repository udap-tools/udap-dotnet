/*
 Copyright (c) Joseph Shook. All rights reserved.
 Authors:
    Joseph Shook   Joseph.Shook@Surescripts.com

 See LICENSE in the project root for license information.
*/


using Duende.IdentityServer;
using Duende.IdentityServer.EntityFramework.DbContexts;
using Duende.IdentityServer.EntityFramework.Mappers;
using Duende.IdentityServer.EntityFramework.Storage;
using Duende.IdentityServer.Models;
using Microsoft.EntityFrameworkCore;
using Serilog;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Udap.Common.Extensions;
using Udap.Model;
using Udap.Server.DbContexts;
using Udap.Server.Entities;
using Udap.Server.Models;
using Udap.Server.Storage.Stores;
using Udap.Server.Stores;
using Udap.Util.Extensions;
using ILogger = Serilog.ILogger;
using Task = System.Threading.Tasks.Task;

namespace UdapDb;

public static class SeedDataAuthServer
{
    private static Anchor anchor;

    /// <summary>
    /// Load some test dat
    /// </summary>
    /// <param name="connectionString"></param>
    /// <param name="certStoreBasePath">Test certs base path</param>
    /// <param name="logger"></param>
    public static async Task<int> EnsureSeedData(string connectionString, string certStoreBasePath, ILogger logger)
    {
        var services = new ServiceCollection();

        services.AddLogging(c => c.AddSerilog());

        services.AddOperationalDbContext(options =>
        {
            options.ConfigureDbContext = db => db.UseSqlServer(connectionString,
                sql => sql.MigrationsAssembly(typeof(Program).Assembly.FullName));
        });
        services.AddConfigurationDbContext(options =>
        {
            options.ConfigureDbContext = db => db.UseSqlServer(connectionString,
                sql => sql.MigrationsAssembly(typeof(Program).Assembly.FullName));
        });

        services.AddScoped<IUdapClientRegistrationStore, UdapClientRegistrationStore>();
        services.AddUdapDbContext(options =>
        {
            options.UdapDbContext = db => db.UseSqlServer(connectionString,
                sql => sql.MigrationsAssembly(typeof(Program).Assembly.FullName));
        });

        await using var serviceProvider = services.BuildServiceProvider();
        using var serviceScope = serviceProvider.GetRequiredService<IServiceScopeFactory>().CreateScope();

        await serviceScope.ServiceProvider.GetRequiredService<PersistedGrantDbContext>().Database.MigrateAsync();
        var configDbContext = serviceScope.ServiceProvider.GetRequiredService<ConfigurationDbContext>();
        await configDbContext.Database.MigrateAsync();

        var udapContext = serviceScope.ServiceProvider.GetRequiredService<UdapDbContext>();
        await udapContext.Database.MigrateAsync();

        var clientRegistrationStore = serviceScope.ServiceProvider.GetRequiredService<IUdapClientRegistrationStore>();


        if (!udapContext.Communities.Any(c => c.Name == "http://localhost"))
        {
            var community = new Community { Name = "http://localhost" };
            community.Enabled = true;
            community.Default = false;
            udapContext.Communities.Add(community);
            await udapContext.SaveChangesAsync();
        }

        if (!udapContext.Communities.Any(c => c.Name == "udap://fhirlabs1/"))
        {
            var community = new Community { Name = "udap://fhirlabs1/" };
            community.Enabled = true;
            community.Default = true;
            udapContext.Communities.Add(community);
            await udapContext.SaveChangesAsync();
        }


        if (!udapContext.Communities.Any(c => c.Name == "udap://stage.healthtogo.me/"))
        {
            var community = new Community { Name = "udap://stage.healthtogo.me/" };
            community.Enabled = true;
            community.Default = false;
            udapContext.Communities.Add(community);
            await udapContext.SaveChangesAsync();
        }


        if (!udapContext.Communities.Any(c => c.Name == "udap://Provider2"))
        {
            var community = new Community { Name = "udap://Provider2" };
            community.Enabled = true;
            community.Default = false;
            udapContext.Communities.Add(community);
            await udapContext.SaveChangesAsync();
        }

        if (!udapContext.Communities.Any(c => c.Name == "udap://ECDSA/"))
        {
            var community = new Community { Name = "udap://ECDSA/" };
            community.Enabled = true;
            community.Default = false;
            udapContext.Communities.Add(community);
            await udapContext.SaveChangesAsync();
        }
    

        var assemblyPath = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);



        //
        // Anchor surefhirlabs_community
        //
        var sureFhirLabsAnchor = new X509Certificate2(
            Path.Combine(assemblyPath!, certStoreBasePath, "surefhirlabs_community/SureFhirLabs_CA.cer"));

        if ((await clientRegistrationStore.GetAnchors("udap://fhirlabs1/"))
            .All(a => a.Thumbprint != sureFhirLabsAnchor.Thumbprint))
        {
            var community = udapContext.Communities.Single(c => c.Name == "udap://fhirlabs1/");

            anchor = new Anchor
            {
                BeginDate = sureFhirLabsAnchor.NotBefore.ToUniversalTime(),
                EndDate = sureFhirLabsAnchor.NotAfter.ToUniversalTime(),
                Name = sureFhirLabsAnchor.Subject,
                Community = community,
                X509Certificate = sureFhirLabsAnchor.ToPemFormat(),
                Thumbprint = sureFhirLabsAnchor.Thumbprint,
                Enabled = true
            };

            udapContext.Anchors.Add(anchor);
            await udapContext.SaveChangesAsync();
        }

        var intermediateCert = new X509Certificate2(
            Path.Combine(assemblyPath!, certStoreBasePath,
                "surefhirlabs_community/intermediates/SureFhirLabs_Intermediate.cer"));

        if ((await clientRegistrationStore.GetIntermediateCertificates())
            .All(a => a.Thumbprint != intermediateCert.Thumbprint))
        {
            var anchor = udapContext.Anchors.Single(a => a.Thumbprint == sureFhirLabsAnchor.Thumbprint);

            //
            // Intermediate surefhirlabs_community
            //
            var x509Certificate2Collection = await clientRegistrationStore.GetIntermediateCertificates();
            
            if (x509Certificate2Collection != null && x509Certificate2Collection.ToList()
                    .All(r => r.Thumbprint != intermediateCert.Thumbprint))
            {

                udapContext.IntermediateCertificates.Add(new Intermediate
                {
                    BeginDate = intermediateCert.NotBefore.ToUniversalTime(),
                    EndDate = intermediateCert.NotAfter.ToUniversalTime(),
                    Name = intermediateCert.Subject,
                    X509Certificate = intermediateCert.ToPemFormat(),
                    Thumbprint = intermediateCert.Thumbprint,
                    Enabled = true,
                    Anchor = anchor
                });

                await udapContext.SaveChangesAsync();
            }
        }


        //
        // Anchor for Community udap://stage.healthtogo.me/
        //
        var emrDirectTestCA = new X509Certificate2(
            Path.Combine(assemblyPath!, certStoreBasePath, "EmrDirect/EMRDirectTestCA.crt"));

        if ((await clientRegistrationStore.GetAnchors("udap://stage.healthtogo.me/"))
            .All(a => a.Thumbprint != emrDirectTestCA.Thumbprint))
        {
            var community = udapContext.Communities.Single(c => c.Name == "udap://stage.healthtogo.me/");

            anchor = new Anchor
            {
                BeginDate = emrDirectTestCA.NotBefore.ToUniversalTime(),
                EndDate = emrDirectTestCA.NotAfter.ToUniversalTime(),
                Name = emrDirectTestCA.Subject,
                Community = community,
                X509Certificate = emrDirectTestCA.ToPemFormat(),
                Thumbprint = emrDirectTestCA.Thumbprint,
                Enabled = true
            };

            udapContext.Anchors.Add(anchor);
            await udapContext.SaveChangesAsync();
        }

        

        //
        // Anchor localhost_community
        //
        var anchorLocalhostCert = new X509Certificate2(
            Path.Combine(assemblyPath!, certStoreBasePath, "localhost_fhirlabs_community1/caLocalhostCert.cer"));

        if ((await clientRegistrationStore.GetAnchors("http://localhost"))
            .All(a => a.Thumbprint != anchorLocalhostCert.Thumbprint))
        {
            var community = udapContext.Communities.Single(c => c.Name == "http://localhost");
            var anchor = new Anchor
            {
                BeginDate = anchorLocalhostCert.NotBefore.ToUniversalTime(),
                EndDate = anchorLocalhostCert.NotAfter.ToUniversalTime(),
                Name = anchorLocalhostCert.Subject,
                Community = community,
                X509Certificate = anchorLocalhostCert.ToPemFormat(),
                Thumbprint = anchorLocalhostCert.Thumbprint,
                Enabled = true
            };
            udapContext.Anchors.Add(anchor);

            await udapContext.SaveChangesAsync();

            //
            // Intermediate surefhirlabs_community
            //
            var x509Certificate2Collection = await clientRegistrationStore.GetIntermediateCertificates();

            intermediateCert = new X509Certificate2(
                Path.Combine(assemblyPath!, certStoreBasePath, "localhost_fhirlabs_community1/intermediates/intermediateLocalhostCert.cer"));

            if (x509Certificate2Collection != null && x509Certificate2Collection.ToList()
                    .All(r => r.Thumbprint != intermediateCert.Thumbprint))
            {

                udapContext.IntermediateCertificates.Add(new Intermediate
                {
                    BeginDate = intermediateCert.NotBefore.ToUniversalTime(),
                    EndDate = intermediateCert.NotAfter.ToUniversalTime(),
                    Name = intermediateCert.Subject,
                    X509Certificate = intermediateCert.ToPemFormat(),
                    Thumbprint = intermediateCert.Thumbprint,
                    Enabled = true,
                    Anchor = anchor
                });

                await udapContext.SaveChangesAsync();
            }
        }



        //
        // Anchor localhost_fhirlabs_community2 for Udap.Identity.Provider2
        //
        var anchorUdapIdentityProvider2 = new X509Certificate2(
            Path.Combine(assemblyPath!, certStoreBasePath, "localhost_fhirlabs_community2/caLocalhostCert2.cer"));

        if ((await clientRegistrationStore.GetAnchors("udap://Provider2"))
            .All(a => a.Thumbprint != anchorUdapIdentityProvider2.Thumbprint))
        {
            var community = udapContext.Communities.Single(c => c.Name == "udap://Provider2");

            anchor = new Anchor
            {
                BeginDate = anchorUdapIdentityProvider2.NotBefore.ToUniversalTime(),
                EndDate = anchorUdapIdentityProvider2.NotAfter.ToUniversalTime(),
                Name = anchorUdapIdentityProvider2.Subject,
                Community = community,
                X509Certificate = anchorUdapIdentityProvider2.ToPemFormat(),
                Thumbprint = anchorUdapIdentityProvider2.Thumbprint,
                Enabled = true
            };

            udapContext.Anchors.Add(anchor);
            await udapContext.SaveChangesAsync();
        }

        var intermediateCertProvider2 = new X509Certificate2(
            Path.Combine(assemblyPath!, certStoreBasePath,
                "localhost_fhirlabs_community2/intermediates/intermediateLocalhostCert2.cer"));

        if ((await clientRegistrationStore.GetIntermediateCertificates())
            .All(a => a.Thumbprint != intermediateCertProvider2.Thumbprint))
        {
            var anchorProvider2 = udapContext.Anchors.Single(a => a.Thumbprint == anchorUdapIdentityProvider2.Thumbprint);

            //
            // Intermediate surefhirlabs_community
            //
            var x509Certificate2Collection = await clientRegistrationStore.GetIntermediateCertificates();

            if (x509Certificate2Collection != null && x509Certificate2Collection.ToList()
                    .All(r => r.Thumbprint != intermediateCertProvider2.Thumbprint))
            {

                udapContext.IntermediateCertificates.Add(new Intermediate
                {
                    BeginDate = intermediateCertProvider2.NotBefore.ToUniversalTime(),
                    EndDate = intermediateCertProvider2.NotAfter.ToUniversalTime(),
                    Name = intermediateCertProvider2.Subject,
                    X509Certificate = intermediateCertProvider2.ToPemFormat(),
                    Thumbprint = intermediateCertProvider2.Thumbprint,
                    Enabled = true,
                    Anchor = anchorProvider2
                });

                await udapContext.SaveChangesAsync();
            }
        }




        //
        // Anchor udap://ECDSA/ community for Udap.Identity.Provider2
        //
        var anchorUdapECDSA = new X509Certificate2(
            Path.Combine(assemblyPath!, certStoreBasePath, "localhost_fhirlabs_community6/caLocalhostCert6.cer"));

        if ((await clientRegistrationStore.GetAnchors("udap://ECDSA/"))
            .All(a => a.Thumbprint != anchorUdapECDSA.Thumbprint))
        {
            var community = udapContext.Communities.Single(c => c.Name == "udap://ECDSA/");

            anchor = new Anchor
            {
                BeginDate = anchorUdapECDSA.NotBefore.ToUniversalTime(),
                EndDate = anchorUdapECDSA.NotAfter.ToUniversalTime(),
                Name = anchorUdapECDSA.Subject,
                Community = community,
                X509Certificate = anchorUdapECDSA.ToPemFormat(),
                Thumbprint = anchorUdapECDSA.Thumbprint,
                Enabled = true
            };

            udapContext.Anchors.Add(anchor);
            await udapContext.SaveChangesAsync();
        }

        var intermediateECDSA= new X509Certificate2(
            Path.Combine(assemblyPath!, certStoreBasePath,
                "localhost_fhirlabs_community6/intermediates/intermediateLocalhostCert6.cer"));

        if ((await clientRegistrationStore.GetIntermediateCertificates())
            .All(a => a.Thumbprint != intermediateECDSA.Thumbprint))
        {
            var anchorProvider2 = udapContext.Anchors.Single(a => a.Thumbprint == anchorUdapECDSA.Thumbprint);

            //
            // Intermediate udap://ECDSA/ community
            //
            var x509Certificate2Collection = await clientRegistrationStore.GetIntermediateCertificates();

            if (x509Certificate2Collection != null && x509Certificate2Collection.ToList()
                    .All(r => r.Thumbprint != intermediateECDSA.Thumbprint))
            {

                udapContext.IntermediateCertificates.Add(new Intermediate
                {
                    BeginDate = intermediateECDSA.NotBefore.ToUniversalTime(),
                    EndDate = intermediateECDSA.NotAfter.ToUniversalTime(),
                    Name = intermediateECDSA.Subject,
                    X509Certificate = intermediateECDSA.ToPemFormat(),
                    Thumbprint = intermediateECDSA.Thumbprint,
                    Enabled = true,
                    Anchor = anchorProvider2
                });

                await udapContext.SaveChangesAsync();
            }
        }


        Func<string, bool> treatmentSpecification = r => r is "Patient" or "AllergyIntolerance" or "Condition" or "Encounter";
        var scopeProperties = new Dictionary<string, string>();
        scopeProperties.Add("smart_version", "v1");   

        await SeedFhirScopes(configDbContext, Hl7ModelInfoExtensions.BuildHl7FhirV1Scopes("patient", treatmentSpecification), scopeProperties);
        await SeedFhirScopes(configDbContext, Hl7ModelInfoExtensions.BuildHl7FhirV1Scopes("user", treatmentSpecification), scopeProperties);
        await SeedFhirScopes(configDbContext, Hl7ModelInfoExtensions.BuildHl7FhirV1Scopes("system", treatmentSpecification), scopeProperties);

        scopeProperties = new Dictionary<string, string>();
        scopeProperties.Add("smart_version", "v2");
        await SeedFhirScopes(configDbContext, Hl7ModelInfoExtensions.BuildHl7FhirV2Scopes("patient", treatmentSpecification), scopeProperties);
        await SeedFhirScopes(configDbContext, Hl7ModelInfoExtensions.BuildHl7FhirV2Scopes("user", treatmentSpecification), scopeProperties);
        await SeedFhirScopes(configDbContext, Hl7ModelInfoExtensions.BuildHl7FhirV2Scopes("system", treatmentSpecification), scopeProperties);


        //
        // openid
        //
        if (configDbContext.IdentityResources.All(i => i.Name != IdentityServerConstants.StandardScopes.OpenId))
        {
            var identityResource = new IdentityResources.OpenId();
            configDbContext.IdentityResources.Add(identityResource.ToEntity());

            await configDbContext.SaveChangesAsync();
        }

        //
        // fhirUser
        //
        if (configDbContext.IdentityResources.All(i => i.Name != UdapConstants.StandardScopes.FhirUser))
        {
            var fhirUserIdentity = new UdapIdentityResources.FhirUser();
            configDbContext.IdentityResources.Add(fhirUserIdentity.ToEntity());

            await configDbContext.SaveChangesAsync();
        }

        //
        // udap
        //
        if (configDbContext.IdentityResources.All(i => i.Name != UdapConstants.StandardScopes.Udap))
        {
            var udapIdentity = new UdapIdentityResources.Udap();
            configDbContext.IdentityResources.Add(udapIdentity.ToEntity());

            await configDbContext.SaveChangesAsync();
        }

        //
        // profile
        //
        if (configDbContext.IdentityResources.All(i => i.Name != IdentityServerConstants.StandardScopes.Profile))
        {
            var identityResource = new UdapIdentityResources.Profile();
            configDbContext.IdentityResources.Add(identityResource.ToEntity());

            await configDbContext.SaveChangesAsync();
        }

        //
        // email
        //
        if (configDbContext.IdentityResources.All(i => i.Name != IdentityServerConstants.StandardScopes.Email))
        {
            var identityResource = new IdentityResources.Email();
            configDbContext.IdentityResources.Add(identityResource.ToEntity());

            await configDbContext.SaveChangesAsync();
        }

        var sb = new StringBuilder();
        sb.AppendLine("Use [Udap.Idp.db];");
        sb.AppendLine("if not exists(select * from sys.server_principals where name = 'udap_user')");
        sb.AppendLine("BEGIN");
        sb.AppendLine("CREATE LOGIN udap_user WITH PASSWORD = 'udap_password1', DEFAULT_DATABASE =[Udap.Idp.db], CHECK_EXPIRATION = OFF, CHECK_POLICY = OFF;");
        sb.AppendLine("END");
        sb.AppendLine("IF NOT EXISTS(SELECT principal_id FROM sys.database_principals WHERE name = 'udap_user')");
        sb.AppendLine("BEGIN");
        sb.AppendLine("CREATE USER udap_user from LOGIN udap_user;");
        sb.AppendLine("EXEC sp_addrolemember N'db_owner', N'udap_user';");
        sb.AppendLine("END");

        await configDbContext.Database.ExecuteSqlRawAsync(sb.ToString());

        return 0;
    }

    private static async Task SeedFhirScopes(
        ConfigurationDbContext configDbContext, 
        HashSet<string>? seedScopes, 
        Dictionary<string,string> scopeProperties)
    {
        var apiScopes = configDbContext.ApiScopes
            .Include(s => s.Properties)
            .Where(s => s.Enabled)
            .Select(s => s)
            .ToList();

        foreach (var scopeName in seedScopes.Where(s => s.StartsWith("system")))
        {
            if (!apiScopes.Any(s =>
                    s.Name == scopeName && s.Properties.Exists(p => p.Key == "udap_prefix" && p.Value == "system")))
            {
                var apiScope = new ApiScope(scopeName);
                apiScope.ShowInDiscoveryDocument = false;
                
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
                var apiScope = new ApiScope(scopeName);
                apiScope.ShowInDiscoveryDocument = false;
                
                if (apiScope.Name.StartsWith("patient/*."))
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
                var apiScope = new ApiScope(scopeName);
                apiScope.ShowInDiscoveryDocument = false;
                
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
