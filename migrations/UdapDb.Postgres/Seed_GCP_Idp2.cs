﻿/*
 Copyright (c) Joseph Shook. All rights reserved.
 Authors:
    Joseph Shook   Joseph.Shook@Surescripts.com

 See LICENSE in the project root for license information.
*/


using System.Linq;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Duende.IdentityServer;
using Duende.IdentityServer.EntityFramework.DbContexts;
using Duende.IdentityServer.EntityFramework.Mappers;
using Duende.IdentityServer.EntityFramework.Storage;
using Duende.IdentityServer.Models;
using Microsoft.EntityFrameworkCore;
using Serilog;
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

public static class Seed_GCP_Idp2
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
            options.ConfigureDbContext = db => db.UseNpgsql(connectionString,
                sql => sql.MigrationsAssembly(typeof(Program).Assembly.FullName));
        });
        services.AddConfigurationDbContext(options =>
        {
            options.ConfigureDbContext = db => db.UseNpgsql(connectionString,
                sql => sql.MigrationsAssembly(typeof(Program).Assembly.FullName));
        });

        services.AddScoped<IUdapClientRegistrationStore, UdapClientRegistrationStore>();
        services.AddUdapDbContext(options =>
        {
            options.UdapDbContext = db => db.UseNpgsql(connectionString,
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

        if (!udapContext.Communities.Any(c => c.Name == "udap://fhirlabs.net/"))
        {
            var community = new Community { Name = "udap://fhirlabs.net/" };
            community.Enabled = true;
            community.Default = true;
            udapContext.Communities.Add(community);
            await udapContext.SaveChangesAsync();
        }

        var assemblyPath = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);



        //
        // Anchor surefhirlabs_community
        //
        var sureFhirLabsAnchor = new X509Certificate2(
            Path.Combine(assemblyPath!, certStoreBasePath, "surefhirlabs_community/SureFhirLabs_CA.cer"));

        if ((await clientRegistrationStore.GetAnchors("udap://fhirlabs.net/"))
            .All(a => a.Thumbprint != sureFhirLabsAnchor.Thumbprint))
        {
            var community = udapContext.Communities.Single(c => c.Name == "udap://fhirlabs.net/");

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


        return 0;
    }
}
