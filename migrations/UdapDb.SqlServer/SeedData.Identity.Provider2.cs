/*
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

public static class SeedDataIdentityProvider2
{
    private static Anchor anchor;

    /// <summary>
    /// Load some test dat
    /// </summary>
    /// <param name="connectionString"></param>
    /// <param name="certStoreBasePath">Test certs base path</param>
    /// <param name="logger"></param>
    /// <param name="identityProvider">Load different scopes</param>
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


        
        if (!udapContext.Communities.Any(c => c.Name == "udap://Provider2"))
        {
            var community = new Community { Name = "udap://Provider2" };
            community.Enabled = true;
            community.Default = true;
            udapContext.Communities.Add(community);
            await udapContext.SaveChangesAsync();
        }

        var assemblyPath = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
        
        

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

        /*
         *  "openid",
            "fhirUser",
            "email", ????
            "profile"
         */

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
        sb.AppendLine("Use [Udap.Identity.Provider2.db];");
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
}
