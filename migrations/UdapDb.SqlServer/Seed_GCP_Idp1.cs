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

public static class Seed_GCP_Idp1
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


        //
        //  Trust Community  udap://stage.healthtogo.me/
        //
        if (!udapContext.Communities.Any(c => c.Name == "udap://stage.healthtogo.me/"))
        {
            var community = new Community { Name = "udap://stage.healthtogo.me/" };
            community.Enabled = true;
            community.Default = true;
            udapContext.Communities.Add(community);
            await udapContext.SaveChangesAsync();
        }

        var assemblyPath = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);



        //
        // Anchor for Trust Community udap://stage.healthtogo.me/
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
        sb.AppendLine("Use [Udap.Identity.Provider1.db];");
        sb.AppendLine("if not exists(select * from sys.server_principals where name = 'udap_Idp1')");
        sb.AppendLine("BEGIN");
        sb.AppendLine("CREATE LOGIN udap_Idp1 WITH PASSWORD = 'udap_password_idp1', DEFAULT_DATABASE =[Udap.Identity.Provider1.db], CHECK_EXPIRATION = OFF, CHECK_POLICY = OFF;");
        sb.AppendLine("END");
        sb.AppendLine("IF NOT EXISTS(SELECT principal_id FROM sys.database_principals WHERE name = 'udap_Idp1')");
        sb.AppendLine("BEGIN");
        sb.AppendLine("CREATE USER udap_Idp1 from LOGIN udap_Idp1;");
        sb.AppendLine("EXEC sp_addrolemember N'db_owner', N'udap_Idp1';");
        sb.AppendLine("END");

        await configDbContext.Database.ExecuteSqlRawAsync(sb.ToString());

        return 0;
    }
}
