/*
 Copyright (c) Joseph Shook. All rights reserved.
 Authors:
    Joseph Shook   Joseph.Shook@Surescripts.com

 See LICENSE in the project root for license information.
*/


using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Duende.IdentityServer.EntityFramework.DbContexts;
using Duende.IdentityServer.EntityFramework.Mappers;
using Duende.IdentityServer.EntityFramework.Storage;
using Duende.IdentityServer.Models;
using Hl7.Fhir.Model;
using Microsoft.EntityFrameworkCore;
using Serilog;
using Udap.Server.DbContexts;
using Udap.Server.Entities;
using Udap.Server.Extensions;
using Udap.Server.Registration;
using Udap.Util.Extensions;
using ILogger = Serilog.ILogger;
using Task = System.Threading.Tasks.Task;

namespace UdapDb;

public static class SeedData
{
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
        using var scope = serviceProvider.GetRequiredService<IServiceScopeFactory>().CreateScope();

        await scope.ServiceProvider.GetRequiredService<PersistedGrantDbContext>().Database.MigrateAsync();
        var configDbContext = scope.ServiceProvider.GetRequiredService<ConfigurationDbContext>();
        await configDbContext.Database.MigrateAsync();

        var udapContext = scope.ServiceProvider.GetRequiredService<UdapDbContext>();
        await udapContext.Database.MigrateAsync();

        var clientRegistrationStore = scope.ServiceProvider.GetRequiredService<IUdapClientRegistrationStore>();


        if (!udapContext.Communities.Any(c => c.Name == "http://localhost"))
        {
            var community = new Community { Name = "http://localhost" };
            community.Enabled = true;
            community.Default = false;
            udapContext.Communities.Add(community);
            await udapContext.SaveChangesAsync();
        }

        if (!udapContext.Communities.Any(c => c.Name == "udap://surefhir.labs"))
        {
            var community = new Community { Name = "udap://surefhir.labs" };
            community.Enabled = true;
            community.Default = true;
            udapContext.Communities.Add(community);
            await udapContext.SaveChangesAsync();
        }

        var assemblyPath = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);

        var x509Certificate2Collection = await clientRegistrationStore.GetRootCertificates();

        var rootCert = new X509Certificate2(
            Path.Combine(assemblyPath!, certStoreBasePath, "surefhirlabs_community/SureFhirLabs_CA.cer"));
        
        if (x509Certificate2Collection != null  &&  x509Certificate2Collection.ToList()
                .All(r => r.Thumbprint != rootCert.Thumbprint )) 
        {

            udapContext.RootCertificates.Add(new RootCertificate
            {
                BeginDate = rootCert.NotBefore.ToUniversalTime(),
                EndDate = rootCert.NotAfter.ToUniversalTime(),
                Name = rootCert.Subject,
                X509Certificate = rootCert.ToPemFormat(),
                Thumbprint = rootCert.Thumbprint,
                Enabled = true
            });

            await udapContext.SaveChangesAsync();
        }

        var anchorLocalhostCert = new X509Certificate2(
            Path.Combine(assemblyPath!, certStoreBasePath, "localhost_community/anchorLocalhostCert.cer"));

        if ((await clientRegistrationStore.GetAnchors("http://localhost"))
            .All(a => a.Thumbprint != anchorLocalhostCert.Thumbprint))
        {
            var community = udapContext.Communities.Single(c => c.Name == "http://localhost");

            udapContext.Anchors.Add(new Anchor
            {
                BeginDate = anchorLocalhostCert.NotBefore.ToUniversalTime(),
                EndDate = anchorLocalhostCert.NotAfter.ToUniversalTime(),
                Name = anchorLocalhostCert.Subject,
                Community = community,
                X509Certificate = anchorLocalhostCert.ToPemFormat(),
                Thumbprint = anchorLocalhostCert.Thumbprint,
                Enabled = true
            });

            await udapContext.SaveChangesAsync();
        }

        var sureFhirLabsAnchor = new X509Certificate2(
            Path.Combine(assemblyPath!, certStoreBasePath, "surefhirlabs_community/anchors/SureFhirLabs_Anchor.cer"));

        if (( await clientRegistrationStore.GetAnchors("udap://surefhir.labs"))
            .All(a => a.Thumbprint != sureFhirLabsAnchor.Thumbprint))
        {
            

            var community = udapContext.Communities.Single(c => c.Name == "udap://surefhir.labs");

            udapContext.Anchors.Add(new Anchor
            {
                BeginDate = sureFhirLabsAnchor.NotBefore.ToUniversalTime(),
                EndDate = sureFhirLabsAnchor.NotAfter.ToUniversalTime(),
                Name = sureFhirLabsAnchor.Subject,
                Community = community,
                X509Certificate = sureFhirLabsAnchor.ToPemFormat(),
                Thumbprint = sureFhirLabsAnchor.Thumbprint,
                Enabled = true
            });

            await udapContext.SaveChangesAsync();
        }

        await SeedFhirScopes(configDbContext, "system");
        await SeedFhirScopes(configDbContext, "user");

        //
        // OpenId
        //
        // if (configDbContext.IdentityResources.All(i => i.Name != IdentityServerConstants.StandardScopes.OpenId))
        // {
        //     var identityResource = new IdentityResources.OpenId();
        //     configDbContext.IdentityResources.Add(identityResource.ToEntity());
        //
        //     await configDbContext.SaveChangesAsync();
        // }
        

        var sb = new StringBuilder();
        sb.AppendLine("Use[Udap.Idp.db];");
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

    private static async Task SeedFhirScopes(ConfigurationDbContext configDbContext, string prefix)
    {
        var seedScopes = new List<string>();

        foreach (var resName in ModelInfo.SupportedResources)
        {
            seedScopes.Add($"{prefix}/{resName}.*");
            seedScopes.Add($"{prefix}/{resName}.read");
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


        if (configDbContext.ApiScopes.All(s => s.Name != "system.cruds"))
        {
            var apiScope = new ApiScope("system.cruds");
            configDbContext.ApiScopes.Add(apiScope.ToEntity());

            await configDbContext.SaveChangesAsync();
        }

        if (configDbContext.ApiScopes.All(s => s.Name != "user.cruds"))
        {
            var apiScope = new ApiScope("user.cruds");
            configDbContext.ApiScopes.Add(apiScope.ToEntity());

            await configDbContext.SaveChangesAsync();
        }

        if (configDbContext.ApiScopes.All(s => s.Name != "udap"))
        {
            var apiScope = new ApiScope("udap");
            configDbContext.ApiScopes.Add(apiScope.ToEntity());

            await configDbContext.SaveChangesAsync();
        }
    }
}
