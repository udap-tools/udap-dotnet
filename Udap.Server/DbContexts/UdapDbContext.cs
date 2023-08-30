#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer.EntityFramework.Entities;
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Udap.Server.Entities;
using Udap.Server.Extensions;
using Udap.Server.Options;

namespace Udap.Server.DbContexts;

public interface IUdapDbAdminContext : IDisposable
{
    DbSet<Duende.IdentityServer.EntityFramework.Entities.Client> Clients { get; set; }
    DbSet<Anchor> Anchors { get; set; }
    DbSet<Intermediate> IntermediateCertificates { get; set; }
    DbSet<Community> Communities { get; set; }
    DbSet<Certification> Certifications { get; set; }
    DbSet<TieredClient> TieredClients { get; set; }

    /// <summary>
    /// Saves the changes.
    /// </summary>
    /// <returns></returns>
    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}

public interface IUdapDbContext : IDisposable
{
    DbSet<Duende.IdentityServer.EntityFramework.Entities.Client> Clients { get; set; }
    DbSet<Anchor> Anchors { get; set; }
    DbSet<Intermediate> IntermediateCertificates { get; set; }
    DbSet<Community> Communities { get; set; }
    DbSet<Certification> Certifications { get; set; }
    DbSet<TieredClient> TieredClients { get; set; }
}

public class UdapDbContext : UdapDbContext<UdapDbContext>
{
    public UdapDbContext(DbContextOptions<UdapDbContext> options)
        : base(options)
    {
    }

    public UdapDbContext(DbContextOptions<UdapDbContext> options, bool migrateClientTables = false) 
        : base(options, migrateClientTables)
    {
    }
}

public class UdapDbContext<TContext> : DbContext, IUdapDbAdminContext, IUdapDbContext, IDataProtectionKeyContext
    where TContext : DbContext, IUdapDbAdminContext, IUdapDbContext
{
    private bool _migrateClientTables;

    /// <summary>
    /// The udap store options.
    /// Overrides ConfigurationStoreOptions.
    /// </summary>
    public UdapConfigurationStoreOptions? UdapStoreOptions { get; set; }


    public DbSet<Anchor> Anchors { get; set; } = null!;
    public DbSet<Intermediate> IntermediateCertificates { get; set; } = null!;

    public DbSet<Duende.IdentityServer.EntityFramework.Entities.Client> Clients { get; set; } = null!;
    public DbSet<Community> Communities { get; set; } = null!;
    public DbSet<Certification> Certifications { get; set; } = null!;
    public DbSet<TieredClient> TieredClients { get; set; } = null!;
    public DbSet<DataProtectionKey> DataProtectionKeys { get; set; } = null!;

    public UdapDbContext(DbContextOptions<TContext> options, bool migrateClientTables = false) : base(options)
    {
        _migrateClientTables = migrateClientTables;
        UdapStoreOptions = this.GetService<UdapConfigurationStoreOptions>();
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        if (UdapStoreOptions is null)
        {
            UdapStoreOptions = this.GetService<UdapConfigurationStoreOptions>();

            if (UdapStoreOptions is null)
            {
                throw new ArgumentNullException(nameof(UdapStoreOptions), "UdapConfigurationStoreOptions must be configured in the DI system.");
            }
        }
        modelBuilder.ConfigureUdapContext(UdapStoreOptions);

        //
        // Need these mappings to correct things like the table names
        //
        // modelBuilder.ConfigureClientContext(UdapStoreOptions);
        // modelBuilder.ConfigureResourcesContext(UdapStoreOptions);
        // modelBuilder.ConfigureIdentityProviderContext(UdapStoreOptions);

        //
        // Reference to DbSet<Client> builds the schema of all Clients table related entities.  
        // Do not want to own the ConfigurationDbContext from Identity Server, so exclude them
        // from EF migration.
        //

        if (!_migrateClientTables)
        {
            modelBuilder.Entity<Duende.IdentityServer.EntityFramework.Entities.Client>().ToTable("Clients", t => t.ExcludeFromMigrations());
            modelBuilder.Entity<ClientClaim>().ToTable("ClientClaims", t => t.ExcludeFromMigrations());
            modelBuilder.Entity<ClientCorsOrigin>().ToTable("ClientCorsOrigins", t => t.ExcludeFromMigrations());
            modelBuilder.Entity<ClientGrantType>().ToTable("ClientGrantTypes", t => t.ExcludeFromMigrations());
            modelBuilder.Entity<ClientIdPRestriction>().ToTable("ClientIdPRestrictions", t => t.ExcludeFromMigrations());
            modelBuilder.Entity<ClientPostLogoutRedirectUri>().ToTable("ClientPostLogoutRedirectUris", t => t.ExcludeFromMigrations());
            modelBuilder.Entity<ClientProperty>().ToTable("ClientProperties", t => t.ExcludeFromMigrations());
            modelBuilder.Entity<ClientRedirectUri>().ToTable("ClientRedirectUris", t => t.ExcludeFromMigrations());
            modelBuilder.Entity<ClientSecret>().ToTable("ClientSecrets", t => t.ExcludeFromMigrations());
            modelBuilder.Entity<ClientScope>().ToTable("ClientScopes", t => t.ExcludeFromMigrations());
        }
        else
        {
            modelBuilder.Entity<Duende.IdentityServer.EntityFramework.Entities.Client>().ToTable("Clients");
            modelBuilder.Entity<ClientClaim>().ToTable("ClientClaims");
            modelBuilder.Entity<ClientCorsOrigin>().ToTable("ClientCorsOrigins");
            modelBuilder.Entity<ClientGrantType>().ToTable("ClientGrantTypes");
            modelBuilder.Entity<ClientIdPRestriction>().ToTable("ClientIdPRestrictions");
            modelBuilder.Entity<ClientPostLogoutRedirectUri>().ToTable("ClientPostLogoutRedirectUris");
            modelBuilder.Entity<ClientProperty>().ToTable("ClientProperties");
            modelBuilder.Entity<ClientRedirectUri>().ToTable("ClientRedirectUris");
            modelBuilder.Entity<ClientSecret>().ToTable("ClientSecrets");
            modelBuilder.Entity<ClientScope>().ToTable("ClientScopes");
        }

        base.OnModelCreating(modelBuilder);
    }
}

