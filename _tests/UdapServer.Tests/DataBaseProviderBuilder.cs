#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion



//
// This code was inspired from Duende Identity Server Tests
//

// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.


using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace UdapServer.Tests;

/// <summary>
/// Pick you database provider
/// </summary>
public class DatabaseProviderBuilder
{
    public static DbContextOptions<TDbContext> BuildInMemory<TDbContext, TStoreOptions>(string name,
        TStoreOptions storeOptions)
        where TDbContext : DbContext
        where TStoreOptions : class
    
    {
        var serviceCollection = new ServiceCollection();
        serviceCollection.AddSingleton(storeOptions);
    
        var builder = new DbContextOptionsBuilder<TDbContext>();
        builder.UseInMemoryDatabase(name);
        builder.UseApplicationServiceProvider(serviceCollection.BuildServiceProvider());
        return builder.Options;
    }

    public static DbContextOptions<TDbContext> BuildSqlite<TDbContext, TStoreOptions>(string name,
        TStoreOptions storeOptions)
        where TDbContext : DbContext
        where TStoreOptions : class
    {
        var serviceCollection = new ServiceCollection();
        serviceCollection.AddSingleton(storeOptions);

        var builder = new DbContextOptionsBuilder<TDbContext>();
        builder.UseSqlite($"Data Source=Udap.Idp.db.{name}.db");
        builder.UseApplicationServiceProvider(serviceCollection.BuildServiceProvider());

        return builder.Options;
    }

    public static DbContextOptions<TDbContext> BuildLocalDb<TDbContext, TStoreOptions>(string name,
        TStoreOptions storeOptions)
        where TDbContext : DbContext
        where TStoreOptions : class
    {
        var serviceCollection = new ServiceCollection();
        serviceCollection.AddSingleton(storeOptions);

        var builder = new DbContextOptionsBuilder<TDbContext>();
        builder.UseSqlServer(
            $@"Data Source=(LocalDb)\MSSQLLocalDB;database=Udap.Idp.db.{name};trusted_connection=yes;");
        builder.UseApplicationServiceProvider(serviceCollection.BuildServiceProvider());
        return builder.Options;
    }
}