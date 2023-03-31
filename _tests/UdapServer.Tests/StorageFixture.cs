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
using Microsoft.Extensions.Configuration;

namespace UdapServer.Tests;

public class StorageFixture<TClass, TDbContext, TStoreOption> : IClassFixture<TestDatabaseProvider<TDbContext>>
    where TDbContext : DbContext
    where TStoreOption : class
{
    public static readonly TheoryData<DbContextOptions<TDbContext>> TestDatabaseProviders;
    protected static readonly TStoreOption StoreOptions = Activator.CreateInstance<TStoreOption>();

    static StorageFixture()
    {
        var config = new ConfigurationBuilder()
            .AddEnvironmentVariables()
            .Build();

        TestDatabaseProviders = new TheoryData<DbContextOptions<TDbContext>>
        {
            DatabaseProviderBuilder.BuildInMemory<TDbContext, TStoreOption>(typeof(TClass).Name, StoreOptions),
            DatabaseProviderBuilder.BuildSqlite<TDbContext, TStoreOption>(typeof(TClass).Name, StoreOptions),
            //DatabaseProviderBuilder.BuildLocalDb<TDbContext, TStoreOption>(typeof(TClass).Name, StoreOptions)
        };
    }

    protected StorageFixture(TestDatabaseProvider<TDbContext> fixture)
    {
        fixture.Options = TestDatabaseProviders.SelectMany(x => x.Select(y => (DbContextOptions<TDbContext>)y))
            .ToList();
    }
}