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

namespace UdapServer.Tests;

public class StorageFixture<TClass, TDbContext, TStoreOption> : IClassFixture<TestDatabaseProvider<TDbContext>>
    where TDbContext : DbContext
    where TStoreOption : class
{
    public static readonly TheoryData<DbContextOptions<TDbContext>> TestDatabaseProviders;
    protected static readonly TStoreOption StoreOptions = Activator.CreateInstance<TStoreOption>();

    static StorageFixture()
    {
        TestDatabaseProviders = new TheoryData<DbContextOptions<TDbContext>>
        {
            // DatabaseProviderBuilder.BuildInMemory<TDbContext, TStoreOption>(typeof(TClass).Name, StoreOptions),
            DatabaseProviderBuilder.BuildSqlite<TDbContext, TStoreOption>(typeof(TClass).Name, StoreOptions)
            // DatabaseProviderBuilder.BuildLocalDb<TDbContext, TStoreOption>(typeof(TClass).Name, StoreOptions)
        };
    }

    protected StorageFixture(TestDatabaseProvider<TDbContext> fixture)
    {
        var optionsList = new List<DbContextOptions<TDbContext>>();

        foreach (var options in TestDatabaseProviders)
        {
            optionsList.Add((DbContextOptions<TDbContext>)options);
        }

        fixture.Options = optionsList;
    }
}