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


public class TestDatabaseProvider<T> : IDisposable where T : DbContext
{
    public List<DbContextOptions<T>>? Options;

    public void Dispose()
    {
        if (Options != null) // null check since fixtures are created even when tests are skipped
        {
            foreach (var option in Options.ToList())
            {
                using var context = (T)Activator.CreateInstance(typeof(T), option)!;
                context!.Database.EnsureDeleted();
            }
        }
    }
}