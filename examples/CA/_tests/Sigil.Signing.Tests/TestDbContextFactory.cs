#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.EntityFrameworkCore;
using Sigil.Common.Data;

namespace Sigil.Signing.Tests;

public sealed class TestDbContextFactory : IDbContextFactory<SigilDbContext>
{
    private readonly DbContextOptions<SigilDbContext> _options;

    public TestDbContextFactory(DbContextOptions<SigilDbContext>? options = null)
    {
        _options = options ?? new DbContextOptionsBuilder<SigilDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        using var db = new SigilDbContext(_options);
        db.Database.EnsureCreated();
    }

    public SigilDbContext CreateDbContext() => new(_options);
}
