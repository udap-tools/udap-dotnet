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
using Microsoft.Extensions.Logging;
using Sigil.Common.Data;
using Sigil.Common.Data.Entities;

namespace Sigil.Common.Services;

public class SanListService
{
    private readonly IDbContextFactory<SigilDbContext> _dbFactory;
    private readonly ILogger<SanListService> _logger;

    public SanListService(
        IDbContextFactory<SigilDbContext> dbFactory,
        ILogger<SanListService> logger)
    {
        _dbFactory = dbFactory;
        _logger = logger;
    }

    public async Task<List<SanList>> GetAllAsync(CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        return await db.SanLists
            .Include(s => s.Templates)
            .OrderBy(s => s.Name)
            .ToListAsync(ct);
    }

    public async Task<SanList> SaveAsync(SanList entity, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        if (entity.Id > 0)
        {
            var existing = await db.SanLists.FindAsync([entity.Id], ct);
            if (existing != null)
            {
                existing.Name = entity.Name;
                existing.Description = entity.Description;
                existing.Items = entity.Items;
                await db.SaveChangesAsync(ct);
                return existing;
            }
        }

        db.SanLists.Add(entity);
        await db.SaveChangesAsync(ct);
        return entity;
    }

    public async Task DeleteAsync(int id, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var entity = await db.SanLists.FindAsync([id], ct);
        if (entity != null)
        {
            db.SanLists.Remove(entity);
            await db.SaveChangesAsync(ct);
        }
    }
}
