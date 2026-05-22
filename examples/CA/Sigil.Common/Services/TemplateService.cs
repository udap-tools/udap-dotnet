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
using Sigil.Common.ViewModels;

namespace Sigil.Common.Services;

public class TemplateService
{
    private readonly IDbContextFactory<SigilDbContext> _dbFactory;
    private readonly ILogger<TemplateService> _logger;

    public TemplateService(
        IDbContextFactory<SigilDbContext> dbFactory,
        ILogger<TemplateService> logger)
    {
        _dbFactory = dbFactory;
        _logger = logger;
    }

    public async Task<List<CertificateTemplate>> GetAllAsync(CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        return await db.CertificateTemplates
            .OrderByDescending(t => t.IsPreset)
            .ThenBy(t => t.CertificateType)
            .ThenBy(t => t.Name)
            .ToListAsync(ct);
    }

    public async Task<CertificateTemplate> SaveAsync(CertificateTemplate entity, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        if (entity.Id > 0)
        {
            var existing = await db.CertificateTemplates.FindAsync([entity.Id], ct);
            if (existing != null)
            {
                db.Entry(existing).CurrentValues.SetValues(entity);
                await db.SaveChangesAsync(ct);
                return existing;
            }
        }

        db.CertificateTemplates.Add(entity);
        await db.SaveChangesAsync(ct);
        return entity;
    }

    public async Task UpdateSanListsAsync(int templateId, HashSet<int> sanListIds, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var template = await db.CertificateTemplates
            .Include(t => t.SanLists)
            .FirstOrDefaultAsync(t => t.Id == templateId, ct);
        if (template == null) return;

        template.SanLists.Clear();
        if (sanListIds.Count > 0)
        {
            var sanLists = await db.SanLists
                .Where(s => sanListIds.Contains(s.Id))
                .ToListAsync(ct);
            foreach (var sl in sanLists)
                template.SanLists.Add(sl);
        }

        await db.SaveChangesAsync(ct);
    }

    public async Task<List<CertificateTemplate>> GetAllWithSanListsAsync(CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        return await db.CertificateTemplates
            .Include(t => t.SanLists)
            .OrderByDescending(t => t.IsPreset)
            .ThenBy(t => t.CertificateType)
            .ThenBy(t => t.Name)
            .ToListAsync(ct);
    }

    public async Task DeleteAsync(int id, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var entity = await db.CertificateTemplates.FindAsync([id], ct);
        if (entity != null && !entity.IsPreset)
        {
            db.CertificateTemplates.Remove(entity);
            await db.SaveChangesAsync(ct);
        }
    }

    public async Task<List<ImpactItem>> GetDeletionImpactAsync(int templateId, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var impacts = new List<ImpactItem>();

        var issuedCount = await db.IssuedCertificates.CountAsync(i => i.TemplateId == templateId, ct);
        if (issuedCount > 0)
            impacts.Add(new ImpactItem(issuedCount, "issued certificate(s) reference this template", ImpactSeverity.Info));

        return impacts;
    }
}
