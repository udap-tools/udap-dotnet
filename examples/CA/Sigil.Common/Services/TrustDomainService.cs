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

public class TrustDomainService
{
    private readonly IDbContextFactory<SigilDbContext> _dbFactory;
    private readonly ILogger<TrustDomainService> _logger;

    public TrustDomainService(
        IDbContextFactory<SigilDbContext> dbFactory,
        ILogger<TrustDomainService> logger)
    {
        _dbFactory = dbFactory;
        _logger = logger;
    }

    public async Task<List<TrustDomainViewModel>> GetAllAsync(CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        return await db.TrustDomains
            .Select(c => new TrustDomainViewModel
            {
                Id = c.Id,
                Name = c.Name,
                Description = c.Description,
                BaseUrls = c.BaseUrls.OrderBy(bu => bu.SortOrder)
                    .Select(bu => new BaseUrlViewModel { Url = bu.Url, PublishingBasePath = bu.PublishingBasePath })
                    .ToList(),
                CrlValidityDays = c.CrlValidityDays,
                Enabled = c.Enabled,
                CreatedAt = c.CreatedAt,
                RootCaCount = c.CaCertificates.Count(ca => ca.ParentId == null),
                TotalCertCount = c.CaCertificates.Count()
                    + c.CaCertificates.SelectMany(ca => ca.IssuedCertificates).Count()
            })
            .OrderBy(c => c.Name)
            .ToListAsync(ct);
    }

    public async Task<TrustDomain> CreateAsync(
        string name,
        string? description,
        List<(string Url, string? PublishingBasePath)> baseUrls,
        int crlValidityDays = 7,
        CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        var trustDomain = new TrustDomain
        {
            Name = name.Trim(),
            Description = string.IsNullOrWhiteSpace(description) ? null : description.Trim(),
            CrlValidityDays = crlValidityDays > 0 ? crlValidityDays : 7,
            Enabled = true
        };

        var sortOrder = 0;
        foreach (var (url, publishPath) in baseUrls)
        {
            if (!string.IsNullOrWhiteSpace(url))
            {
                trustDomain.BaseUrls.Add(new TrustDomainBaseUrl
                {
                    Url = url.Trim().TrimEnd('/'),
                    SortOrder = sortOrder++,
                    PublishingBasePath = string.IsNullOrWhiteSpace(publishPath) ? null : publishPath.Trim()
                });
            }
        }

        db.TrustDomains.Add(trustDomain);
        await db.SaveChangesAsync(ct);
        return trustDomain;
    }

    public async Task UpdateAsync(
        int id,
        string name,
        string? description,
        List<(string Url, string? PublishingBasePath)> baseUrls,
        int crlValidityDays = 7,
        CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var entity = await db.TrustDomains
            .Include(c => c.BaseUrls)
            .FirstOrDefaultAsync(c => c.Id == id, ct);

        if (entity == null) return;

        entity.Name = name.Trim();
        entity.Description = string.IsNullOrWhiteSpace(description) ? null : description.Trim();
        entity.CrlValidityDays = crlValidityDays > 0 ? crlValidityDays : 7;

        entity.BaseUrls.Clear();
        var sortOrder = 0;
        foreach (var (url, publishPath) in baseUrls)
        {
            if (!string.IsNullOrWhiteSpace(url))
            {
                entity.BaseUrls.Add(new TrustDomainBaseUrl
                {
                    Url = url.Trim().TrimEnd('/'),
                    SortOrder = sortOrder++,
                    PublishingBasePath = string.IsNullOrWhiteSpace(publishPath) ? null : publishPath.Trim()
                });
            }
        }

        await db.SaveChangesAsync(ct);
    }

    public async Task DeleteAsync(int id, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var entity = await db.TrustDomains.FindAsync([id], ct);
        if (entity != null)
        {
            db.TrustDomains.Remove(entity);
            await db.SaveChangesAsync(ct);
        }
    }

    public async Task<List<ImpactItem>> GetDeletionImpactAsync(int trustDomainId, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var impacts = new List<ImpactItem>();

        var caCount = await db.CaCertificates.CountAsync(c => c.TrustDomainId == trustDomainId, ct);
        if (caCount > 0)
            impacts.Add(new ImpactItem(caCount, "CA certificate(s)", ImpactSeverity.Critical));

        var issuedCount = await db.IssuedCertificates
            .CountAsync(i => i.IssuingCaCertificate.TrustDomainId == trustDomainId, ct);
        if (issuedCount > 0)
            impacts.Add(new ImpactItem(issuedCount, "issued certificate(s)", ImpactSeverity.Critical));

        var crlCount = await db.Crls
            .CountAsync(c => c.CaCertificate.TrustDomainId == trustDomainId && !c.IsArchived, ct);
        if (crlCount > 0)
            impacts.Add(new ImpactItem(crlCount, "CRL(s)", ImpactSeverity.Warning));

        return impacts;
    }
}
