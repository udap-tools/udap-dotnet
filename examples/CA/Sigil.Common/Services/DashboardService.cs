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
using Sigil.Common.ViewModels;

namespace Sigil.Common.Services;

public class DashboardService
{
    private readonly IDbContextFactory<SigilDbContext> _dbFactory;
    private readonly ILogger<DashboardService> _logger;

    public DashboardService(
        IDbContextFactory<SigilDbContext> dbFactory,
        ILogger<DashboardService> logger)
    {
        _dbFactory = dbFactory;
        _logger = logger;
    }

    public async Task<DashboardData> GetDashboardAsync(CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var now = DateTime.UtcNow;
        var expiringSoonThreshold = now.AddDays(60);

        var data = new DashboardData
        {
            TrustDomainCount = await db.TrustDomains.CountAsync(ct),
            CaCertCount = await db.CaCertificates.CountAsync(ct),
            IssuedCertCount = await db.IssuedCertificates.CountAsync(ct),
            TemplateCount = await db.CertificateTemplates.CountAsync(ct),
            RevokedCertCount = await db.IssuedCertificates.CountAsync(i => i.IsRevoked, ct)
        };

        data.TrustDomainSummaries = await db.TrustDomains
            .Select(c => new TrustDomainSummary
            {
                Id = c.Id,
                Name = c.Name,
                CaCount = c.CaCertificates.Count,
                IssuedCount = c.CaCertificates.SelectMany(ca => ca.IssuedCertificates).Count(),
                ExpiredCaCount = c.CaCertificates.Count(ca => ca.NotAfter <= now),
                ExpiredIssuedCount = c.CaCertificates
                    .SelectMany(ca => ca.IssuedCertificates)
                    .Count(i => i.NotAfter <= now),
                ExpiringCaCount = c.CaCertificates
                    .Count(ca => ca.NotAfter > now && ca.NotAfter <= expiringSoonThreshold),
                ExpiringIssuedCount = c.CaCertificates
                    .SelectMany(ca => ca.IssuedCertificates)
                    .Count(i => i.NotAfter > now && i.NotAfter <= expiringSoonThreshold),
                OverdueCrlCount = c.CaCertificates
                    .SelectMany(ca => ca.Crls)
                    .Count(crl => crl.NextUpdate < now),
            })
            .OrderBy(c => c.Name)
            .ToListAsync(ct);

        var expiringCas = await db.CaCertificates
            .Where(c => c.NotAfter > now && c.NotAfter <= expiringSoonThreshold && !c.IsArchived)
            .Select(c => new CertRow
            {
                Name = c.Name,
                Subject = c.Subject,
                Thumbprint = c.Thumbprint,
                NotAfter = c.NotAfter,
                TrustDomainName = c.TrustDomain.Name,
                TrustDomainId = c.TrustDomainId,
                CertType = "CA",
                DaysRemaining = (int)(c.NotAfter - now).TotalDays
            })
            .ToListAsync(ct);

        var expiringIssued = await db.IssuedCertificates
            .Where(i => i.NotAfter > now && i.NotAfter <= expiringSoonThreshold && !i.IsRevoked && !i.IsArchived)
            .Select(i => new CertRow
            {
                Name = i.Name,
                Subject = i.Subject,
                Thumbprint = i.Thumbprint,
                NotAfter = i.NotAfter,
                TrustDomainName = i.IssuingCaCertificate.TrustDomain.Name,
                TrustDomainId = i.IssuingCaCertificate.TrustDomainId,
                CertType = "End Entity",
                DaysRemaining = (int)(i.NotAfter - now).TotalDays
            })
            .ToListAsync(ct);

        data.ExpiringCerts = expiringCas.Concat(expiringIssued)
            .OrderBy(c => c.NotAfter)
            .ToList();

        var expiredCas = await db.CaCertificates
            .Where(c => c.NotAfter <= now && !c.IsArchived)
            .Select(c => new CertRow
            {
                Name = c.Name,
                Subject = c.Subject,
                Thumbprint = c.Thumbprint,
                NotAfter = c.NotAfter,
                TrustDomainName = c.TrustDomain.Name,
                TrustDomainId = c.TrustDomainId,
                CertType = "CA",
                DaysRemaining = (int)(c.NotAfter - now).TotalDays
            })
            .ToListAsync(ct);

        var expiredIssued = await db.IssuedCertificates
            .Where(i => i.NotAfter <= now && !i.IsRevoked && !i.IsArchived)
            .Select(i => new CertRow
            {
                Name = i.Name,
                Subject = i.Subject,
                Thumbprint = i.Thumbprint,
                NotAfter = i.NotAfter,
                TrustDomainName = i.IssuingCaCertificate.TrustDomain.Name,
                TrustDomainId = i.IssuingCaCertificate.TrustDomainId,
                CertType = "End Entity",
                DaysRemaining = (int)(i.NotAfter - now).TotalDays
            })
            .ToListAsync(ct);

        data.ExpiredCerts = expiredCas.Concat(expiredIssued)
            .OrderByDescending(c => c.NotAfter)
            .Take(20)
            .ToList();

        data.OverdueCrls = await db.Crls
            .Where(c => c.NextUpdate < now && !c.IsArchived)
            .Select(c => new CrlRow
            {
                CrlNumber = c.CrlNumber,
                CaName = c.CaCertificate.Name,
                CaThumbprint = c.CaCertificate.Thumbprint,
                TrustDomainName = c.CaCertificate.TrustDomain.Name,
                TrustDomainId = c.CaCertificate.TrustDomainId,
                NextUpdate = c.NextUpdate,
                DaysOverdue = (int)(now - c.NextUpdate).TotalDays
            })
            .OrderByDescending(c => c.DaysOverdue)
            .ToListAsync(ct);

        return data;
    }
}
