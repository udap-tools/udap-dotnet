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

namespace Sigil.Common.Services.Jobs;

/// <summary>
/// Scans all non-archived CA certificates and regenerates CRLs that are approaching
/// or past their NextUpdate. Intended to be invoked by Hangfire as a recurring job.
/// </summary>
public class CrlAutoRenewalJob
{
    private readonly IDbContextFactory<SigilDbContext> _dbFactory;
    private readonly CrlGenerationService _crlGenerationService;
    private readonly ILogger<CrlAutoRenewalJob> _logger;

    public CrlAutoRenewalJob(
        IDbContextFactory<SigilDbContext> dbFactory,
        CrlGenerationService crlGenerationService,
        ILogger<CrlAutoRenewalJob> logger)
    {
        _dbFactory = dbFactory;
        _crlGenerationService = crlGenerationService;
        _logger = logger;
    }

    public async Task ExecuteAsync(CancellationToken ct)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        var cas = await db.CaCertificates
            .Where(ca => !ca.IsArchived)
            .Include(ca => ca.Crls.Where(c => !c.IsArchived))
            .ToListAsync(ct);

        foreach (var ca in cas)
        {
            // Only generate CRLs for CAs that have a private key available
            if (ca.EncryptedPfxBytes == null && string.IsNullOrEmpty(ca.StoreProviderHint))
                continue;

            var latestCrl = ca.Crls
                .OrderByDescending(c => c.CrlNumber)
                .FirstOrDefault();

            // Renew if no CRL exists or NextUpdate is within 24 hours
            var needsRenewal = latestCrl == null
                || latestCrl.NextUpdate <= DateTime.UtcNow.AddHours(24);

            if (!needsRenewal)
            {
                _logger.LogDebug("CRL for CA '{CaName}' (ID {CaId}) is current, republishing to filesystem", ca.Name, ca.Id);
                await _crlGenerationService.PublishCrlAsync(ca.Id, ct);
                continue;
            }

            _logger.LogInformation("CRL renewal needed for CA '{CaName}' (ID {CaId})", ca.Name, ca.Id);

            var result = await _crlGenerationService.GenerateCrlAsync(ca.Id, ct: ct);

            if (result.IsSuccess)
            {
                _logger.LogInformation(
                    "Auto-renewed CRL for CA '{CaName}', CRL #{CrlNumber}, {RevokedCount} revocations, next update {NextUpdate}",
                    ca.Name, result.CrlNumber, result.RevokedCount, result.NextUpdate);
            }
            else
            {
                _logger.LogWarning(
                    "CRL auto-renewal failed for CA '{CaName}': {Error}. Republishing existing CRL if available.", ca.Name, result.Error);
                await _crlGenerationService.PublishCrlAsync(ca.Id, ct);
            }
        }
    }
}
