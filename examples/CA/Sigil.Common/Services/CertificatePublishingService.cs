#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Sigil.Common.Data;
using Sigil.Common.Services.Jobs;

namespace Sigil.Common.Services;

public record PublishResult(bool Success, int PublishedCount = 0, string? Error = null);

public class CertificatePublishingService
{
    private readonly IDbContextFactory<SigilDbContext> _dbFactory;
    private readonly ILogger<CertificatePublishingService> _logger;
    private readonly CrlGenerationService _crlGenService;

    public CertificatePublishingService(
        IDbContextFactory<SigilDbContext> dbFactory,
        ILogger<CertificatePublishingService> logger,
        CrlGenerationService crlGenService)
    {
        _dbFactory = dbFactory;
        _logger = logger;
        _crlGenService = crlGenService;
    }

    public async Task<PublishResult> PublishAiaCertificateAsync(int caId, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var ca = await db.CaCertificates.FindAsync([caId], ct);
        if (ca == null)
            return new PublishResult(false, Error: "CA certificate not found.");

        using var cert = X509Certificate2.CreateFromPem(ca.X509CertificatePem);
        var baseUrls = await db.TrustDomainBaseUrls
            .Where(bu => bu.TrustDomainId == ca.TrustDomainId && bu.PublishingBasePath != null)
            .ToListAsync(ct);

        if (baseUrls.Count == 0)
            return new PublishResult(false, Error: "No publishing paths configured on this trust domain's base URLs.");

        var published = 0;
        foreach (var baseUrl in baseUrls)
        {
            if (string.IsNullOrEmpty(baseUrl.PublishingBasePath)) continue;

            var certPath = Path.GetFullPath(Path.Combine(baseUrl.PublishingBasePath, "certs", $"{ca.Name}.cer"));
            var certDir = Path.GetDirectoryName(certPath);
            if (!string.IsNullOrEmpty(certDir))
                Directory.CreateDirectory(certDir);

            var tempPath = certPath + ".tmp";
            await File.WriteAllBytesAsync(tempPath, cert.RawData, ct);
            File.Move(tempPath, certPath, overwrite: true);
            published++;
        }

        return new PublishResult(true, published);
    }

    public async Task EnsureIssuerPublishedAsync(int issuingCaId, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var ca = await db.CaCertificates.FindAsync([issuingCaId], ct);
        if (ca == null) return;

        var baseUrls = await db.TrustDomainBaseUrls
            .Where(bu => bu.TrustDomainId == ca.TrustDomainId && bu.PublishingBasePath != null)
            .ToListAsync(ct);

        if (baseUrls.Count == 0) return;

        using var cert = X509Certificate2.CreateFromPem(ca.X509CertificatePem);

        foreach (var baseUrl in baseUrls)
        {
            if (string.IsNullOrEmpty(baseUrl.PublishingBasePath)) continue;

            var certPath = Path.GetFullPath(Path.Combine(baseUrl.PublishingBasePath, "certs", $"{ca.Name}.cer"));
            if (!File.Exists(certPath))
            {
                var certDir = Path.GetDirectoryName(certPath);
                if (!string.IsNullOrEmpty(certDir))
                    Directory.CreateDirectory(certDir);

                var tempPath = certPath + ".tmp";
                await File.WriteAllBytesAsync(tempPath, cert.RawData, ct);
                File.Move(tempPath, certPath, overwrite: true);
            }

            var crlPath = Path.GetFullPath(Path.Combine(baseUrl.PublishingBasePath, "crls", $"{ca.Name}.crl"));
            if (!File.Exists(crlPath))
            {
                await _crlGenService.GenerateCrlAsync(issuingCaId);
            }
        }
    }
}
