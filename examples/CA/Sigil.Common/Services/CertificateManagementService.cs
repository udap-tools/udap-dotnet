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
using Sigil.Common.Data.Entities;
using Sigil.Common.Services.Jobs;
using Sigil.Common.Validators;
using Sigil.Common.ViewModels;

namespace Sigil.Common.Services;

public record RenameResult(bool Success, string? Error = null);
public record ArchiveResult(bool Success, string? Error = null);
public record DeleteResult(bool Success, string? Error = null);
public record MoveResult(bool Success, string? Error = null);
public record RevokeResult(bool Success, int? CrlNumber = null, int? RevokedCount = null, string? Error = null);

public class CertificateNodeDetails
{
    public string? Pem { get; set; }
    public bool HasPrivateKey { get; set; }
    public bool HasRemoteKey { get; set; }
    public bool AutoRenew { get; set; } = true;
    public string? SubjectAltNames { get; set; }
}

public class TrustDomainTreeData
{
    public string TrustDomainName { get; set; } = string.Empty;
    public List<CertificateChainNodeViewModel> TreeNodes { get; set; } = new();
    public Dictionary<string, ChainValidationResult> Validations { get; set; } = new();
}

public class CertificateManagementService
{
    private readonly IDbContextFactory<SigilDbContext> _dbFactory;
    private readonly ILogger<CertificateManagementService> _logger;
    private readonly ChainValidationService _chainValidator;
    private readonly CrlGenerationService _crlGenService;
    private readonly IssuanceValidator _validator;

    public CertificateManagementService(
        IDbContextFactory<SigilDbContext> dbFactory,
        ILogger<CertificateManagementService> logger,
        ChainValidationService chainValidator,
        CrlGenerationService crlGenService,
        IssuanceValidator? validator = null)
    {
        _dbFactory = dbFactory;
        _logger = logger;
        _chainValidator = chainValidator;
        _crlGenService = crlGenService;
        _validator = validator ?? new IssuanceValidator();
    }

    public async Task<TrustDomainTreeData> GetTrustDomainTreeAsync(int trustDomainId, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        var trustDomain = await db.TrustDomains.FindAsync([trustDomainId], ct);
        var trustDomainName = trustDomain?.Name ?? "Unknown";

        var caCerts = await db.CaCertificates
            .Where(ca => ca.TrustDomainId == trustDomainId && !ca.IsArchived)
            .Include(ca => ca.IssuedCertificates.Where(i => !i.IsArchived))
            .Include(ca => ca.Crls.Where(c => !c.IsArchived))
            .OrderBy(ca => ca.Name)
            .ToListAsync(ct);

        var validations = await _chainValidator.ValidateTrustDomainAsync(trustDomainId);
        var supersededCaIds = _validator.FindSupersededCaIds(caCerts);

        var treeNodes = caCerts
            .Where(ca => ca.ParentId == null)
            .Select(rootCa => BuildTreeNode(rootCa, caCerts, validations, supersededCaIds))
            .ToList();

        return new TrustDomainTreeData
        {
            TrustDomainName = trustDomainName,
            TreeNodes = treeNodes,
            Validations = validations
        };
    }

    public async Task<CertificateNodeDetails> GetNodeDetailsAsync(
        int id, string entityType, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var details = new CertificateNodeDetails();

        if (entityType == "CaCertificate")
        {
            var ca = await db.CaCertificates.FindAsync([id], ct);
            details.Pem = ca?.X509CertificatePem;
            details.HasPrivateKey = ca?.EncryptedPfxBytes != null;
            details.HasRemoteKey = !string.IsNullOrEmpty(ca?.StoreProviderHint);
            details.AutoRenew = ca?.AutoRenew ?? true;
        }
        else
        {
            var issued = await db.IssuedCertificates.FindAsync([id], ct);
            details.Pem = issued?.X509CertificatePem;
            details.SubjectAltNames = issued?.SubjectAltNames;
            details.HasPrivateKey = issued?.EncryptedPfxBytes != null;
            details.AutoRenew = issued?.AutoRenew ?? true;
        }

        return details;
    }

    public async Task<RenameResult> RenameAsync(
        int id, string entityType, string newName, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(newName))
            return new RenameResult(false, "Name cannot be empty.");

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var trimmed = newName.Trim();

        if (entityType == "CaCertificate")
        {
            var ca = await db.CaCertificates.FindAsync([id], ct);
            if (ca == null) return new RenameResult(false, "Certificate not found.");
            ca.Name = trimmed;
        }
        else if (entityType == "IssuedCertificate")
        {
            var issued = await db.IssuedCertificates.FindAsync([id], ct);
            if (issued == null) return new RenameResult(false, "Certificate not found.");
            issued.Name = trimmed;
        }
        else
        {
            return new RenameResult(false, "Invalid entity type.");
        }

        await db.SaveChangesAsync(ct);
        return new RenameResult(true);
    }

    public async Task SetAutoRenewAsync(
        int id, string entityType, bool enabled, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        if (entityType == "CaCertificate")
        {
            var ca = await db.CaCertificates.FindAsync([id], ct);
            if (ca != null)
            {
                ca.AutoRenew = enabled;
                await db.SaveChangesAsync(ct);
            }
        }
        else if (entityType == "IssuedCertificate")
        {
            var issued = await db.IssuedCertificates.FindAsync([id], ct);
            if (issued != null)
            {
                issued.AutoRenew = enabled;
                await db.SaveChangesAsync(ct);
            }
        }
    }

    public async Task<ArchiveResult> ArchiveAsync(
        int id, string entityType, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var now = DateTime.UtcNow;

        switch (entityType)
        {
            case "CaCertificate":
                var ca = await db.CaCertificates.FindAsync([id], ct);
                if (ca == null) return new ArchiveResult(false, "Certificate not found.");
                ca.IsArchived = true;
                ca.ArchivedAt = now;
                break;
            case "IssuedCertificate":
                var issued = await db.IssuedCertificates.FindAsync([id], ct);
                if (issued == null) return new ArchiveResult(false, "Certificate not found.");
                issued.IsArchived = true;
                issued.ArchivedAt = now;
                break;
            case "Crl":
                var crl = await db.Crls.FindAsync([id], ct);
                if (crl == null) return new ArchiveResult(false, "CRL not found.");
                crl.IsArchived = true;
                crl.ArchivedAt = now;
                break;
            default:
                return new ArchiveResult(false, "Invalid entity type.");
        }

        await db.SaveChangesAsync(ct);
        return new ArchiveResult(true);
    }

    public async Task<DeleteResult> DeleteAsync(
        int id, string entityType,
        Func<string?, Task>? deleteRemoteKeyAsync = null,
        CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        switch (entityType)
        {
            case "CaCertificate":
                var ca = await db.CaCertificates
                    .Include(c => c.IssuedCertificates)
                    .Include(c => c.Crls).ThenInclude(c => c.Revocations)
                    .Include(c => c.Children)
                    .FirstOrDefaultAsync(c => c.Id == id, ct);
                if (ca == null)
                    return new DeleteResult(false, "Certificate not found.");
                if (ca.Children.Count > 0 || ca.IssuedCertificates.Count > 0)
                    return new DeleteResult(false,
                        $"Cannot delete: it has {ca.Children.Count} child CA(s) and {ca.IssuedCertificates.Count} issued cert(s). Delete or move them first.");
                if (deleteRemoteKeyAsync != null)
                    await deleteRemoteKeyAsync(ca.StoreProviderHint);
                foreach (var crl in ca.Crls.ToList())
                {
                    db.CertificateRevocations.RemoveRange(crl.Revocations);
                    db.Crls.Remove(crl);
                }
                db.CaCertificates.Remove(ca);
                break;
            case "IssuedCertificate":
                var issued = await db.IssuedCertificates.FindAsync([id], ct);
                if (issued == null)
                    return new DeleteResult(false, "Certificate not found.");
                if (deleteRemoteKeyAsync != null)
                    await deleteRemoteKeyAsync(issued.StoreProviderHint);
                db.IssuedCertificates.Remove(issued);
                break;
            case "Crl":
                var crl2 = await db.Crls
                    .Include(c => c.Revocations)
                    .FirstOrDefaultAsync(c => c.Id == id, ct);
                if (crl2 == null)
                    return new DeleteResult(false, "CRL not found.");
                db.CertificateRevocations.RemoveRange(crl2.Revocations);
                db.Crls.Remove(crl2);
                break;
            default:
                return new DeleteResult(false, "Invalid entity type.");
        }

        await db.SaveChangesAsync(ct);
        return new DeleteResult(true);
    }

    public async Task<MoveResult> MoveAsync(
        int id, string entityType, int targetTrustDomainId, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        switch (entityType)
        {
            case "CaCertificate":
                var ca = await db.CaCertificates.FindAsync([id], ct);
                if (ca == null) return new MoveResult(false, "Certificate not found.");
                ca.TrustDomainId = targetTrustDomainId;
                ca.ParentId = null;
                break;
            case "IssuedCertificate":
                var issued = await db.IssuedCertificates
                    .Include(i => i.IssuingCaCertificate)
                    .FirstOrDefaultAsync(i => i.Id == id, ct);
                if (issued == null) return new MoveResult(false, "Certificate not found.");

                var newIssuingCaId = await FindMatchingCaInTrustDomainAsync(db, issued.X509CertificatePem, targetTrustDomainId, ct);

                if (newIssuingCaId == null)
                {
                    var fallbackCa = await db.CaCertificates
                        .Where(c => c.TrustDomainId == targetTrustDomainId)
                        .OrderByDescending(c => c.ParentId)
                        .FirstOrDefaultAsync(ct);
                    newIssuingCaId = fallbackCa?.Id;
                }

                if (newIssuingCaId == null)
                    return new MoveResult(false, "Target trust domain has no CA certificates.");

                issued.IssuingCaCertificateId = newIssuingCaId.Value;
                break;
            default:
                return new MoveResult(false, "Invalid entity type.");
        }

        await db.SaveChangesAsync(ct);
        return new MoveResult(true);
    }

    public async Task<RevokeResult> RevokeAsync(
        int id, string entityType, int reasonCode, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var now = DateTime.UtcNow;
        int? issuingCaId = null;

        if (entityType == "CaCertificate")
        {
            var ca = await db.CaCertificates.FindAsync([id], ct);
            if (ca == null) return new RevokeResult(false, Error: "Certificate not found.");
            ca.IsRevoked = true;
            ca.RevokedAt = now;
            ca.RevocationReason = reasonCode;
            issuingCaId = ca.ParentId;
            await db.SaveChangesAsync(ct);
        }
        else
        {
            var issued = await db.IssuedCertificates.FindAsync([id], ct);
            if (issued == null) return new RevokeResult(false, Error: "Certificate not found.");
            issued.IsRevoked = true;
            issued.RevokedAt = now;
            issued.RevocationReason = reasonCode;
            issuingCaId = issued.IssuingCaCertificateId;
            await db.SaveChangesAsync(ct);
        }

        if (issuingCaId.HasValue)
        {
            var crlResult = await _crlGenService.GenerateCrlAsync(issuingCaId.Value);
            if (crlResult.IsSuccess)
                return new RevokeResult(true, CrlNumber: (int)crlResult.CrlNumber, RevokedCount: crlResult.RevokedCount);
            else
                return new RevokeResult(true, Error: $"CRL regeneration failed: {crlResult.Error}");
        }

        return new RevokeResult(true);
    }

    public async Task<int?> FindCaBySkiAsync(int trustDomainId, string authorityKeyIdentifier, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        return await FindCaBySkiInternalAsync(db, trustDomainId, authorityKeyIdentifier, ct);
    }

    public async Task<int?> FindCaByDnAndSignatureAsync(int trustDomainId, X509Certificate2 cert, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        return await FindCaByDnAndSignatureInternalAsync(db, trustDomainId, cert, ct);
    }

    public static async Task<int?> FindCaBySkiInternalAsync(
        SigilDbContext db, int trustDomainId, string authorityKeyIdentifier, CancellationToken ct = default)
    {
        var cas = await db.CaCertificates
            .Where(ca => ca.TrustDomainId == trustDomainId)
            .ToListAsync(ct);

        foreach (var ca in cas)
        {
            try
            {
                using var caCert = X509Certificate2.CreateFromPem(ca.X509CertificatePem);
                var skiExt = caCert.Extensions["2.5.29.14"];
                if (skiExt != null)
                {
                    var ski = new X509SubjectKeyIdentifierExtension(skiExt, skiExt.Critical);
                    if (ski.SubjectKeyIdentifier == authorityKeyIdentifier)
                        return ca.Id;
                }
            }
            catch { }
        }

        return null;
    }

    public static async Task<int?> FindCaByDnAndSignatureInternalAsync(
        SigilDbContext db, int trustDomainId, X509Certificate2 cert, CancellationToken ct = default)
    {
        var cas = await db.CaCertificates
            .Where(ca => ca.TrustDomainId == trustDomainId)
            .ToListAsync(ct);

        var bcParser = new Org.BouncyCastle.X509.X509CertificateParser();
        var bcCert = bcParser.ReadCertificate(cert.RawData);

        foreach (var ca in cas)
        {
            try
            {
                using var caCert = X509Certificate2.CreateFromPem(ca.X509CertificatePem);
                var bcCa = bcParser.ReadCertificate(caCert.RawData);

                if (bcCa.SubjectDN.Equivalent(bcCert.IssuerDN))
                {
                    bcCert.Verify(bcCa.GetPublicKey());
                    return ca.Id;
                }
            }
            catch { }
        }

        return null;
    }

    private static async Task<int?> FindMatchingCaInTrustDomainAsync(
        SigilDbContext db, string? certPem, int targetTrustDomainId, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(certPem)) return null;

        try
        {
            using var cert = X509Certificate2.CreateFromPem(certPem);
            var akiExt = cert.Extensions["2.5.29.35"];
            if (akiExt?.RawData != null && akiExt.RawData.Length >= 6)
            {
                var data = akiExt.RawData;
                if (data[2] == 0x80)
                {
                    var len = data[3];
                    var keyId = new byte[len];
                    Array.Copy(data, 4, keyId, 0, len);
                    var aki = Convert.ToHexString(keyId);

                    return await FindCaBySkiInternalAsync(db, targetTrustDomainId, aki, ct);
                }
            }

            return await FindCaByDnAndSignatureInternalAsync(db, targetTrustDomainId, cert, ct);
        }
        catch
        {
            return null;
        }
    }

    private static CertificateChainNodeViewModel BuildTreeNode(
        CaCertificate ca,
        List<CaCertificate> allCas,
        Dictionary<string, ChainValidationResult> validationResults,
        HashSet<int>? supersededCaIds = null)
    {
        var caStatus = DeriveStatus(ca.Thumbprint, ca.NotAfter, ca.IsRevoked, validationResults);
        var isSuperseded = supersededCaIds?.Contains(ca.Id) == true;

        var node = new CertificateChainNodeViewModel
        {
            Id = ca.Id,
            Name = ca.Name,
            Subject = ca.Subject,
            Thumbprint = ca.Thumbprint,
            NotAfter = ca.NotAfter,
            CertificateRole = ca.ParentId == null ? "RootCA" : "IntermediateCA",
            EntityType = "CaCertificate",
            Status = caStatus,
            IsSuperseded = isSuperseded,
            KeyStorage = !string.IsNullOrEmpty(ca.StoreProviderHint)
                    ? ca.StoreProviderHint[..ca.StoreProviderHint.IndexOf(':')]
                : ca.EncryptedPfxBytes != null ? "local"
                : null,
            KeyIdentifier = !string.IsNullOrEmpty(ca.StoreProviderHint) && ca.StoreProviderHint.Contains(':')
                ? ca.StoreProviderHint[(ca.StoreProviderHint.IndexOf(':') + 1)..]
                : null
        };

        foreach (var child in ca.Children.OrderBy(c => c.Name))
        {
            node.Children.Add(BuildTreeNode(child, allCas, validationResults, supersededCaIds));
        }

        foreach (var issued in ca.IssuedCertificates.OrderBy(i => i.Name))
        {
            var issuedStatus = DeriveStatus(issued.Thumbprint, issued.NotAfter, issued.IsRevoked, validationResults);
            if (isSuperseded && issuedStatus is CertificateStatus.Valid or CertificateStatus.Expiring)
                issuedStatus = CertificateStatus.Stale;

            node.Children.Add(new CertificateChainNodeViewModel
            {
                Id = issued.Id,
                Name = issued.Name,
                Subject = issued.Subject,
                Thumbprint = issued.Thumbprint,
                NotAfter = issued.NotAfter,
                CertificateRole = "EndEntity",
                EntityType = "IssuedCertificate",
                Status = issuedStatus,
                KeyStorage = !string.IsNullOrEmpty(issued.StoreProviderHint)
                        ? issued.StoreProviderHint[..issued.StoreProviderHint.IndexOf(':')]
                    : issued.EncryptedPfxBytes != null ? "local"
                    : null,
                KeyIdentifier = !string.IsNullOrEmpty(issued.StoreProviderHint) && issued.StoreProviderHint.Contains(':')
                    ? issued.StoreProviderHint[(issued.StoreProviderHint.IndexOf(':') + 1)..]
                    : null
            });
        }

        var seenLatestActiveCrl = false;
        foreach (var crl in ca.Crls.OrderByDescending(c => c.CrlNumber))
        {
            var crlStatus = DateTime.UtcNow > crl.NextUpdate
                ? CertificateStatus.Expired
                : DateTime.UtcNow > crl.NextUpdate.AddDays(-7)
                    ? CertificateStatus.Expiring
                    : CertificateStatus.Valid;

            var isLatest = false;
            if (!seenLatestActiveCrl && !crl.IsArchived)
            {
                isLatest = true;
                seenLatestActiveCrl = true;
            }

            node.Children.Add(new CertificateChainNodeViewModel
            {
                Id = crl.Id,
                Name = $"CRL #{crl.CrlNumber}" + (crl.FileName != null ? $" ({crl.FileName})" : ""),
                Subject = ca.Subject,
                NotAfter = crl.NextUpdate,
                CertificateRole = "CRL",
                EntityType = "Crl",
                Status = crlStatus,
                IsLatestCrl = isLatest
            });
        }

        var latestActiveCrl = ca.Crls.Where(c => !c.IsArchived).OrderByDescending(c => c.CrlNumber).FirstOrDefault();
        if (latestActiveCrl != null)
        {
            node.LatestCrlFreshness = DateTime.UtcNow > latestActiveCrl.NextUpdate
                ? CrlFreshness.Expired
                : DateTime.UtcNow > latestActiveCrl.NextUpdate.AddDays(-7)
                    ? CrlFreshness.ExpiringSoon
                    : CrlFreshness.Fresh;
        }

        return node;
    }

    public static CertificateStatus DeriveStatus(
        string thumbprint, DateTime notAfter, bool isRevoked,
        Dictionary<string, ChainValidationResult> validationResults)
    {
        if (isRevoked) return CertificateStatus.Revoked;
        if (DateTime.UtcNow > notAfter) return CertificateStatus.Expired;

        if (validationResults.TryGetValue(thumbprint, out var result))
        {
            if (!result.IsValid)
            {
                var hasRevocation = result.ChainLinks
                    .Any(l => l.CrlStatus == CrlCheckStatus.Revoked);
                if (hasRevocation) return CertificateStatus.Revoked;

                return CertificateStatus.Untrusted;
            }
        }

        if (DateTime.UtcNow > notAfter.AddDays(-30)) return CertificateStatus.Expiring;
        return CertificateStatus.Valid;
    }

    public async Task<List<ImpactItem>> GetCaDeletionImpactAsync(int caId, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var ca = await db.CaCertificates
            .Include(c => c.Children)
            .Include(c => c.IssuedCertificates)
            .Include(c => c.Crls).ThenInclude(c => c.Revocations)
            .FirstOrDefaultAsync(c => c.Id == caId, ct);

        var impacts = new List<ImpactItem>();
        if (ca == null) return impacts;

        if (ca.Children.Count > 0)
            impacts.Add(new ImpactItem(ca.Children.Count, "child CA(s)", ImpactSeverity.Critical));
        if (ca.IssuedCertificates.Count > 0)
            impacts.Add(new ImpactItem(ca.IssuedCertificates.Count, "issued certificate(s)", ImpactSeverity.Critical));
        var nonArchivedCrls = ca.Crls.Count(c => !c.IsArchived);
        if (nonArchivedCrls > 0)
            impacts.Add(new ImpactItem(nonArchivedCrls, "CRL(s)", ImpactSeverity.Warning));
        var revocations = ca.Crls.Sum(c => c.Revocations.Count);
        if (revocations > 0)
            impacts.Add(new ImpactItem(revocations, "revocation record(s)", ImpactSeverity.Info));

        return impacts;
    }

    public async Task<List<ImpactItem>> GetIssuedDeletionImpactAsync(int issuedId, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var issued = await db.IssuedCertificates.FindAsync([issuedId], ct);
        var impacts = new List<ImpactItem>();
        if (issued == null) return impacts;

        if (issued.IsRevoked)
            impacts.Add(new ImpactItem(1, "revocation record will remain on CRL", ImpactSeverity.Info));

        return impacts;
    }

    public async Task<List<ImpactItem>> GetCaRevokeImpactAsync(int caId, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var ca = await db.CaCertificates
            .Include(c => c.Children)
            .Include(c => c.IssuedCertificates)
            .FirstOrDefaultAsync(c => c.Id == caId, ct);

        var impacts = new List<ImpactItem>();
        if (ca == null) return impacts;

        var activeIssued = ca.IssuedCertificates.Count(i => !i.IsRevoked);
        if (activeIssued > 0)
            impacts.Add(new ImpactItem(activeIssued, "issued certificate(s) will become untrusted", ImpactSeverity.Critical));
        if (ca.Children.Count > 0)
            impacts.Add(new ImpactItem(ca.Children.Count, "child CA(s) will become untrusted", ImpactSeverity.Critical));

        return impacts;
    }
}
