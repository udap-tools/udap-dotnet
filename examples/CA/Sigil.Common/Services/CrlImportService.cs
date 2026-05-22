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
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Sigil.Common.Data;
using Sigil.Common.Data.Entities;

namespace Sigil.Common.Services;

public class CrlImportService
{
    private readonly IDbContextFactory<SigilDbContext> _dbFactory;
    private readonly ILogger<CrlImportService> _logger;

    public CrlImportService(
        IDbContextFactory<SigilDbContext> dbFactory,
        ILogger<CrlImportService> logger)
    {
        _dbFactory = dbFactory;
        _logger = logger;
    }

    /// <summary>
    /// Imports a CRL file, validates its signature against the issuing CA in the trustDomain,
    /// and stores the CRL entity + revocation entries.
    /// </summary>
    public async Task<CrlImportResult> ImportCrlAsync(
        byte[] crlBytes,
        string fileName,
        int trustDomainId,
        CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        return await ImportCrlAsync(db, crlBytes, fileName, trustDomainId, ct);
    }

    /// <summary>
    /// Imports a CRL using an existing DbContext (for use within a transaction/batch).
    /// </summary>
    public async Task<CrlImportResult> ImportCrlAsync(
        SigilDbContext db,
        byte[] crlBytes,
        string fileName,
        int trustDomainId,
        CancellationToken ct = default)
    {
        var crlParser = new X509CrlParser();
        var crl = crlParser.ReadCrl(crlBytes);
        var issuerDn = crl.IssuerDN.ToString();

        // Find the issuing CA by matching issuer DN
        var cas = await db.CaCertificates
            .Where(ca => ca.TrustDomainId == trustDomainId)
            .ToListAsync(ct);

        CaCertificate? issuingCa = null;

        // Try DN matching first
        foreach (var ca in cas)
        {
            if (DnMatch(ca.Subject, issuerDn))
            {
                issuingCa = ca;
                break;
            }
        }

        // Fallback: try signature verification against each CA
        if (issuingCa == null)
        {
            var bcCertParser = new X509CertificateParser();
            foreach (var ca in cas)
            {
                try
                {
                    var bcCaCert = bcCertParser.ReadCertificate(
                        System.Text.Encoding.UTF8.GetBytes(ca.X509CertificatePem));
                    crl.Verify(bcCaCert.GetPublicKey());
                    issuingCa = ca;
                    _logger.LogInformation("Matched CRL to CA '{Name}' via signature verification (DN match failed)", ca.Name);
                    break;
                }
                catch { }
            }
        }

        if (issuingCa == null)
        {
            return CrlImportResult.Failed($"No CA in this trust domain matches CRL issuer: {issuerDn}");
        }

        // Extract CRL number
        long crlNumber = 0;
        var crlNumExt = crl.GetExtensionValue(
            Org.BouncyCastle.Asn1.X509.X509Extensions.CrlNumber);
        if (crlNumExt != null)
        {
            var asn1Num = X509ExtensionUtilities.FromExtensionValue(crlNumExt);
            crlNumber = DerInteger.GetInstance(asn1Num).LongValueExact;
        }

        // Validate CRL signature against the issuing CA
        bool signatureValid = false;
        try
        {
            var bcCertParser = new X509CertificateParser();
            var bcCaCert = bcCertParser.ReadCertificate(
                System.Text.Encoding.UTF8.GetBytes(issuingCa.X509CertificatePem));
            crl.Verify(bcCaCert.GetPublicKey());
            signatureValid = true;
        }
        catch { }

        // Create the CRL entity
        var crlEntity = new Crl
        {
            CaCertificateId = issuingCa.Id,
            CrlNumber = crlNumber,
            ThisUpdate = crl.ThisUpdate.ToUniversalTime(),
            NextUpdate = crl.NextUpdate?.ToUniversalTime() ?? DateTime.MaxValue,
            SignatureAlgorithm = crl.SigAlgName,
            RawBytes = crlBytes,
            FileName = fileName,
            SignatureValid = signatureValid
        };

        db.Crls.Add(crlEntity);
        await db.SaveChangesAsync(ct);

        // Import revocation entries
        var revokedCerts = crl.GetRevokedCertificates();
        int revokedCount = 0;

        if (revokedCerts != null)
        {
            foreach (X509CrlEntry entry in revokedCerts)
            {
                int reason = 0;
                try
                {
                    var reasonExt = entry.GetExtensionValue(
                        Org.BouncyCastle.Asn1.X509.X509Extensions.ReasonCode);
                    if (reasonExt != null)
                    {
                        var asn1 = X509ExtensionUtilities.FromExtensionValue(reasonExt);
                        reason = DerEnumerated.GetInstance(asn1).IntValueExact;
                    }
                }
                catch { }

                db.CertificateRevocations.Add(new CertificateRevocation
                {
                    CrlId = crlEntity.Id,
                    RevokedCertSerialNumber = entry.SerialNumber.ToString(16).ToUpperInvariant(),
                    RevocationDate = entry.RevocationDate.ToUniversalTime(),
                    RevocationReason = reason
                });
                revokedCount++;
            }

            await db.SaveChangesAsync(ct);
        }

        _logger.LogInformation("Imported CRL #{CrlNumber} from {File}: {Count} revocations, signature {Valid}",
            crlNumber, fileName, revokedCount, signatureValid ? "valid" : "INVALID");

        return CrlImportResult.Success(crlNumber, revokedCount, signatureValid,
            crl.NextUpdate?.ToUniversalTime(), issuingCa.Name);
    }

    public static bool DnMatch(string dn1, string dn2)
    {
        var parts1 = ParseDnParts(dn1);
        var parts2 = ParseDnParts(dn2);
        return parts1.SetEquals(parts2);
    }

    private static HashSet<string> ParseDnParts(string dn)
    {
        var parts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var part in dn.Split(','))
        {
            var trimmed = part.Trim();
            if (trimmed.StartsWith("ST=", StringComparison.OrdinalIgnoreCase))
                trimmed = "S=" + trimmed[3..];
            if (trimmed.StartsWith("s=", StringComparison.OrdinalIgnoreCase))
                trimmed = "S=" + trimmed[2..];
            parts.Add(trimmed);
        }
        return parts;
    }
}

public record CrlImportResult
{
    public bool IsSuccess { get; init; }
    public string? Error { get; init; }
    public long CrlNumber { get; init; }
    public int RevokedCount { get; init; }
    public bool SignatureValid { get; init; }
    public DateTime? NextUpdate { get; init; }
    public string? IssuingCaName { get; init; }

    public static CrlImportResult Failed(string error) => new() { IsSuccess = false, Error = error };

    public static CrlImportResult Success(long crlNumber, int revokedCount, bool signatureValid,
        DateTime? nextUpdate, string issuingCaName) => new()
    {
        IsSuccess = true,
        CrlNumber = crlNumber,
        RevokedCount = revokedCount,
        SignatureValid = signatureValid,
        NextUpdate = nextUpdate,
        IssuingCaName = issuingCaName
    };
}
