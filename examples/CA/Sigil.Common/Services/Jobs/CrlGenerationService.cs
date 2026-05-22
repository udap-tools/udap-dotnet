#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Sigil.Common.Data;
using Sigil.Common.Data.Entities;
using Sigil.Common.Services.Signing;
using X509Extensions = Org.BouncyCastle.Asn1.X509.X509Extensions;

namespace Sigil.Common.Services.Jobs;

public record CrlGenerationResult
{
    public bool IsSuccess { get; init; }
    public string? Error { get; init; }
    public int CrlEntityId { get; init; }
    public long CrlNumber { get; init; }
    public int RevokedCount { get; init; }
    public DateTime NextUpdate { get; init; }

    public static CrlGenerationResult Failed(string error) =>
        new() { IsSuccess = false, Error = error };

    public static CrlGenerationResult Success(int crlEntityId, long crlNumber, int revokedCount, DateTime nextUpdate) =>
        new() { IsSuccess = true, CrlEntityId = crlEntityId, CrlNumber = crlNumber, RevokedCount = revokedCount, NextUpdate = nextUpdate };
}

public class CrlGenerationService
{
    private readonly IDbContextFactory<SigilDbContext> _dbFactory;
    private readonly ILogger<CrlGenerationService> _logger;
    private readonly ISigningProvider _signingProvider;

    public CrlGenerationService(
        IDbContextFactory<SigilDbContext> dbFactory,
        ILogger<CrlGenerationService> logger,
        ISigningProvider signingProvider)
    {
        _dbFactory = dbFactory;
        _logger = logger;
        _signingProvider = signingProvider;
    }

    /// <summary>
    /// Generates a new CRL for the specified CA certificate.
    /// Collects all revoked issued certificates and carries forward revocations from the latest existing CRL.
    /// Signs with local PFX key or remote signing provider based on StoreProviderHint.
    /// </summary>
    public async Task<CrlGenerationResult> GenerateCrlAsync(
        int caCertificateId,
        TimeSpan? validity = null,
        CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        var ca = await db.CaCertificates
            .Include(c => c.Crls.Where(crl => !crl.IsArchived))
            .FirstOrDefaultAsync(c => c.Id == caCertificateId, ct);

        if (ca == null)
            return CrlGenerationResult.Failed($"CA certificate with ID {caCertificateId} not found.");

        if (validity == null)
        {
            var trustDomain = await db.TrustDomains.FindAsync([ca.TrustDomainId], ct);
            var days = trustDomain?.CrlValidityDays ?? 0;
            if (days <= 0) days = 7;
            validity = TimeSpan.FromDays(days);
        }

        // Collect revoked issued certificates for this CA
        var revokedCerts = await db.IssuedCertificates
            .Where(c => c.IssuingCaCertificateId == caCertificateId && c.IsRevoked && !c.IsArchived)
            .Select(c => new
            {
                c.SerialNumber,
                c.RevokedAt,
                c.RevocationReason
            })
            .ToListAsync(ct);

        // Collect revoked child CAs (intermediates signed by this CA)
        var revokedChildCas = await db.CaCertificates
            .Where(c => c.ParentId == caCertificateId && c.IsRevoked && !c.IsArchived)
            .Select(c => new
            {
                c.SerialNumber,
                c.RevokedAt,
                c.RevocationReason
            })
            .ToListAsync(ct);

        // Carry forward revocations from the latest existing CRL (for certs revoked via CRL import)
        var latestCrl = ca.Crls
            .OrderByDescending(c => c.CrlNumber)
            .FirstOrDefault();

        var carryForwardRevocations = new List<CertificateRevocation>();
        if (latestCrl != null)
        {
            carryForwardRevocations = await db.CertificateRevocations
                .Where(r => r.CrlId == latestCrl.Id)
                .ToListAsync(ct);
        }

        // Determine next CRL number
        long nextCrlNumber = (latestCrl?.CrlNumber ?? 0L) + 1;

        var now = DateTime.UtcNow;
        var nextUpdate = now.Add(validity.Value);

        // Build unified revocation list (dedup by serial number)
        var revocationEntries = new Dictionary<string, (DateTime RevokedAt, int Reason)>(StringComparer.OrdinalIgnoreCase);

        foreach (var cert in revokedCerts)
        {
            revocationEntries[cert.SerialNumber] = (cert.RevokedAt ?? now, cert.RevocationReason);
        }

        foreach (var childCa in revokedChildCas)
        {
            revocationEntries[childCa.SerialNumber] = (childCa.RevokedAt ?? now, childCa.RevocationReason);
        }

        foreach (var rev in carryForwardRevocations)
        {
            revocationEntries.TryAdd(rev.RevokedCertSerialNumber, (rev.RevocationDate, rev.RevocationReason));
        }

        byte[] crlBytes;
        string signatureAlgorithm;

        try
        {
            if (!string.IsNullOrEmpty(ca.StoreProviderHint))
            {
                // Remote signing path
                (crlBytes, signatureAlgorithm) = await GenerateCrlRemoteAsync(
                    ca, revocationEntries, nextCrlNumber, now, nextUpdate, ct);
            }
            else
            {
                // Local signing path (PFX key)
                (crlBytes, signatureAlgorithm) = GenerateCrlLocal(
                    ca, revocationEntries, nextCrlNumber, now, nextUpdate);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to generate CRL for CA '{CaName}' (ID {CaId})", ca.Name, ca.Id);
            return CrlGenerationResult.Failed($"CRL generation failed: {ex.Message}");
        }

        // Archive previous active CRL
        if (latestCrl != null)
        {
            latestCrl.IsArchived = true;
            latestCrl.ArchivedAt = now;
        }

        // Store new CRL
        var crlEntity = new Crl
        {
            CaCertificateId = caCertificateId,
            CrlNumber = nextCrlNumber,
            ThisUpdate = now,
            NextUpdate = nextUpdate,
            SignatureAlgorithm = signatureAlgorithm,
            RawBytes = crlBytes,
            FileName = $"{ca.Name}-crl-{nextCrlNumber}.crl",
            SignatureValid = true,
            ImportedAt = now
        };

        db.Crls.Add(crlEntity);
        await db.SaveChangesAsync(ct);

        // Add revocation entries to the new CRL
        foreach (var (serial, (revokedAt, reason)) in revocationEntries)
        {
            db.CertificateRevocations.Add(new CertificateRevocation
            {
                CrlId = crlEntity.Id,
                RevokedCertSerialNumber = serial,
                RevocationDate = revokedAt,
                RevocationReason = reason
            });
        }

        if (revocationEntries.Count > 0)
            await db.SaveChangesAsync(ct);

        _logger.LogInformation(
            "Generated CRL #{CrlNumber} for CA '{CaName}' with {RevokedCount} revocations, next update {NextUpdate}",
            nextCrlNumber, ca.Name, revocationEntries.Count, nextUpdate);

        await PublishCrlToFileSystemAsync(db, ca, crlBytes, ct);

        return CrlGenerationResult.Success(crlEntity.Id, nextCrlNumber, revocationEntries.Count, nextUpdate);
    }

    /// <summary>
    /// Publishes the latest CRL for the specified CA to all configured filesystem endpoints.
    /// Safe to call even if the CRL was not just regenerated — ensures the filesystem stays in sync with the DB.
    /// </summary>
    public async Task PublishCrlAsync(int caCertificateId, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        var ca = await db.CaCertificates
            .Include(c => c.Crls.Where(crl => !crl.IsArchived))
            .FirstOrDefaultAsync(c => c.Id == caCertificateId, ct);

        if (ca == null) return;

        var latestCrl = ca.Crls
            .OrderByDescending(c => c.CrlNumber)
            .FirstOrDefault();

        if (latestCrl == null) return;

        await PublishCrlToFileSystemAsync(db, ca, latestCrl.RawBytes, ct);
    }

    private async Task PublishCrlToFileSystemAsync(
        SigilDbContext db, CaCertificate ca, byte[] crlBytes, CancellationToken ct)
    {
        var baseUrls = await db.TrustDomainBaseUrls
            .Where(bu => bu.TrustDomainId == ca.TrustDomainId && bu.PublishingBasePath != null)
            .ToListAsync(ct);

        foreach (var baseUrl in baseUrls)
        {
            if (string.IsNullOrEmpty(baseUrl.PublishingBasePath)) continue;

            try
            {
                var crlPath = Path.GetFullPath(Path.Combine(baseUrl.PublishingBasePath, "crls", $"{ca.Name}.crl"));
                var crlDir = Path.GetDirectoryName(crlPath);
                if (!string.IsNullOrEmpty(crlDir))
                    Directory.CreateDirectory(crlDir);

                var tempPath = crlPath + ".tmp";
                await File.WriteAllBytesAsync(tempPath, crlBytes, ct);
                File.Move(tempPath, crlPath, overwrite: true);
                _logger.LogInformation("Published CRL to {Path} ({Bytes} bytes)", crlPath, crlBytes.Length);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to publish CRL for CA '{CaName}'", ca.Name);
            }
        }
    }

    private (byte[] CrlBytes, string SignatureAlgorithm) GenerateCrlLocal(
        CaCertificate ca,
        Dictionary<string, (DateTime RevokedAt, int Reason)> revocationEntries,
        long crlNumber,
        DateTime thisUpdate,
        DateTime nextUpdate)
    {
        if (ca.EncryptedPfxBytes == null)
            throw new InvalidOperationException($"CA '{ca.Name}' has no PFX key available for local signing.");

        using var x509Ca = X509CertificateLoader.LoadPkcs12(ca.EncryptedPfxBytes, ca.PfxPassword,
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);

        var bouncyCaCert = DotNetUtilities.FromX509Certificate(x509Ca);

        AsymmetricKeyParameter privateKey;
        if (x509Ca.GetRSAPrivateKey() is RSA rsa)
        {
            privateKey = DotNetUtilities.GetKeyPair(rsa).Private;
        }
        else if (x509Ca.GetECDsaPrivateKey() is ECDsa ecdsa)
        {
            privateKey = DotNetUtilities.GetKeyPair(ecdsa).Private;
        }
        else
        {
            throw new InvalidOperationException($"Unsupported key algorithm for CA '{ca.Name}'.");
        }

        var sigAlgName = GetLocalSignatureAlgorithmName(ca.KeyAlgorithm);

        var crlGen = new X509V2CrlGenerator();
        crlGen.SetIssuerDN(bouncyCaCert.SubjectDN);
        crlGen.SetThisUpdate(thisUpdate);
        crlGen.SetNextUpdate(nextUpdate);

        foreach (var (serial, (revokedAt, reason)) in revocationEntries)
        {
            crlGen.AddCrlEntry(
                new BigInteger(serial, 16),
                revokedAt,
                reason);
        }

        // CRL Number extension
        crlGen.AddExtension(X509Extensions.CrlNumber, false,
            new CrlNumber(new BigInteger(crlNumber.ToString())));

        // Authority Key Identifier
        crlGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
            new AuthorityKeyIdentifierStructure(bouncyCaCert.GetPublicKey()));

        var crl = crlGen.Generate(new Asn1SignatureFactory(sigAlgName, privateKey));

        return (crl.GetEncoded(), sigAlgName);
    }

    private async Task<(byte[] CrlBytes, string SignatureAlgorithm)> GenerateCrlRemoteAsync(
        CaCertificate ca,
        Dictionary<string, (DateTime RevokedAt, int Reason)> revocationEntries,
        long crlNumber,
        DateTime thisUpdate,
        DateTime nextUpdate,
        CancellationToken ct)
    {
        // Parse StoreProviderHint to get the key reference (e.g., "vault-transit:keyId")
        var parts = ca.StoreProviderHint!.Split(':', 2);
        if (parts.Length != 2)
            throw new InvalidOperationException($"Invalid StoreProviderHint format: '{ca.StoreProviderHint}'");

        var keyRef = new SigningKeyReference(parts[0], parts[1], ca.KeyAlgorithm, ca.KeySize);

        var hashAlgorithm = HashAlgorithmName.SHA256;
        var sigAlgId = RemoteCertificateBuilder.GetSignatureAlgorithmIdentifier(ca.KeyAlgorithm, hashAlgorithm);

        // Build TBS CRL using BouncyCastle
        var tbsGen = new V2TbsCertListGenerator();
        var issuerDn = new Org.BouncyCastle.Asn1.X509.X509Name(ca.Subject);

        tbsGen.SetIssuer(issuerDn);
        tbsGen.SetThisUpdate(new Org.BouncyCastle.Asn1.X509.Time(thisUpdate));
        tbsGen.SetNextUpdate(new Org.BouncyCastle.Asn1.X509.Time(nextUpdate));
        tbsGen.SetSignature(sigAlgId);

        // Add revocation entries
        foreach (var (serial, (revokedAt, reason)) in revocationEntries)
        {
            var serialNumber = new BigInteger(serial, 16);
            var reasonExt = new X509Extensions(
                new DerObjectIdentifier[] { X509Extensions.ReasonCode },
                new Org.BouncyCastle.Asn1.X509.X509Extension[] {
                    new(false, new DerOctetString(new CrlReason(reason).GetDerEncoded()))
                });
            tbsGen.AddCrlEntry(new DerInteger(serialNumber),
                new Org.BouncyCastle.Asn1.X509.Time(revokedAt), reasonExt);
        }

        // Extensions
        var extGen = new X509ExtensionsGenerator();

        // CRL Number
        extGen.AddExtension(X509Extensions.CrlNumber, false,
            new CrlNumber(new BigInteger(crlNumber.ToString())));

        // Authority Key Identifier — get public key from provider
        var publicKey = await _signingProvider.GetPublicKeyAsync(keyRef, ct);
        var bcPublicKey = PublicKeyFactory.CreateKey(
            publicKey is RSA rsa
                ? rsa.ExportSubjectPublicKeyInfo()
                : ((ECDsa)publicKey).ExportSubjectPublicKeyInfo());

        var akiValue = new AuthorityKeyIdentifier(
            SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bcPublicKey));
        extGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, akiValue);

        tbsGen.SetExtensions(extGen.Generate());

        var tbsCertList = tbsGen.GenerateTbsCertList();
        var tbsBytes = tbsCertList.GetDerEncoded();

        // Sign asynchronously via the provider
        var signature = await _signingProvider.SignDataAsync(tbsBytes, hashAlgorithm, keyRef, ct);

        // Assemble: SEQUENCE { tbsCertList, signatureAlgorithm, signatureValue }
        var crlSeq = new DerSequence(tbsCertList, sigAlgId, new DerBitString(signature));
        var crlBytes = crlSeq.GetDerEncoded();

        var sigAlgName = sigAlgId.Algorithm.Id;
        return (crlBytes, sigAlgName);
    }

    public async Task<List<CrlStatusSummary>> GetCrlStatusesAsync(CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        var cas = await db.CaCertificates
            .Where(ca => !ca.IsArchived &&
                (ca.EncryptedPfxBytes != null || ca.StoreProviderHint != null))
            .Include(ca => ca.TrustDomain)
            .Include(ca => ca.Crls.Where(c => !c.IsArchived))
            .OrderBy(ca => ca.TrustDomain.Name)
            .ThenBy(ca => ca.Name)
            .ToListAsync(ct);

        return cas.Select(ca =>
        {
            var latestCrl = ca.Crls
                .OrderByDescending(c => c.CrlNumber)
                .FirstOrDefault();

            return new CrlStatusSummary
            {
                CaId = ca.Id,
                CaName = ca.Name,
                TrustDomainName = ca.TrustDomain.Name,
                LatestCrlNumber = latestCrl?.CrlNumber,
                NextUpdate = latestCrl?.NextUpdate ?? DateTime.MinValue,
                HasCrl = latestCrl != null,
                NeedsRenewal = latestCrl == null
                    || latestCrl.NextUpdate <= DateTime.UtcNow.AddHours(24),
                RevokedCount = latestCrl?.Revocations?.Count ?? 0
            };
        }).ToList();
    }

    private static string GetLocalSignatureAlgorithmName(string keyAlgorithm) =>
        keyAlgorithm.Equals("RSA", StringComparison.OrdinalIgnoreCase)
            ? "SHA256WithRSAEncryption"
            : "SHA256WithECDSA";
}

public class CrlStatusSummary
{
    public int CaId { get; init; }
    public string CaName { get; init; } = string.Empty;
    public string TrustDomainName { get; init; } = string.Empty;
    public long? LatestCrlNumber { get; init; }
    public DateTime NextUpdate { get; init; }
    public bool HasCrl { get; init; }
    public bool NeedsRenewal { get; init; }
    public int RevokedCount { get; init; }
}
