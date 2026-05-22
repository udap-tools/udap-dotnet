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
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Sigil.Common.Data;
using Sigil.Common.Data.Entities;
using Sigil.Common.ViewModels;

namespace Sigil.Common.Services;

public record SingleImportResult
{
    public bool Success { get; init; }
    public bool AlreadyExists { get; init; }
    public bool NeedsCaSelection { get; init; }
    public string? Error { get; init; }
    public string? ImportedName { get; init; }

    public static SingleImportResult Imported(string name) => new() { Success = true, ImportedName = name };
    public static SingleImportResult Merged(string name) => new() { Success = true, AlreadyExists = true, ImportedName = name };
    public static SingleImportResult NoCaFound() => new() { NeedsCaSelection = true };
    public static SingleImportResult Failed(string error) => new() { Error = error };
}

public class CertificateImportService
{
    private readonly IDbContextFactory<SigilDbContext> _dbFactory;
    private readonly ILogger<CertificateImportService> _logger;

    public CertificateImportService(
        IDbContextFactory<SigilDbContext> dbFactory,
        ILogger<CertificateImportService> logger)
    {
        _dbFactory = dbFactory;
        _logger = logger;
    }

    /// <summary>
    /// Imports a single parsed certificate into the database.
    /// Handles dedup by thumbprint, AKI/SKI chain matching, and entity creation.
    /// Returns NeedsCaSelection if no issuing CA can be determined automatically.
    /// </summary>
    public async Task<SingleImportResult> ImportParsedCertificateAsync(
        ParsedCertificate parsed,
        int trustDomainId,
        string? name = null,
        string? password = null,
        int? issuingCaId = null,
        byte[]? rawFileOverride = null,
        CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var cert = parsed.Certificate;
        var thumbprint = cert.Thumbprint;
        var fileBytes = rawFileOverride ?? parsed.RawFileBytes;
        var certName = name ?? Path.GetFileNameWithoutExtension(parsed.FileName);

        // --- Dedup: check existing by thumbprint ---
        var existingCa = await db.CaCertificates
            .FirstOrDefaultAsync(c => c.Thumbprint == thumbprint && c.TrustDomainId == trustDomainId, ct);
        if (existingCa != null)
        {
            if (parsed.HasPrivateKey && existingCa.EncryptedPfxBytes == null)
            {
                existingCa.EncryptedPfxBytes = fileBytes;
                existingCa.PfxPassword = password;
                await db.SaveChangesAsync(ct);
            }
            return SingleImportResult.Merged(existingCa.Name);
        }

        var existingIssued = await db.IssuedCertificates
            .Include(i => i.IssuingCaCertificate)
            .FirstOrDefaultAsync(c => c.Thumbprint == thumbprint
                && c.IssuingCaCertificate.TrustDomainId == trustDomainId, ct);
        if (existingIssued != null)
        {
            if (parsed.HasPrivateKey && existingIssued.EncryptedPfxBytes == null)
            {
                existingIssued.EncryptedPfxBytes = fileBytes;
                existingIssued.PfxPassword = password;
                await db.SaveChangesAsync(ct);
            }
            return SingleImportResult.Merged(existingIssued.Name);
        }

        // --- New cert: determine chain placement ---
        if (parsed.DetectedRole is DetectedCertRole.RootCa or DetectedCertRole.IntermediateCa)
        {
            int? parentId = null;
            if (parsed.DetectedRole == DetectedCertRole.IntermediateCa)
            {
                parentId = issuingCaId;
                if (parentId == null && parsed.AuthorityKeyIdentifier != null)
                    parentId = await CertificateManagementService.FindCaBySkiInternalAsync(
                        db, trustDomainId, parsed.AuthorityKeyIdentifier, ct);
                parentId ??= await CertificateManagementService.FindCaByDnAndSignatureInternalAsync(
                    db, trustDomainId, cert, ct);
            }

            db.CaCertificates.Add(new CaCertificate
            {
                TrustDomainId = trustDomainId,
                ParentId = parentId,
                Name = certName.Trim(),
                Subject = cert.Subject,
                X509CertificatePem = cert.ExportCertificatePem(),
                EncryptedPfxBytes = parsed.HasPrivateKey ? fileBytes : null,
                PfxPassword = parsed.HasPrivateKey ? password : null,
                Thumbprint = thumbprint,
                SerialNumber = cert.SerialNumber,
                KeyAlgorithm = parsed.Algorithm,
                KeySize = parsed.KeySize,
                NotBefore = cert.NotBefore.ToUniversalTime(),
                NotAfter = cert.NotAfter.ToUniversalTime(),
                CertSecurityLevel = CertSecurityLevel.Software,
                Enabled = true
            });
        }
        else
        {
            // End-entity cert
            var resolvedCaId = issuingCaId;
            if (resolvedCaId == null && parsed.AuthorityKeyIdentifier != null)
                resolvedCaId = await CertificateManagementService.FindCaBySkiInternalAsync(
                    db, trustDomainId, parsed.AuthorityKeyIdentifier, ct);
            resolvedCaId ??= await CertificateManagementService.FindCaByDnAndSignatureInternalAsync(
                db, trustDomainId, cert, ct);

            if (resolvedCaId == null)
                return SingleImportResult.NoCaFound();

            db.IssuedCertificates.Add(new IssuedCertificate
            {
                IssuingCaCertificateId = resolvedCaId.Value,
                Name = certName.Trim(),
                Subject = cert.Subject,
                SubjectAltNames = parsed.SubjectAltNames,
                X509CertificatePem = cert.ExportCertificatePem(),
                EncryptedPfxBytes = parsed.HasPrivateKey ? fileBytes : null,
                PfxPassword = parsed.HasPrivateKey ? password : null,
                Thumbprint = thumbprint,
                SerialNumber = cert.SerialNumber,
                KeyAlgorithm = parsed.Algorithm,
                KeySize = parsed.KeySize,
                NotBefore = cert.NotBefore.ToUniversalTime(),
                NotAfter = cert.NotAfter.ToUniversalTime(),
                Enabled = true
            });
        }

        await db.SaveChangesAsync(ct);
        return SingleImportResult.Imported(certName.Trim());
    }

    /// <summary>
    /// Scans a certstores directory and returns a preview of what can be imported.
    /// </summary>
    public List<ImportPreviewViewModel> ScanCertStore(string certstoresPath, string pfxPassword = "udap-test")
    {
        var results = new List<ImportPreviewViewModel>();

        if (!Directory.Exists(certstoresPath))
        {
            results.Add(new ImportPreviewViewModel
            {
                TrustDomainName = "(error)",
                Errors = { $"Directory not found: {certstoresPath}" }
            });
            return results;
        }

        foreach (var trustDomainDir in Directory.GetDirectories(certstoresPath))
        {
            var trustDomainName = Path.GetFileName(trustDomainDir);
            var preview = new ImportPreviewViewModel
            {
                TrustDomainName = trustDomainName,
                DirectoryPath = trustDomainDir
            };

            // Count root CA pfx files at top level
            var rootPfxFiles = Directory.GetFiles(trustDomainDir, "*.pfx", SearchOption.TopDirectoryOnly);
            preview.RootCaCount = rootPfxFiles.Length;

            // Validate root CA files can be loaded
            foreach (var pfxFile in rootPfxFiles)
            {
                try
                {
                    using var cert = X509CertificateLoader.LoadPkcs12FromFile(pfxFile, pfxPassword,
                        X509KeyStorageFlags.Exportable);
                }
                catch (Exception ex)
                {
                    preview.Errors.Add($"Cannot load {Path.GetFileName(pfxFile)}: {ex.Message}");
                }
            }

            // Count intermediates
            var intermediatesDir = Path.Combine(trustDomainDir, "intermediates");
            if (Directory.Exists(intermediatesDir))
            {
                preview.IntermediateCount = Directory.GetFiles(intermediatesDir, "*.pfx").Length;
            }

            // Count issued certs
            var issuedDir = Path.Combine(trustDomainDir, "issued");
            if (Directory.Exists(issuedDir))
            {
                preview.IssuedCertCount = Directory.GetFiles(issuedDir, "*.pfx").Length;
            }

            // Count CRL files
            var crlDir = Path.Combine(trustDomainDir, "crl");
            if (Directory.Exists(crlDir))
            {
                preview.CrlCount = Directory.GetFiles(crlDir, "*.crl").Length;
            }

            results.Add(preview);
        }

        return results;
    }

    /// <summary>
    /// Imports all certificates from a trustDomain directory into the database.
    /// </summary>
    public async Task<(int imported, List<string> errors)> ImportTrustDomainAsync(
        string trustDomainDir,
        string pfxPassword = "udap-test",
        CancellationToken ct = default)
    {
        var trustDomainName = Path.GetFileName(trustDomainDir);
        var errors = new List<string>();
        int imported = 0;

        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        // Check if trustDomain already exists
        var existingTrustDomain = await db.TrustDomains
            .FirstOrDefaultAsync(c => c.Name == trustDomainName, ct);

        if (existingTrustDomain != null)
        {
            errors.Add($"Trust domain '{trustDomainName}' already exists. Delete it first to re-import.");
            return (0, errors);
        }

        var trustDomain = new TrustDomain
        {
            Name = trustDomainName,
            Description = $"Imported from {trustDomainDir}",
            Enabled = true
        };
        db.TrustDomains.Add(trustDomain);
        await db.SaveChangesAsync(ct);

        // Import root CAs
        var rootCas = new Dictionary<string, CaCertificate>(); // SKI -> entity
        var rootPfxFiles = Directory.GetFiles(trustDomainDir, "*.pfx", SearchOption.TopDirectoryOnly);

        foreach (var pfxFile in rootPfxFiles)
        {
            try
            {
                var (entity, ski) = await ImportCaCertificateAsync(db, pfxFile, pfxPassword, trustDomain.Id, null, ct);
                if (ski != null)
                {
                    rootCas[ski] = entity;
                }
                imported++;
                _logger.LogInformation("Imported root CA: {Name}", entity.Name);
            }
            catch (Exception ex)
            {
                errors.Add($"Error importing {Path.GetFileName(pfxFile)}: {ex.Message}");
                _logger.LogError(ex, "Error importing root CA {File}", pfxFile);
            }
        }

        // Import intermediates
        var intermediatesDir = Path.Combine(trustDomainDir, "intermediates");
        var intermediates = new Dictionary<string, CaCertificate>(); // SKI -> entity

        if (Directory.Exists(intermediatesDir))
        {
            var intermediatePfxFiles = Directory.GetFiles(intermediatesDir, "*.pfx");
            foreach (var pfxFile in intermediatePfxFiles)
            {
                try
                {
                    using var cert = X509CertificateLoader.LoadPkcs12FromFile(pfxFile, pfxPassword,
                        X509KeyStorageFlags.Exportable);
                    var aki = GetAuthorityKeyIdentifier(cert);
                    int? parentId = null;

                    if (aki != null && rootCas.TryGetValue(aki, out var parentCa))
                    {
                        parentId = parentCa.Id;
                    }
                    else if (rootCas.Count == 1)
                    {
                        // Fallback: if there's only one root CA, use it
                        parentId = rootCas.Values.First().Id;
                    }

                    var (entity, ski) = await ImportCaCertificateAsync(db, pfxFile, pfxPassword, trustDomain.Id, parentId, ct);
                    if (ski != null)
                    {
                        intermediates[ski] = entity;
                    }
                    imported++;
                    _logger.LogInformation("Imported intermediate: {Name}", entity.Name);
                }
                catch (Exception ex)
                {
                    errors.Add($"Error importing {Path.GetFileName(pfxFile)}: {ex.Message}");
                    _logger.LogError(ex, "Error importing intermediate {File}", pfxFile);
                }
            }
        }

        // Import issued certs
        var issuedDir = Path.Combine(trustDomainDir, "issued");
        if (Directory.Exists(issuedDir))
        {
            var issuedPfxFiles = Directory.GetFiles(issuedDir, "*.pfx");
            foreach (var pfxFile in issuedPfxFiles)
            {
                try
                {
                    using var cert = X509CertificateLoader.LoadPkcs12FromFile(pfxFile, pfxPassword,
                        X509KeyStorageFlags.Exportable);
                    var aki = GetAuthorityKeyIdentifier(cert);
                    int? issuingCaId = null;

                    // Try to match to intermediate first, then root
                    if (aki != null)
                    {
                        if (intermediates.TryGetValue(aki, out var issuingIntermediate))
                        {
                            issuingCaId = issuingIntermediate.Id;
                        }
                        else if (rootCas.TryGetValue(aki, out var issuingRoot))
                        {
                            issuingCaId = issuingRoot.Id;
                        }
                    }

                    if (issuingCaId == null)
                    {
                        // Fallback: if there's one intermediate, use it
                        if (intermediates.Count == 1)
                        {
                            issuingCaId = intermediates.Values.First().Id;
                        }
                        else if (rootCas.Count == 1 && intermediates.Count == 0)
                        {
                            issuingCaId = rootCas.Values.First().Id;
                        }
                        else
                        {
                            errors.Add($"Cannot determine issuer for {Path.GetFileName(pfxFile)}");
                            continue;
                        }
                    }

                    var entity = ImportIssuedCertificate(cert, pfxFile, pfxPassword, issuingCaId.Value);
                    db.IssuedCertificates.Add(entity);
                    await db.SaveChangesAsync(ct);
                    imported++;
                    _logger.LogInformation("Imported issued cert: {Name}", entity.Name);
                }
                catch (Exception ex)
                {
                    errors.Add($"Error importing {Path.GetFileName(pfxFile)}: {ex.Message}");
                    _logger.LogError(ex, "Error importing issued cert {File}", pfxFile);
                }
            }
        }

        // Import CRLs
        var crlDir = Path.Combine(trustDomainDir, "crl");
        if (Directory.Exists(crlDir))
        {
            var crlFiles = Directory.GetFiles(crlDir, "*.crl");
            foreach (var crlFile in crlFiles)
            {
                try
                {
                    var crlImported = await ImportCrlAsync(db, crlFile, rootCas, intermediates, ct);
                    imported += crlImported;
                }
                catch (Exception ex)
                {
                    errors.Add($"Error importing CRL {Path.GetFileName(crlFile)}: {ex.Message}");
                    _logger.LogError(ex, "Error importing CRL {File}", crlFile);
                }
            }
        }

        return (imported, errors);
    }

    private async Task<(CaCertificate entity, string? ski)> ImportCaCertificateAsync(
        SigilDbContext db,
        string pfxFile,
        string pfxPassword,
        int trustDomainId,
        int? parentId,
        CancellationToken ct)
    {
        using var cert = X509CertificateLoader.LoadPkcs12FromFile(pfxFile, pfxPassword,
            X509KeyStorageFlags.Exportable);
        var pfxBytes = File.ReadAllBytes(pfxFile);
        var pem = cert.ExportCertificatePem();
        var ski = GetSubjectKeyIdentifier(cert);

        var (algorithm, keySize) = GetKeyInfo(cert);

        var entity = new CaCertificate
        {
            TrustDomainId = trustDomainId,
            ParentId = parentId,
            Name = Path.GetFileNameWithoutExtension(pfxFile),
            Subject = cert.Subject,
            X509CertificatePem = pem,
            EncryptedPfxBytes = pfxBytes,
            PfxPassword = pfxPassword,
            Thumbprint = cert.Thumbprint,
            SerialNumber = cert.SerialNumber,
            KeyAlgorithm = algorithm,
            KeySize = keySize,
            NotBefore = cert.NotBefore.ToUniversalTime(),
            NotAfter = cert.NotAfter.ToUniversalTime(),
            CrlDistributionPoint = GetCdpUrl(cert),
            AuthorityInfoAccessUri = GetAiaUrl(cert),
            CertSecurityLevel = CertSecurityLevel.Software,
            Enabled = true
        };

        db.CaCertificates.Add(entity);
        await db.SaveChangesAsync(ct);

        return (entity, ski);
    }

    private static IssuedCertificate ImportIssuedCertificate(
        X509Certificate2 cert,
        string pfxFile,
        string pfxPassword,
        int issuingCaId)
    {
        var pfxBytes = File.ReadAllBytes(pfxFile);
        var pem = cert.ExportCertificatePem();
        var (algorithm, keySize) = GetKeyInfo(cert);
        var sans = GetSubjectAltNames(cert);

        return new IssuedCertificate
        {
            IssuingCaCertificateId = issuingCaId,
            Name = Path.GetFileNameWithoutExtension(pfxFile),
            Subject = cert.Subject,
            SubjectAltNames = sans,
            X509CertificatePem = pem,
            EncryptedPfxBytes = pfxBytes,
            PfxPassword = pfxPassword,
            Thumbprint = cert.Thumbprint,
            SerialNumber = cert.SerialNumber,
            KeyAlgorithm = algorithm,
            KeySize = keySize,
            NotBefore = cert.NotBefore.ToUniversalTime(),
            NotAfter = cert.NotAfter.ToUniversalTime(),
            Enabled = true
        };
    }

    private async Task<int> ImportCrlAsync(
        SigilDbContext db,
        string crlFile,
        Dictionary<string, CaCertificate> rootCas,
        Dictionary<string, CaCertificate> intermediates,
        CancellationToken ct)
    {
        var crlBytes = File.ReadAllBytes(crlFile);
        var crlParser = new X509CrlParser();
        var crl = crlParser.ReadCrl(crlBytes);

        // Find the issuing CA by matching the CRL issuer to a CA subject
        var issuerDn = crl.IssuerDN.ToString();
        CaCertificate? issuingCa = null;

        foreach (var ca in rootCas.Values.Concat(intermediates.Values))
        {
            // Compare normalized DN
            if (DnMatch(ca.Subject, issuerDn))
            {
                issuingCa = ca;
                break;
            }
        }

        if (issuingCa == null)
        {
            _logger.LogWarning("Cannot find issuing CA for CRL {File} (issuer: {Issuer})",
                Path.GetFileName(crlFile), issuerDn);
            return 0;
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

        // Validate CRL signature
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

        // Create CRL entity
        var crlEntity = new Crl
        {
            CaCertificateId = issuingCa.Id,
            CrlNumber = crlNumber,
            ThisUpdate = crl.ThisUpdate.ToUniversalTime(),
            NextUpdate = crl.NextUpdate?.ToUniversalTime() ?? DateTime.MaxValue,
            SignatureAlgorithm = crl.SigAlgName,
            RawBytes = crlBytes,
            FileName = Path.GetFileName(crlFile),
            SignatureValid = signatureValid
        };

        db.Crls.Add(crlEntity);
        await db.SaveChangesAsync(ct);

        int imported = 0;
        var revokedCerts = crl.GetRevokedCertificates();

        if (revokedCerts != null)
        {
            foreach (X509CrlEntry entry in revokedCerts)
            {
                var revocation = new CertificateRevocation
                {
                    CrlId = crlEntity.Id,
                    RevokedCertSerialNumber = entry.SerialNumber.ToString(16).ToUpperInvariant(),
                    RevocationDate = entry.RevocationDate.ToUniversalTime(),
                    RevocationReason = entry.HasExtensions ? GetCrlReason(entry) : 0
                };

                db.CertificateRevocations.Add(revocation);
                imported++;
            }

            await db.SaveChangesAsync(ct);
        }

        _logger.LogInformation("Imported CRL #{CrlNumber} from {File}: {Count} revocations, signature {Valid}",
            crlNumber, Path.GetFileName(crlFile), imported, signatureValid ? "valid" : "INVALID");

        return imported + 1; // +1 for the CRL entity itself
    }

    private static int GetCrlReason(X509CrlEntry entry)
    {
        try
        {
            var reasonExt = entry.GetExtensionValue(
                Org.BouncyCastle.Asn1.X509.X509Extensions.ReasonCode);
            if (reasonExt != null)
            {
                var asn1 = Org.BouncyCastle.X509.Extension.X509ExtensionUtilities.FromExtensionValue(reasonExt);
                var reason = Org.BouncyCastle.Asn1.DerEnumerated.GetInstance(asn1);
                return reason.IntValueExact;
            }
        }
        catch
        {
            // Ignore parse errors
        }

        return 0;
    }

    private static string? GetSubjectKeyIdentifier(X509Certificate2 cert)
    {
        var skiExt = cert.Extensions["2.5.29.14"];
        if (skiExt == null) return null;

        var ski = new X509SubjectKeyIdentifierExtension(skiExt, skiExt.Critical);
        return ski.SubjectKeyIdentifier;
    }

    private static string? GetAuthorityKeyIdentifier(X509Certificate2 cert)
    {
        var akiExt = cert.Extensions["2.5.29.35"];
        if (akiExt?.RawData == null || akiExt.RawData.Length < 6) return null;

        // Parse AKI: SEQUENCE { [0] OCTET STRING keyIdentifier }
        // Skip the outer SEQUENCE tag+length and the [0] context tag+length
        try
        {
            var data = akiExt.RawData;
            int offset = 2; // skip SEQUENCE tag + length

            if (data[offset] == 0x80) // [0] implicit tag
            {
                var len = data[offset + 1];
                var keyId = new byte[len];
                Array.Copy(data, offset + 2, keyId, 0, len);
                return Convert.ToHexString(keyId);
            }
        }
        catch
        {
            // Ignore parse errors
        }

        return null;
    }

    private static string? GetCdpUrl(X509Certificate2 cert)
    {
        var cdpExt = cert.Extensions["2.5.29.31"];
        if (cdpExt == null) return null;

        // Simple extraction: find the URI in the raw data
        try
        {
            var rawData = cdpExt.RawData;
            return ExtractUriFromAsn1(rawData);
        }
        catch
        {
            return null;
        }
    }

    private static string? GetAiaUrl(X509Certificate2 cert)
    {
        var aiaExt = cert.Extensions["1.3.6.1.5.5.7.1.1"];
        if (aiaExt == null) return null;

        try
        {
            var rawData = aiaExt.RawData;
            return ExtractUriFromAsn1(rawData);
        }
        catch
        {
            return null;
        }
    }

    private static string? ExtractUriFromAsn1(byte[] data)
    {
        // Look for the IA5String/GeneralName tag 0x86 (uniformResourceIdentifier)
        for (int i = 0; i < data.Length - 2; i++)
        {
            if (data[i] == 0x86)
            {
                var len = data[i + 1];
                if (i + 2 + len <= data.Length)
                {
                    return System.Text.Encoding.ASCII.GetString(data, i + 2, len);
                }
            }
        }

        return null;
    }

    private static string? GetSubjectAltNames(X509Certificate2 cert)
    {
        var sanExt = cert.Extensions["2.5.29.17"];
        if (sanExt == null) return null;

        var sans = new List<string>();
        var rawData = sanExt.RawData;

        // Parse: SEQUENCE of GeneralName
        // We look for tag 0x86 (URI) and 0x82 (DNS)
        for (int i = 0; i < rawData.Length - 2; i++)
        {
            if (rawData[i] == 0x86 || rawData[i] == 0x82) // URI or DNS
            {
                var len = rawData[i + 1];
                if (i + 2 + len <= rawData.Length)
                {
                    var value = System.Text.Encoding.ASCII.GetString(rawData, i + 2, len);
                    var prefix = rawData[i] == 0x86 ? "URI:" : "DNS:";
                    sans.Add($"{prefix}{value}");
                    i += 1 + len; // skip past this entry
                }
            }
        }

        return sans.Count > 0 ? string.Join("; ", sans) : null;
    }

    private static (string algorithm, int keySize) GetKeyInfo(X509Certificate2 cert)
    {
        var rsa = cert.GetRSAPublicKey();
        if (rsa != null)
        {
            return ("RSA", rsa.KeySize);
        }

        var ecdsa = cert.GetECDsaPublicKey();
        if (ecdsa != null)
        {
            return ("ECDSA", ecdsa.KeySize);
        }

        return ("Unknown", 0);
    }

    private static bool DnMatch(string dn1, string dn2)
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
