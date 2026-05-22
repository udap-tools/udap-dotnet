#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Sigil.Common.Data;
using Sigil.Common.Data.Entities;
using Sigil.Common.Services.Signing;
using Sigil.Common.Validators;
using Sigil.Common.ViewModels;

namespace Sigil.Common.Services;

/// <summary>
/// Certificate generation engine. Creates Root CAs, Intermediate CAs, and end-entity
/// certificates using .NET's CertificateRequest API with extension helpers extracted
/// from Udap.PKI.Generator. Designed for consumption by UI, CLI, and API hosts.
/// Supports local (PFX) and remote (Vault Transit) signing via ISigningProvider.
/// </summary>
public class CertificateIssuanceService
{
    private readonly IDbContextFactory<SigilDbContext> _dbFactory;
    private readonly ILogger<CertificateIssuanceService> _logger;
    private readonly ISigningProvider _signingProvider;
    private readonly IssuanceValidator _validator;

    public CertificateIssuanceService(
        IDbContextFactory<SigilDbContext> dbFactory,
        ILogger<CertificateIssuanceService> logger,
        ISigningProvider? signingProvider = null,
        IssuanceValidator? validator = null)
    {
        _dbFactory = dbFactory;
        _logger = logger;
        _signingProvider = signingProvider ?? new LocalSigningProvider();
        _validator = validator ?? new IssuanceValidator();
    }

    public IssuanceValidator Validator => _validator;

    /// <summary>
    /// Whether the active signing provider is remote (keys don't leave the provider).
    /// </summary>
    public bool IsRemoteProvider => _signingProvider.ProviderName != "local";

    /// <summary>
    /// Issues a certificate based on the given request and template.
    /// For Root CAs, IssuingCaCertificateId should be null (self-signed).
    /// For Intermediate CAs and end-entity certs, it must reference a CA with a private key.
    /// </summary>
    public async Task<CertificateIssuanceResult> IssueCertificateAsync(CertificateIssuanceRequest request)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();

        // Load template
        var template = await db.CertificateTemplates.FindAsync(request.TemplateId);
        if (template == null)
            return CertificateIssuanceResult.Failure("Template not found.");

        // Validate trustDomain exists
        var trustDomain = await db.TrustDomains.FindAsync(request.TrustDomainId);
        if (trustDomain == null)
            return CertificateIssuanceResult.Failure("Trust domain not found.");

        if (string.IsNullOrWhiteSpace(request.SubjectDn))
            return CertificateIssuanceResult.Failure("Subject DN is required.");

        // Validate AIA URLs and SAN URIs up front — they must be absolute URIs
        var badAia = request.AiaUrls.FirstOrDefault(u => !Uri.TryCreate(u, UriKind.Absolute, out _));
        if (badAia != null)
            return CertificateIssuanceResult.Failure($"AIA URL is not a valid absolute URI: '{badAia}'. Use http:// or https://.");

        var badSanUri = request.SubjectAltNames
            .FirstOrDefault(s => s.Type == SanType.Uri && !Uri.TryCreate(s.Value, UriKind.Absolute, out _));
        if (badSanUri != null)
            return CertificateIssuanceResult.Failure($"SAN URI is not a valid absolute URI: '{badSanUri.Value}'. Use http:// or https:// (or a custom scheme like spiffe://).");

        // Determine effective signing mode for this request
        bool useRemoteSigning = request.SigningProviderOverride != null
            ? request.SigningProviderOverride != "local"
            : IsRemoteProvider;

        // PFX password is only required for local signing
        if (!useRemoteSigning && string.IsNullOrWhiteSpace(request.PfxPassword))
            return CertificateIssuanceResult.Failure("PFX password is required.");

        // Determine if self-signed (root CA)
        bool isSelfSigned = request.IssuingCaCertificateId == null;

        if (isSelfSigned && template.CertificateType != CertificateType.RootCa)
            return CertificateIssuanceResult.Failure("Only Root CA templates can be used for self-signed certificates.");

        if (!isSelfSigned && template.CertificateType == CertificateType.RootCa)
            return CertificateIssuanceResult.Failure("Root CA template cannot be used with an issuing CA — root CAs are self-signed.");

        // Load issuing CA if not self-signed
        X509Certificate2? issuingCert = null;
        CaCertificate? issuingCaEntity = null;
        SigningKeyReference? issuerKeyRef = null;

        if (!isSelfSigned)
        {
            issuingCaEntity = await db.CaCertificates.FindAsync(request.IssuingCaCertificateId);
            if (issuingCaEntity == null)
                return CertificateIssuanceResult.Failure("Issuing CA not found.");

            // Check if the issuing CA uses a remote signing provider
            if (issuingCaEntity.StoreProviderHint?.StartsWith("vault-transit:") == true)
            {
                var vaultKeyName = issuingCaEntity.StoreProviderHint["vault-transit:".Length..];
                issuerKeyRef = new SigningKeyReference(
                    "vault-transit", vaultKeyName, issuingCaEntity.KeyAlgorithm, issuingCaEntity.KeySize);

                // Load the cert (public only) for issuer DN and extensions
                issuingCert = X509Certificate2.CreateFromPem(issuingCaEntity.X509CertificatePem);
            }
            else if (issuingCaEntity.StoreProviderHint?.StartsWith("gcp-kms:") == true)
            {
                var kmsKeyId = issuingCaEntity.StoreProviderHint["gcp-kms:".Length..];
                issuerKeyRef = new SigningKeyReference(
                    "gcp-kms", kmsKeyId, issuingCaEntity.KeyAlgorithm, issuingCaEntity.KeySize);

                issuingCert = X509Certificate2.CreateFromPem(issuingCaEntity.X509CertificatePem);
            }
            else
            {
                // Local signing — need the PFX with private key
                if (issuingCaEntity.EncryptedPfxBytes == null || string.IsNullOrEmpty(issuingCaEntity.PfxPassword))
                    return CertificateIssuanceResult.Failure("Issuing CA does not have a private key. Import the PFX first.");

                try
                {
                    issuingCert = X509CertificateLoader.LoadPkcs12(
                        issuingCaEntity.EncryptedPfxBytes,
                        issuingCaEntity.PfxPassword,
                        X509KeyStorageFlags.Exportable);
                }
                catch (Exception ex)
                {
                    return CertificateIssuanceResult.Failure($"Failed to load issuing CA private key: {ex.Message}");
                }
            }
        }

        // Route to appropriate signing path:
        // 1. Full remote: new cert key AND signing both in remote provider
        // 2. Hybrid: new cert key is LOCAL (PFX), but issuer signs via remote provider (Vault Transit)
        // 3. Full local: both key and signing are local (existing code below)
        if (useRemoteSigning)
        {
            return await IssueCertificateRemoteAsync(
                db, template, request, isSelfSigned, issuingCert, issuingCaEntity, issuerKeyRef);
        }

        if (issuerKeyRef != null)
        {
            // Hybrid: local key + remote signing (e.g., end-entity with PFX, signed by Vault CA)
            return await IssueCertificateHybridAsync(
                db, template, request, issuingCert!, issuingCaEntity!, issuerKeyRef);
        }

        try
        {
            // Generate key pair
            using var keyHolder = GenerateKeyPair(template);

            // Build CertificateRequest
            var certRequest = CreateCertificateRequest(template, request.SubjectDn, keyHolder);

            // Add extensions
            AddExtensions(certRequest, template, request, issuingCert);

            // Determine validity
            var notBefore = request.NotBefore ?? DateTimeOffset.UtcNow;
            var notAfter = request.NotAfter ?? notBefore.AddDays(template.ValidityDays);

            // Clamp notAfter to issuing CA's expiry — .NET won't issue past the issuer's NotAfter
            if (issuingCert != null && notAfter > issuingCert.NotAfter)
            {
                notAfter = new DateTimeOffset(issuingCert.NotAfter.ToUniversalTime(), TimeSpan.Zero);
            }

            // Sign and create certificate
            X509Certificate2 cert;
            if (isSelfSigned)
            {
                cert = certRequest.CreateSelfSigned(notBefore, notAfter);
            }
            else
            {
                var serialBytes = RandomNumberGenerator.GetBytes(16);
                using var signedCert = certRequest.Create(
                    issuingCert!.SubjectName,
                    CreateSignatureGenerator(issuingCert!),
                    notBefore,
                    notAfter,
                    serialBytes);

                // Attach private key
                cert = AttachPrivateKey(signedCert, keyHolder);
            }

            using (cert)
            {
                // Verify the new cert was actually signed by the issuing CA
                if (!isSelfSigned)
                {
                    var issuerError = VerifyIssuedBy(cert, issuingCert!);
                    if (issuerError != null)
                        return CertificateIssuanceResult.Failure(issuerError);
                }

                // Export
                var pfxBytes = cert.Export(X509ContentType.Pkcs12, request.PfxPassword);
                var pem = cert.ExportCertificatePem();

                var certName = string.IsNullOrWhiteSpace(request.CertificateName)
                    ? ExtractCnFromDn(request.SubjectDn) ?? request.SubjectDn
                    : request.CertificateName;

                // Determine key size for storage
                int keySize = GetKeySize(cert);

                // Store in database
                bool isCaType = template.CertificateType is CertificateType.RootCa
                    or CertificateType.IntermediateCa;

                if (isCaType)
                {
                    var caEntity = new CaCertificate
                    {
                        TrustDomainId = request.TrustDomainId,
                        ParentId = isSelfSigned ? null : request.IssuingCaCertificateId,
                        Name = certName,
                        Subject = cert.Subject,
                        X509CertificatePem = pem,
                        EncryptedPfxBytes = pfxBytes,
                        PfxPassword = request.PfxPassword,
                        Thumbprint = cert.Thumbprint,
                        SerialNumber = cert.SerialNumber,
                        KeyAlgorithm = template.KeyAlgorithm,
                        KeySize = keySize,
                        NotBefore = cert.NotBefore.ToUniversalTime(),
                        NotAfter = cert.NotAfter.ToUniversalTime(),
                        CrlDistributionPoint = request.CdpUrls.Count > 0 ? string.Join(";", request.CdpUrls) : null,
                        AuthorityInfoAccessUri = request.AiaUrls.Count > 0 ? string.Join(";", request.AiaUrls) : null,
                    };

                    db.CaCertificates.Add(caEntity);
                    await db.SaveChangesAsync();

                    await PublishCaCertAndCrlAsync(request.TrustDomainId, certName, cert.RawData);

                    return new CertificateIssuanceResult
                    {
                        Success = true,
                        EntityId = caEntity.Id,
                        EntityType = "CaCertificate",
                        Thumbprint = cert.Thumbprint,
                        SerialNumber = cert.SerialNumber
                    };
                }
                else
                {
                    var sanString = request.SubjectAltNames.Count > 0
                        ? string.Join(";", request.SubjectAltNames.Select(s => $"{s.Type}:{s.Value}"))
                        : null;

                    var issuedEntity = new IssuedCertificate
                    {
                        IssuingCaCertificateId = request.IssuingCaCertificateId!.Value,
                        TemplateId = request.TemplateId,
                        Name = certName,
                        Subject = cert.Subject,
                        SubjectAltNames = sanString,
                        X509CertificatePem = pem,
                        EncryptedPfxBytes = pfxBytes,
                        PfxPassword = request.PfxPassword,
                        Thumbprint = cert.Thumbprint,
                        SerialNumber = cert.SerialNumber,
                        KeyAlgorithm = template.KeyAlgorithm,
                        KeySize = keySize,
                        NotBefore = cert.NotBefore.ToUniversalTime(),
                        NotAfter = cert.NotAfter.ToUniversalTime(),
                    };

                    db.IssuedCertificates.Add(issuedEntity);
                    await db.SaveChangesAsync();

                    return new CertificateIssuanceResult
                    {
                        Success = true,
                        EntityId = issuedEntity.Id,
                        EntityType = "IssuedCertificate",
                        Thumbprint = cert.Thumbprint,
                        SerialNumber = cert.SerialNumber
                    };
                }
            }
        }
        catch (Exception ex)
        {
            return CertificateIssuanceResult.Failure($"Certificate generation failed: {ex.Message}");
        }
        finally
        {
            issuingCert?.Dispose();
        }
    }

    /// <summary>
    /// Re-signs an existing certificate with the same key pair but new serial and validity.
    /// The SKI remains the same so downstream certificate chains continue to validate.
    /// Creates a new certificate entity; the old one is preserved.
    /// </summary>
    public async Task<CertificateIssuanceResult> ResignCertificateAsync(CertificateResignRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.PfxPassword))
            return CertificateIssuanceResult.Failure("PFX password is required.");

        await using var db = await _dbFactory.CreateDbContextAsync();

        // Currently only CA certificates can be re-signed (they have hierarchy)
        if (request.EntityType != "CaCertificate")
            return CertificateIssuanceResult.Failure("Only CA certificates can be re-signed.");

        var caEntity = await db.CaCertificates.FindAsync(request.ExistingCertificateId);
        if (caEntity == null)
            return CertificateIssuanceResult.Failure("Certificate not found.");

        if (caEntity.EncryptedPfxBytes == null || string.IsNullOrEmpty(caEntity.PfxPassword))
            return CertificateIssuanceResult.Failure("Certificate does not have a private key.");

        // Load existing cert with private key
        X509Certificate2 existingCert;
        try
        {
            existingCert = X509CertificateLoader.LoadPkcs12(
                caEntity.EncryptedPfxBytes,
                caEntity.PfxPassword,
                X509KeyStorageFlags.Exportable);
        }
        catch (Exception ex)
        {
            return CertificateIssuanceResult.Failure($"Failed to load certificate: {ex.Message}");
        }

        // Load parent CA for signing (if not self-signed root)
        X509Certificate2? parentCert = null;
        bool isSelfSigned = caEntity.ParentId == null;

        if (!isSelfSigned)
        {
            var parentEntity = await db.CaCertificates.FindAsync(caEntity.ParentId);
            if (parentEntity?.EncryptedPfxBytes == null || string.IsNullOrEmpty(parentEntity.PfxPassword))
            {
                existingCert.Dispose();
                return CertificateIssuanceResult.Failure("Parent CA does not have a private key.");
            }

            try
            {
                parentCert = X509CertificateLoader.LoadPkcs12(
                    parentEntity.EncryptedPfxBytes,
                    parentEntity.PfxPassword,
                    X509KeyStorageFlags.Exportable);
            }
            catch (Exception ex)
            {
                existingCert.Dispose();
                return CertificateIssuanceResult.Failure($"Failed to load parent CA: {ex.Message}");
            }
        }

        try
        {
            // Build CertificateRequest using the SAME key from the existing cert
            var rsaKey = existingCert.GetRSAPrivateKey();
            var ecdsaKey = existingCert.GetECDsaPrivateKey();

            CertificateRequest certRequest;
            if (ecdsaKey != null)
            {
                certRequest = new CertificateRequest(
                    existingCert.SubjectName,
                    ecdsaKey,
                    HashAlgorithmName.SHA256);
            }
            else if (rsaKey != null)
            {
                certRequest = new CertificateRequest(
                    existingCert.SubjectName,
                    rsaKey,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);
            }
            else
            {
                return CertificateIssuanceResult.Failure("Unsupported key algorithm.");
            }

            // Copy ALL extensions from the existing certificate
            // This preserves SKI, AKI, BasicConstraints, KeyUsage, SANs, CDP, AIA, etc.
            foreach (var ext in existingCert.Extensions)
            {
                certRequest.CertificateExtensions.Add(ext);
            }

            // Determine validity
            var notBefore = request.NotBefore ?? DateTimeOffset.UtcNow;
            var originalDuration = existingCert.NotAfter - existingCert.NotBefore;
            var notAfter = request.NotAfter ?? notBefore.Add(originalDuration);

            // Clamp to parent's NotAfter
            if (parentCert != null && notAfter > parentCert.NotAfter)
            {
                notAfter = new DateTimeOffset(parentCert.NotAfter.ToUniversalTime(), TimeSpan.Zero);
            }

            // Sign with new serial
            X509Certificate2 newCert;
            if (isSelfSigned)
            {
                // Self-signed root: sign with own key
                newCert = certRequest.CreateSelfSigned(notBefore, notAfter);
            }
            else
            {
                var serialBytes = RandomNumberGenerator.GetBytes(16);
                using var signedCert = certRequest.Create(
                    parentCert!.SubjectName,
                    CreateSignatureGenerator(parentCert!),
                    notBefore,
                    notAfter,
                    serialBytes);

                // Attach the SAME private key
                if (ecdsaKey != null)
                    newCert = signedCert.CopyWithPrivateKey(ecdsaKey);
                else
                    newCert = signedCert.CopyWithPrivateKey(rsaKey!);
            }

            using (newCert)
            {
                // Verify the re-signed cert is actually signed by the parent CA
                if (!isSelfSigned)
                {
                    var issuerError = VerifyIssuedBy(newCert, parentCert!);
                    if (issuerError != null)
                        return CertificateIssuanceResult.Failure(issuerError);
                }

                var pfxBytes = newCert.Export(X509ContentType.Pkcs12, request.PfxPassword);
                var pem = newCert.ExportCertificatePem();

                // Update the existing entity in-place so all child relationships
                // (issued certs, CRLs, sub-CAs) remain attached to this CA.
                _logger.LogInformation("Re-sign: updating CA entity Id={Id} in-place (EntityState={State})",
                    caEntity.Id, db.Entry(caEntity).State);

                caEntity.X509CertificatePem = pem;
                caEntity.EncryptedPfxBytes = pfxBytes;
                caEntity.PfxPassword = request.PfxPassword;
                caEntity.Thumbprint = newCert.Thumbprint;
                caEntity.SerialNumber = newCert.SerialNumber;
                caEntity.NotBefore = newCert.NotBefore.ToUniversalTime();
                caEntity.NotAfter = newCert.NotAfter.ToUniversalTime();

                _logger.LogInformation("Re-sign: after property update EntityState={State}, NotAfter={NotAfter}",
                    db.Entry(caEntity).State, caEntity.NotAfter);

                await db.SaveChangesAsync();

                _logger.LogInformation("Re-sign: SaveChanges complete for CA Id={Id}", caEntity.Id);

                return new CertificateIssuanceResult
                {
                    Success = true,
                    EntityId = caEntity.Id,
                    EntityType = "CaCertificate",
                    Thumbprint = newCert.Thumbprint,
                    SerialNumber = newCert.SerialNumber
                };
            }
        }
        catch (Exception ex)
        {
            return CertificateIssuanceResult.Failure($"Re-sign failed: {ex.Message}");
        }
        finally
        {
            existingCert.Dispose();
            parentCert?.Dispose();
        }
    }

    /// <summary>
    /// Issues a certificate using a remote signing provider (Vault Transit, Cloud KMS).
    /// Uses BouncyCastle's X509V3CertificateGenerator with a pluggable ISignatureFactory
    /// so the private key never leaves the provider boundary.
    /// </summary>
    private async Task<CertificateIssuanceResult> IssueCertificateRemoteAsync(
        SigilDbContext db,
        CertificateTemplate template,
        CertificateIssuanceRequest request,
        bool isSelfSigned,
        X509Certificate2? issuingCert,
        CaCertificate? issuingCaEntity,
        SigningKeyReference? issuerKeyRef)
    {
        try
        {
            var hashAlg = template.HashAlgorithm?.ToUpperInvariant() switch
            {
                "SHA384" => HashAlgorithmName.SHA384,
                "SHA512" => HashAlgorithmName.SHA512,
                _ => HashAlgorithmName.SHA256
            };

            // Generate new key in the remote provider
            var newKeyRef = await _signingProvider.GenerateKeyAsync(
                template.KeyAlgorithm, template.KeySize, template.EcdsaCurve);

            // Get the public key to build extensions
            using var publicKey = await _signingProvider.GetPublicKeyAsync(newKeyRef);

            // Build extensions using the same logic as local path
            var extensions = BuildExtensionsForRemote(template, request, publicKey, issuingCert);

            // Determine validity
            var notBefore = request.NotBefore ?? DateTimeOffset.UtcNow;
            var notAfter = request.NotAfter ?? notBefore.AddDays(template.ValidityDays);
            if (issuingCert != null && notAfter > issuingCert.NotAfter)
                notAfter = new DateTimeOffset(issuingCert.NotAfter.ToUniversalTime(), TimeSpan.Zero);

            // For self-signed: sign with own key. For CA-signed: sign with issuer's key.
            var signingKeyRef = isSelfSigned ? newKeyRef : (issuerKeyRef ?? newKeyRef);

            X509Certificate2 cert;
            if (isSelfSigned)
            {
                cert = await RemoteCertificateBuilder.CreateSelfSignedAsync(
                    _signingProvider, signingKeyRef, request.SubjectDn,
                    notBefore, notAfter, extensions, hashAlg);
            }
            else
            {
                cert = await RemoteCertificateBuilder.CreateSignedAsync(
                    _signingProvider, signingKeyRef, issuingCert!,
                    publicKey, request.SubjectDn,
                    notBefore, notAfter, extensions, hashAlg);
            }

            using (cert)
            {
                // Verify issuer relationship
                if (!isSelfSigned)
                {
                    var issuerError = VerifyIssuedBy(cert, issuingCert!);
                    if (issuerError != null)
                        return CertificateIssuanceResult.Failure(issuerError);
                }

                var pem = cert.ExportCertificatePem();
                var certName = string.IsNullOrWhiteSpace(request.CertificateName)
                    ? ExtractCnFromDn(request.SubjectDn) ?? request.SubjectDn
                    : request.CertificateName;

                int keySize = GetKeySize(cert);
                bool isCaType = template.CertificateType is CertificateType.RootCa or CertificateType.IntermediateCa;

                if (isCaType)
                {
                    var caEntity = new CaCertificate
                    {
                        TrustDomainId = request.TrustDomainId,
                        ParentId = isSelfSigned ? null : request.IssuingCaCertificateId,
                        Name = certName,
                        Subject = cert.Subject,
                        X509CertificatePem = pem,
                        EncryptedPfxBytes = null, // No PFX — key is in Vault
                        PfxPassword = null,
                        Thumbprint = cert.Thumbprint,
                        SerialNumber = cert.SerialNumber,
                        KeyAlgorithm = template.KeyAlgorithm,
                        KeySize = keySize,
                        NotBefore = cert.NotBefore.ToUniversalTime(),
                        NotAfter = cert.NotAfter.ToUniversalTime(),
                        CrlDistributionPoint = request.CdpUrls.Count > 0 ? string.Join(";", request.CdpUrls) : null,
                        AuthorityInfoAccessUri = request.AiaUrls.Count > 0 ? string.Join(";", request.AiaUrls) : null,
                        CertSecurityLevel = CertSecurityLevel.CloudKms,
                        StoreProviderHint = $"{_signingProvider.ProviderName}:{newKeyRef.KeyIdentifier}",
                    };

                    db.CaCertificates.Add(caEntity);
                    await db.SaveChangesAsync();

                    await PublishCaCertAndCrlAsync(request.TrustDomainId, certName, cert.RawData);

                    return new CertificateIssuanceResult
                    {
                        Success = true,
                        EntityId = caEntity.Id,
                        EntityType = "CaCertificate",
                        Thumbprint = cert.Thumbprint,
                        SerialNumber = cert.SerialNumber
                    };
                }
                else
                {
                    var sanString = request.SubjectAltNames.Count > 0
                        ? string.Join(";", request.SubjectAltNames.Select(s => $"{s.Type}:{s.Value}"))
                        : null;

                    var issuedEntity = new IssuedCertificate
                    {
                        IssuingCaCertificateId = request.IssuingCaCertificateId!.Value,
                        TemplateId = request.TemplateId,
                        Name = certName,
                        Subject = cert.Subject,
                        SubjectAltNames = sanString,
                        X509CertificatePem = pem,
                        EncryptedPfxBytes = null, // No PFX — key is in Vault
                        PfxPassword = null,
                        Thumbprint = cert.Thumbprint,
                        SerialNumber = cert.SerialNumber,
                        KeyAlgorithm = template.KeyAlgorithm,
                        KeySize = keySize,
                        NotBefore = cert.NotBefore.ToUniversalTime(),
                        NotAfter = cert.NotAfter.ToUniversalTime(),
                        CertSecurityLevel = CertSecurityLevel.CloudKms,
                        StoreProviderHint = $"{_signingProvider.ProviderName}:{newKeyRef.KeyIdentifier}",
                    };

                    db.IssuedCertificates.Add(issuedEntity);
                    await db.SaveChangesAsync();

                    return new CertificateIssuanceResult
                    {
                        Success = true,
                        EntityId = issuedEntity.Id,
                        EntityType = "IssuedCertificate",
                        Thumbprint = cert.Thumbprint,
                        SerialNumber = cert.SerialNumber
                    };
                }
            }
        }
        catch (Exception ex) when (ex.Message.Contains("signing key not found", StringComparison.OrdinalIgnoreCase))
        {
            return CertificateIssuanceResult.Failure(
                "The issuing CA's signing key is missing from Vault Transit. " +
                "This usually means Vault was restarted (dev mode stores keys in memory and wipes them on restart). " +
                "Re-create the issuing CA, or run Vault with persistent storage.");
        }
        catch (Exception ex)
        {
            return CertificateIssuanceResult.Failure($"Remote certificate generation failed: {ex.Message}");
        }
        finally
        {
            issuingCert?.Dispose();
        }
    }

    /// <summary>
    /// Issues a certificate with a LOCAL private key but signed by a REMOTE provider (Vault Transit).
    /// This is the hybrid path: the end-entity gets a PFX (exportable private key),
    /// while the issuing CA's signature comes from the remote signing provider.
    /// </summary>
    private async Task<CertificateIssuanceResult> IssueCertificateHybridAsync(
        SigilDbContext db,
        CertificateTemplate template,
        CertificateIssuanceRequest request,
        X509Certificate2 issuingCert,
        CaCertificate issuingCaEntity,
        SigningKeyReference issuerKeyRef)
    {
        try
        {
            var hashAlg = template.HashAlgorithm?.ToUpperInvariant() switch
            {
                "SHA384" => HashAlgorithmName.SHA384,
                "SHA512" => HashAlgorithmName.SHA512,
                _ => HashAlgorithmName.SHA256
            };

            // Generate key pair LOCALLY
            using var keyHolder = GenerateKeyPair(template);
            AsymmetricAlgorithm localKey = (AsymmetricAlgorithm?)keyHolder.Ecdsa ?? keyHolder.Rsa!;

            // Build extensions using local public key
            var extensions = BuildExtensionsForRemote(template, request, localKey, issuingCert);

            // Determine validity
            var notBefore = request.NotBefore ?? DateTimeOffset.UtcNow;
            var notAfter = request.NotAfter ?? notBefore.AddDays(template.ValidityDays);
            if (notAfter > issuingCert.NotAfter)
                notAfter = new DateTimeOffset(issuingCert.NotAfter.ToUniversalTime(), TimeSpan.Zero);

            // Sign via remote provider (issuer's key is in Vault) but subject key is local
            var cert = await RemoteCertificateBuilder.CreateSignedAsync(
                _signingProvider, issuerKeyRef, issuingCert,
                localKey, request.SubjectDn,
                notBefore, notAfter, extensions, hashAlg);

            // Attach the LOCAL private key so we can export as PFX
            X509Certificate2 certWithKey;
            if (keyHolder.Ecdsa != null)
                certWithKey = cert.CopyWithPrivateKey(keyHolder.Ecdsa);
            else
                certWithKey = cert.CopyWithPrivateKey(keyHolder.Rsa!);
            cert.Dispose();

            using (certWithKey)
            {
                // Verify issuer relationship
                var issuerError = VerifyIssuedBy(certWithKey, issuingCert);
                if (issuerError != null)
                    return CertificateIssuanceResult.Failure(issuerError);

                var pfxBytes = certWithKey.Export(X509ContentType.Pkcs12, request.PfxPassword);
                var pem = certWithKey.ExportCertificatePem();

                var certName = string.IsNullOrWhiteSpace(request.CertificateName)
                    ? ExtractCnFromDn(request.SubjectDn) ?? request.SubjectDn
                    : request.CertificateName;

                int keySize = GetKeySize(certWithKey);
                bool isCaType = template.CertificateType is CertificateType.RootCa or CertificateType.IntermediateCa;

                if (isCaType)
                {
                    var caEntity = new CaCertificate
                    {
                        TrustDomainId = request.TrustDomainId,
                        ParentId = request.IssuingCaCertificateId,
                        Name = certName,
                        Subject = certWithKey.Subject,
                        X509CertificatePem = pem,
                        EncryptedPfxBytes = pfxBytes,
                        PfxPassword = request.PfxPassword,
                        Thumbprint = certWithKey.Thumbprint,
                        SerialNumber = certWithKey.SerialNumber,
                        KeyAlgorithm = template.KeyAlgorithm,
                        KeySize = keySize,
                        NotBefore = certWithKey.NotBefore.ToUniversalTime(),
                        NotAfter = certWithKey.NotAfter.ToUniversalTime(),
                        CrlDistributionPoint = request.CdpUrls.Count > 0 ? string.Join(";", request.CdpUrls) : null,
                        AuthorityInfoAccessUri = request.AiaUrls.Count > 0 ? string.Join(";", request.AiaUrls) : null,
                        // Local key — standard software level, no provider hint
                    };

                    db.CaCertificates.Add(caEntity);
                    await db.SaveChangesAsync();

                    await PublishCaCertAndCrlAsync(request.TrustDomainId, certName, certWithKey.RawData);

                    return new CertificateIssuanceResult
                    {
                        Success = true,
                        EntityId = caEntity.Id,
                        EntityType = "CaCertificate",
                        Thumbprint = certWithKey.Thumbprint,
                        SerialNumber = certWithKey.SerialNumber
                    };
                }
                else
                {
                    var sanString = request.SubjectAltNames.Count > 0
                        ? string.Join(";", request.SubjectAltNames.Select(s => $"{s.Type}:{s.Value}"))
                        : null;

                    var issuedEntity = new IssuedCertificate
                    {
                        IssuingCaCertificateId = request.IssuingCaCertificateId!.Value,
                        TemplateId = request.TemplateId,
                        Name = certName,
                        Subject = certWithKey.Subject,
                        SubjectAltNames = sanString,
                        X509CertificatePem = pem,
                        EncryptedPfxBytes = pfxBytes,
                        PfxPassword = request.PfxPassword,
                        Thumbprint = certWithKey.Thumbprint,
                        SerialNumber = certWithKey.SerialNumber,
                        KeyAlgorithm = template.KeyAlgorithm,
                        KeySize = keySize,
                        NotBefore = certWithKey.NotBefore.ToUniversalTime(),
                        NotAfter = certWithKey.NotAfter.ToUniversalTime(),
                        // Local key — no StoreProviderHint, standard security level
                    };

                    db.IssuedCertificates.Add(issuedEntity);
                    await db.SaveChangesAsync();

                    return new CertificateIssuanceResult
                    {
                        Success = true,
                        EntityId = issuedEntity.Id,
                        EntityType = "IssuedCertificate",
                        Thumbprint = certWithKey.Thumbprint,
                        SerialNumber = certWithKey.SerialNumber
                    };
                }
            }
        }
        catch (Exception ex) when (ex.Message.Contains("signing key not found", StringComparison.OrdinalIgnoreCase))
        {
            return CertificateIssuanceResult.Failure(
                "The new certificate's signing key is missing from Vault Transit. " +
                "This usually means Vault was restarted (dev mode stores keys in memory and wipes them on restart). " +
                "Re-create the certificate, or run Vault with persistent storage.");
        }
        catch (Exception ex)
        {
            return CertificateIssuanceResult.Failure($"Hybrid certificate generation failed: {ex.Message}");
        }
        finally
        {
            issuingCert.Dispose();
        }
    }

    /// <summary>
    /// Builds X509Extensions for the remote signing path using .NET's extension types.
    /// These are later converted to BouncyCastle format by RemoteCertificateBuilder.
    /// </summary>
    private static X509Extension[] BuildExtensionsForRemote(
        CertificateTemplate template,
        CertificateIssuanceRequest request,
        AsymmetricAlgorithm subjectPublicKey,
        X509Certificate2? issuingCert)
    {
        var extensions = new List<X509Extension>();

        // BasicConstraints
        bool hasPathLength = template.IsBasicConstraintsCa && template.PathLengthConstraint.HasValue;
        extensions.Add(new X509BasicConstraintsExtension(
            template.IsBasicConstraintsCa,
            hasPathLength,
            hasPathLength ? template.PathLengthConstraint!.Value : 0,
            template.IsBasicConstraintsCritical));

        // Key Usage
        var keyUsage = (X509KeyUsageFlags)template.KeyUsageFlags;
        extensions.Add(new X509KeyUsageExtension(keyUsage, template.IsKeyUsageCritical));

        // Subject Key Identifier — need a temporary CertificateRequest to get the PublicKey
        var tempRequest = subjectPublicKey is ECDsa ecdsa
            ? new CertificateRequest("CN=temp", ecdsa, HashAlgorithmName.SHA256)
            : new CertificateRequest("CN=temp", (RSA)subjectPublicKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        extensions.Add(new X509SubjectKeyIdentifierExtension(tempRequest.PublicKey, false));

        // Authority Key Identifier
        if (issuingCert != null)
        {
            CertificateExtensionHelpers.AddAuthorityKeyIdentifierToList(issuingCert, extensions);
        }

        // Extended Key Usage
        if (!string.IsNullOrWhiteSpace(template.ExtendedKeyUsageOids))
        {
            var oids = new OidCollection();
            foreach (var oid in template.ExtendedKeyUsageOids.Split(';',
                         StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                oids.Add(new Oid(oid));
            if (oids.Count > 0)
                extensions.Add(new X509EnhancedKeyUsageExtension(oids, template.IsExtendedKeyUsageCritical));
        }

        // CDP
        if (template.IncludeCdp && request.CdpUrls.Count > 0)
            extensions.Add(CertificateExtensionHelpers.MakeCdp(request.CdpUrls));

        // AIA
        if (template.IncludeAia && request.AiaUrls.Count > 0)
            extensions.Add(CertificateExtensionHelpers.BuildAiaExtension(
                request.AiaUrls.Select(u => new Uri(u)).ToList()));

        // SANs
        if (request.SubjectAltNames.Count > 0)
        {
            var sanBuilder = new SubjectAlternativeNameBuilder();
            foreach (var san in request.SubjectAltNames)
            {
                switch (san.Type)
                {
                    case SanType.Uri: sanBuilder.AddUri(new Uri(san.Value)); break;
                    case SanType.Dns: sanBuilder.AddDnsName(san.Value); break;
                    case SanType.Email: sanBuilder.AddEmailAddress(san.Value); break;
                    case SanType.IpAddress: sanBuilder.AddIpAddress(System.Net.IPAddress.Parse(san.Value)); break;
                }
            }
            extensions.Add(sanBuilder.Build());
        }

        return extensions.ToArray();
    }

    /// <summary>
    /// Verifies that <paramref name="cert"/> was signed by <paramref name="issuer"/>
    /// using BouncyCastle signature verification. Returns null on success or an error message.
    /// </summary>
    public static string? VerifyIssuedBy(X509Certificate2 cert, X509Certificate2 issuer)
    {
        try
        {
            var bcParser = new Org.BouncyCastle.X509.X509CertificateParser();
            var bcCert = bcParser.ReadCertificate(cert.RawData);
            var bcIssuer = bcParser.ReadCertificate(issuer.RawData);

            // Check Issuer DN matches Subject DN of the alleged issuer
            if (!bcCert.IssuerDN.Equivalent(bcIssuer.SubjectDN))
            {
                return $"Certificate Issuer DN '{bcCert.IssuerDN}' does not match the CA Subject DN '{bcIssuer.SubjectDN}'.";
            }

            // Verify the signature
            bcCert.Verify(bcIssuer.GetPublicKey());
            return null; // success
        }
        catch (Org.BouncyCastle.Security.InvalidKeyException)
        {
            return "Certificate signature verification failed: the certificate was not signed by the specified CA.";
        }
        catch (Org.BouncyCastle.Security.Certificates.CertificateException ex)
        {
            return $"Certificate signature verification failed: {ex.Message}";
        }
        catch (Exception ex)
        {
            return $"Certificate issuer validation failed: {ex.Message}";
        }
    }

    private static KeyHolder GenerateKeyPair(CertificateTemplate template)
    {
        if (template.KeyAlgorithm.Equals("ECDSA", StringComparison.OrdinalIgnoreCase))
        {
            var curve = template.EcdsaCurve?.ToLowerInvariant() switch
            {
                "nistp256" => ECCurve.NamedCurves.nistP256,
                "nistp384" => ECCurve.NamedCurves.nistP384,
                "nistp521" => ECCurve.NamedCurves.nistP521,
                _ => ECCurve.NamedCurves.nistP384 // default
            };

            return new KeyHolder(ecdsa: ECDsa.Create(curve));
        }

        return new KeyHolder(rsa: RSA.Create(template.KeySize));
    }

    private static CertificateRequest CreateCertificateRequest(
        CertificateTemplate template,
        string subjectDn,
        KeyHolder keyHolder)
    {
        var hashAlg = template.HashAlgorithm?.ToUpperInvariant() switch
        {
            "SHA384" => HashAlgorithmName.SHA384,
            "SHA512" => HashAlgorithmName.SHA512,
            _ => HashAlgorithmName.SHA256
        };

        if (keyHolder.Ecdsa != null)
        {
            return new CertificateRequest(subjectDn, keyHolder.Ecdsa, hashAlg);
        }

        return new CertificateRequest(
            subjectDn,
            keyHolder.Rsa!,
            hashAlg,
            RSASignaturePadding.Pkcs1);
    }

    private static void AddExtensions(
        CertificateRequest certRequest,
        CertificateTemplate template,
        CertificateIssuanceRequest request,
        X509Certificate2? issuingCert)
    {
        // Basic Constraints
        bool hasPathLength = template.IsBasicConstraintsCa && template.PathLengthConstraint.HasValue;
        certRequest.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                template.IsBasicConstraintsCa,
                hasPathLength,
                hasPathLength ? template.PathLengthConstraint!.Value : 0,
                template.IsBasicConstraintsCritical));

        // Key Usage
        var keyUsage = (X509KeyUsageFlags)template.KeyUsageFlags;
        certRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(keyUsage, template.IsKeyUsageCritical));

        // Subject Key Identifier
        certRequest.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(certRequest.PublicKey, false));

        // Authority Key Identifier (if issued by a CA)
        if (issuingCert != null)
        {
            CertificateExtensionHelpers.AddAuthorityKeyIdentifier(issuingCert, certRequest);
        }

        // Extended Key Usage
        if (!string.IsNullOrWhiteSpace(template.ExtendedKeyUsageOids))
        {
            var oids = new OidCollection();
            foreach (var oid in template.ExtendedKeyUsageOids.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                oids.Add(new Oid(oid));
            }

            if (oids.Count > 0)
            {
                certRequest.CertificateExtensions.Add(
                    new X509EnhancedKeyUsageExtension(oids, template.IsExtendedKeyUsageCritical));
            }
        }

        // CRL Distribution Points
        if (template.IncludeCdp && request.CdpUrls.Count > 0)
        {
            certRequest.CertificateExtensions.Add(
                CertificateExtensionHelpers.MakeCdp(request.CdpUrls));
        }

        // Authority Information Access
        if (template.IncludeAia && request.AiaUrls.Count > 0)
        {
            certRequest.CertificateExtensions.Add(
                CertificateExtensionHelpers.BuildAiaExtension(
                    request.AiaUrls.Select(u => new Uri(u)).ToList()));
        }

        // Subject Alternative Names
        if (request.SubjectAltNames.Count > 0)
        {
            var sanBuilder = new SubjectAlternativeNameBuilder();
            foreach (var san in request.SubjectAltNames)
            {
                switch (san.Type)
                {
                    case SanType.Uri:
                        sanBuilder.AddUri(new Uri(san.Value));
                        break;
                    case SanType.Dns:
                        sanBuilder.AddDnsName(san.Value);
                        break;
                    case SanType.Email:
                        sanBuilder.AddEmailAddress(san.Value);
                        break;
                    case SanType.IpAddress:
                        sanBuilder.AddIpAddress(IPAddress.Parse(san.Value));
                        break;
                }
            }

            certRequest.CertificateExtensions.Add(sanBuilder.Build());
        }
    }

    private static X509SignatureGenerator CreateSignatureGenerator(X509Certificate2 issuerCert)
    {
        if (issuerCert.GetECDsaPrivateKey() is ECDsa ecdsa)
            return X509SignatureGenerator.CreateForECDsa(ecdsa);

        if (issuerCert.GetRSAPrivateKey() is RSA rsa)
            return X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1);

        throw new InvalidOperationException($"Unsupported issuer key algorithm: {issuerCert.PublicKey.Oid.FriendlyName}");
    }

    private static X509Certificate2 AttachPrivateKey(X509Certificate2 signedCert, KeyHolder keyHolder)
    {
        if (keyHolder.Ecdsa != null)
            return signedCert.CopyWithPrivateKey(keyHolder.Ecdsa);

        return signedCert.CopyWithPrivateKey(keyHolder.Rsa!);
    }

    private async Task PublishCaCertAndCrlAsync(
        int trustDomainId, string certName, byte[] certDerBytes)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var baseUrls = await db.TrustDomainBaseUrls
            .Where(bu => bu.TrustDomainId == trustDomainId && bu.PublishingBasePath != null)
            .ToListAsync();

        if (baseUrls.Count == 0) return;

        foreach (var baseUrl in baseUrls)
        {
            if (string.IsNullOrEmpty(baseUrl.PublishingBasePath)) continue;

            try
            {
                var certPath = Path.GetFullPath(Path.Combine(baseUrl.PublishingBasePath, "certs", $"{certName}.cer"));
                var certDir = Path.GetDirectoryName(certPath);
                if (!string.IsNullOrEmpty(certDir))
                    Directory.CreateDirectory(certDir);

                var tempPath = certPath + ".tmp";
                await File.WriteAllBytesAsync(tempPath, certDerBytes);
                File.Move(tempPath, certPath, overwrite: true);
                _logger.LogInformation("Published certificate to {Path} ({Bytes} bytes)", certPath, certDerBytes.Length);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to publish certificate for CA '{CertName}'", certName);
            }
        }
    }

    private static int GetKeySize(X509Certificate2 cert)
    {
        if (cert.GetECDsaPublicKey() is { } ecdsa)
        {
            using (ecdsa)
                return ecdsa.KeySize;
        }

        if (cert.GetRSAPublicKey() is { } rsa)
        {
            using (rsa)
                return rsa.KeySize;
        }

        return 0;
    }

    private static string? ExtractCnFromDn(string dn)
    {
        // Simple CN extraction from "CN=value, O=..."
        foreach (var part in dn.Split(','))
        {
            var trimmed = part.Trim();
            if (trimmed.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                return trimmed[3..].Trim();
        }

        return null;
    }

    /// <summary>
    /// Holds the generated key pair (either RSA or ECDSA) and disposes it properly.
    /// </summary>
    private sealed class KeyHolder : IDisposable
    {
        public RSA? Rsa { get; }
        public ECDsa? Ecdsa { get; }

        public KeyHolder(RSA? rsa = null, ECDsa? ecdsa = null)
        {
            Rsa = rsa;
            Ecdsa = ecdsa;
        }

        public void Dispose()
        {
            Rsa?.Dispose();
            Ecdsa?.Dispose();
        }
    }
}
