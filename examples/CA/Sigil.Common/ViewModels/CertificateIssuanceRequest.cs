#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigil.Common.ViewModels;

/// <summary>
/// Request DTO for certificate issuance. Designed for use by UI, CLI, or API consumers.
/// </summary>
public class CertificateIssuanceRequest
{
    /// <summary>
    /// The ID of the issuing CA certificate. Null for self-signed root CA generation.
    /// </summary>
    public int? IssuingCaCertificateId { get; set; }

    /// <summary>
    /// The template that defines extensions, key parameters, and defaults.
    /// </summary>
    public int TemplateId { get; set; }

    /// <summary>
    /// The trustDomain this certificate belongs to.
    /// </summary>
    public int TrustDomainId { get; set; }

    /// <summary>
    /// The X.500 distinguished name for the certificate subject.
    /// Example: "CN=My Cert, O=My Org, C=US"
    /// </summary>
    public string SubjectDn { get; set; } = string.Empty;

    /// <summary>
    /// A friendly display name for the certificate in the UI.
    /// </summary>
    public string CertificateName { get; set; } = string.Empty;

    /// <summary>
    /// Subject Alternative Name entries to include in the certificate.
    /// </summary>
    public List<SanEntry> SubjectAltNames { get; set; } = [];

    /// <summary>
    /// CRL Distribution Point URLs. Only used when the template has IncludeCdp enabled.
    /// </summary>
    public List<string> CdpUrls { get; set; } = [];

    /// <summary>
    /// Authority Information Access URLs. Only used when the template has IncludeAia enabled.
    /// </summary>
    public List<string> AiaUrls { get; set; } = [];

    /// <summary>
    /// Certificate validity start. Defaults to UtcNow if not specified.
    /// </summary>
    public DateTimeOffset? NotBefore { get; set; }

    /// <summary>
    /// Certificate validity end. Defaults to NotBefore + template.ValidityDays if not specified.
    /// </summary>
    public DateTimeOffset? NotAfter { get; set; }

    /// <summary>
    /// Password for the exported PFX (PKCS#12) file containing the private key.
    /// Not required when using a remote signing provider (e.g. Vault Transit).
    /// </summary>
    public string PfxPassword { get; set; } = string.Empty;

    /// <summary>
    /// Override for the signing provider to use for this request.
    /// "local" = PFX-based local signing (default).
    /// "vault-transit" = HashiCorp Vault Transit remote signing.
    /// Null = use the globally configured provider.
    /// </summary>
    public string? SigningProviderOverride { get; set; }
}

/// <summary>
/// Request DTO for re-signing an existing certificate with the same key pair.
/// Creates a new certificate with a new serial number and validity period,
/// but preserves the original private key and SKI so downstream chains remain valid.
/// </summary>
public class CertificateResignRequest
{
    /// <summary>
    /// The database ID of the existing certificate to re-sign.
    /// Must be a CaCertificate (Root or Intermediate) with a private key.
    /// </summary>
    public int ExistingCertificateId { get; set; }

    /// <summary>
    /// "CaCertificate" or "IssuedCertificate".
    /// </summary>
    public string EntityType { get; set; } = "CaCertificate";

    /// <summary>
    /// New validity start. Defaults to UtcNow if not specified.
    /// </summary>
    public DateTimeOffset? NotBefore { get; set; }

    /// <summary>
    /// New validity end. Defaults to NotBefore + original validity duration if not specified.
    /// </summary>
    public DateTimeOffset? NotAfter { get; set; }

    /// <summary>
    /// Password for the exported PFX containing the (same) private key.
    /// </summary>
    public string PfxPassword { get; set; } = string.Empty;
}

/// <summary>
/// A single Subject Alternative Name entry.
/// </summary>
public record SanEntry(SanType Type, string Value);

/// <summary>
/// The type of Subject Alternative Name.
/// </summary>
public enum SanType
{
    Uri,
    Dns,
    Email,
    IpAddress
}

/// <summary>
/// Result DTO returned after certificate issuance.
/// </summary>
public class CertificateIssuanceResult
{
    public bool Success { get; set; }
    public string? Error { get; set; }

    /// <summary>
    /// The database ID of the newly created certificate entity.
    /// </summary>
    public int? EntityId { get; set; }

    /// <summary>
    /// "CaCertificate" for Root/Intermediate CAs, "IssuedCertificate" for end-entity certs.
    /// </summary>
    public string? EntityType { get; set; }

    public string? Thumbprint { get; set; }
    public string? SerialNumber { get; set; }

    public static CertificateIssuanceResult Failure(string error) =>
        new() { Success = false, Error = error };
}
