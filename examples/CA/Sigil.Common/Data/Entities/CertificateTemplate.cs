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

namespace Sigil.Common.Data.Entities;

public enum CertificateType : byte
{
    RootCa = 0,
    IntermediateCa = 1,
    EndEntityClient = 2,
    EndEntityServer = 3
}

public class CertificateTemplate
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public CertificateType CertificateType { get; set; }
    public string KeyAlgorithm { get; set; } = "RSA";
    public int KeySize { get; set; } = 2048;
    public int ValidityDays { get; set; } = 365;
    public int KeyUsageFlags { get; set; } = (int)X509KeyUsageFlags.DigitalSignature;
    public bool IsKeyUsageCritical { get; set; } = true;

    /// <summary>
    /// Semicolon-delimited OIDs (e.g., "1.3.6.1.5.5.7.3.2;1.3.6.1.5.5.7.3.1").
    /// </summary>
    public string? ExtendedKeyUsageOids { get; set; }

    public bool IsBasicConstraintsCa { get; set; }
    public bool IsBasicConstraintsCritical { get; set; } = true;
    public int? PathLengthConstraint { get; set; }
    public bool IsExtendedKeyUsageCritical { get; set; }

    /// <summary>
    /// "nistP256", "nistP384", or "nistP521". Only used when KeyAlgorithm is "ECDSA".
    /// </summary>
    public string? EcdsaCurve { get; set; }

    public string HashAlgorithm { get; set; } = "SHA256";

    public string? SubjectTemplate { get; set; }
    public bool IncludeCdp { get; set; }

    /// <summary>
    /// URL template for CRL Distribution Point, e.g. "http://crl.example.com/{CAName}.crl".
    /// </summary>
    public string? CdpUrlTemplate { get; set; }

    public bool IncludeAia { get; set; }

    /// <summary>
    /// URL template for Authority Information Access, e.g. "http://crl.example.com/{CAName}.cer".
    /// </summary>
    public string? AiaUrlTemplate { get; set; }

    /// <summary>
    /// Semicolon-delimited SAN type hints for the issuance UI: "URI;DNS;Email;IP".
    /// </summary>
    public string? SubjectAltNameTypes { get; set; }

    /// <summary>
    /// When true, this is a system-seeded template that cannot be deleted (only cloned).
    /// </summary>
    public bool IsPreset { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public ICollection<IssuedCertificate> IssuedCertificates { get; set; } = new List<IssuedCertificate>();
    public ICollection<SanList> SanLists { get; set; } = new List<SanList>();
}
