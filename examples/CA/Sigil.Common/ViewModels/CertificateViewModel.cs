#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Sigil.Common.Data.Entities;

namespace Sigil.Common.ViewModels;

public class CertificateViewModel
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Subject { get; set; } = string.Empty;
    public string? SubjectAltNames { get; set; }
    public string Thumbprint { get; set; } = string.Empty;
    public string SerialNumber { get; set; } = string.Empty;
    public string KeyAlgorithm { get; set; } = "RSA";
    public int KeySize { get; set; }
    public DateTime NotBefore { get; set; }
    public DateTime NotAfter { get; set; }
    public bool IsRevoked { get; set; }
    public bool Enabled { get; set; }
    public string? CrlDistributionPoint { get; set; }
    public string? AuthorityInfoAccessUri { get; set; }

    /// <summary>
    /// "RootCA", "IntermediateCA", or "EndEntity".
    /// </summary>
    public string CertificateRole { get; set; } = string.Empty;

    public CertificateStatus Status
    {
        get
        {
            if (IsRevoked) return CertificateStatus.Revoked;
            if (DateTime.UtcNow > NotAfter) return CertificateStatus.Expired;
            if (DateTime.UtcNow > NotAfter.AddDays(-30)) return CertificateStatus.Expiring;
            return CertificateStatus.Valid;
        }
    }
}

public enum CertificateStatus
{
    Valid,
    Expiring,
    Expired,
    Revoked,
    Untrusted,
    Stale
}
