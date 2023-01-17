#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.CA.Entities;

public class Anchor
{
    public int Id { get; set; }
    public int RootCertificateId { get; set; }

    public bool Enabled { get; set; }
    public string Subject { get; set; } = string.Empty;
    public string SubjectAltName { get; set; } = string.Empty;

    public string CertificateRevocation { get; set; } = string.Empty;
    public string CertificateAuthIssuerUri { get; set; } = string.Empty;

    /// <summary>
    /// Base64 Der encoded
    /// </summary>
    public string X509Certificate { get; set; }
    public string Thumbprint { get; set; }
    public DateTime BeginDate { get; set; }
    public DateTime EndDate { get; set; }

    public RootCertificate RootCertificate { get; set; }
    public virtual ICollection<IssuedCertificate> IssuedCertificates { get; set; }

    //TODO: future
    // public virtual ICollection<AnchorCertification> AnchorCertifications { get; set; }
}