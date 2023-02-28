#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;

namespace Udap.CA.ViewModel;

public class Anchor
{
    public long Id { get; set; }
    public bool Enabled { get; set; }
    public string Subject { get; set; } = string.Empty;
    public string SubjectAltName { get; set; } = string.Empty;
    public string CertificateRevocation { get; set; } = "http://crl.fhircerts.net:7026/crl/SureFhir-Anchor.crl";
    public string CertificateAuthIssuerUri { get; set; } = "http://crl.fhircerts.net:7026/certs/anchors/SureFhir-TestAnchor.cer";
    public X509Certificate2? Certificate { get; set; }
    public string? Thumbprint { get; set; }
    public DateTime? BeginDate { get; set; }
    public DateTime? EndDate { get; set; }

    public virtual ICollection<IssuedCertificate> IssuedCertificates { get; set; }
    public int RootCertificateId { get; set; }
}