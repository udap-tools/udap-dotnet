#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigil.Common.Data.Entities;

public class TrustDomain
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }

    public int CrlValidityDays { get; set; } = 7;

    public bool Enabled { get; set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public ICollection<TrustDomainBaseUrl> BaseUrls { get; set; } = new List<TrustDomainBaseUrl>();
    public ICollection<CaCertificate> CaCertificates { get; set; } = new List<CaCertificate>();
}
