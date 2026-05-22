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

public class SanList
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }

    /// <summary>
    /// Semicolon-delimited SAN entries: "URI:urn:oid:...#T-TRTMNT;URI:urn:oid:...#T-TREAT;DNS:example.com"
    /// </summary>
    public string Items { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public ICollection<CertificateTemplate> Templates { get; set; } = new List<CertificateTemplate>();
}
