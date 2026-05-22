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

public class TrustDomainBaseUrl
{
    public int Id { get; set; }
    public int TrustDomainId { get; set; }
    public TrustDomain TrustDomain { get; set; } = null!;
    public string Url { get; set; } = string.Empty;
    public int SortOrder { get; set; }

    /// <summary>
    /// Local filesystem path where CRLs and certificates are published for this base URL.
    /// The URL path is appended to this directory (e.g., "/crls/MyCA.crl" writes to "{PublishingBasePath}/crls/MyCA.crl").
    /// </summary>
    public string? PublishingBasePath { get; set; }
}
