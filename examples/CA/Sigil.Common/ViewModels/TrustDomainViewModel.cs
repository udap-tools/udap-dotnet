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

public class TrustDomainViewModel
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public List<BaseUrlViewModel> BaseUrls { get; set; } = new();
    public string BaseUrlsDisplay => string.Join("; ", BaseUrls.Select(b => b.Url));
    public int CrlValidityDays { get; set; } = 7;
    public bool Enabled { get; set; } = true;
    public int RootCaCount { get; set; }
    public int TotalCertCount { get; set; }
    public DateTime CreatedAt { get; set; }
}

public class BaseUrlViewModel
{
    public string Url { get; set; } = string.Empty;
    public string? PublishingBasePath { get; set; }
}
