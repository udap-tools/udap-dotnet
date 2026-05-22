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

public class ImportPreviewViewModel
{
    public string TrustDomainName { get; set; } = string.Empty;
    public string DirectoryPath { get; set; } = string.Empty;
    public int RootCaCount { get; set; }
    public int IntermediateCount { get; set; }
    public int IssuedCertCount { get; set; }
    public int CrlCount { get; set; }
    public List<string> Errors { get; set; } = new();
    public bool IsValid => Errors.Count == 0;
}
