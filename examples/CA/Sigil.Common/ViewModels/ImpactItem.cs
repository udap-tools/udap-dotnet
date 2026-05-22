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

public enum ImpactSeverity
{
    Info,
    Warning,
    Critical
}

public record ImpactItem(int Count, string Label, ImpactSeverity Severity = ImpactSeverity.Info);
