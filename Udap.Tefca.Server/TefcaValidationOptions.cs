#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Tefca.Server;

/// <summary>
/// Configuration options for TEFCA community validators.
/// Maps community names to the TEFCA validation pipeline,
/// allowing the same validators to apply to multiple communities
/// regardless of their naming convention.
/// </summary>
public class TefcaValidationOptions
{
    /// <summary>
    /// Community names that should use TEFCA validation rules.
    /// Defaults to <see cref="Udap.Tefca.Model.TefcaConstants.CommunityUri"/>.
    /// </summary>
    public HashSet<string> Communities { get; set; } = new(StringComparer.Ordinal)
    {
        Udap.Tefca.Model.TefcaConstants.CommunityUri
    };

    /// <summary>
    /// When true, token requests for the Treatment exchange purposes (T-TREAT, T-TRTMNT)
    /// must include the provider's NPI and/or TIN appended to <c>organization_name</c> and an
    /// <c>organization_id</c> referencing the RCE Directory Organization entry, per the
    /// Treatment XP Implementation SOP v2.0 Section 6.2. Off by default because the SOP does
    /// not prescribe an exact format for the appended identifiers.
    ///
    /// <a href="https://rce.sequoiaproject.org/wp-content/uploads/2026/07/Treatment-XP-SOP-v2.0_7.1.2026_508.pdf#page=8">Treatment XP SOP v2.0 — Section 6.2</a>
    /// </summary>
    public bool EnforceTreatmentOrganizationIdentifiers { get; set; }
}
