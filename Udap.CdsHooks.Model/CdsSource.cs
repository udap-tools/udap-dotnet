#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Hl7.Fhir.Model;

namespace Udap.CdsHooks.Model;

/// <summary>
/// Grouping structure for the Source of the information displayed on a card.
/// The source should be the primary source of guidance for the decision support
/// the card represents.
/// </summary>
[Serializable]
public class CdsSource
{
    /// <summary>
    /// REQUIRED: A short, human-readable label to display for the source of the 
    /// information displayed on this card. If a <code>url</code> is also 
    /// specified, this MAY be the text for the hyperlink.
    /// </summary>
    public string? Label { get; set; }

    /// <summary>
    /// OPTIONAL: An optional absolute URL to load (via <code>GET</code>, in a 
    /// browser context) when a user clicks on this link to learn more about the 
    /// organization or data set that provided the information on this card. Note 
    /// that this URL should not be used to supply a context-specific "drill-down" 
    /// view of the information on this card. For that, use 
    /// <a href="#link">card.link.url</a> instead.
    /// </summary>
    public Uri? Url { get; set; }

    /// <summary>
    /// OPTIONAL: An absolute URL to an icon for the source of this card. The icon 
    /// returned by this URL SHOULD be a 100x100 pixel PNG image without any 
    /// transparent regions. The CDS Client may ignore or scale the image during 
    /// display as appropriate for user experience.
    /// </summary>
    public Uri? Icon { get; set; }

    /// <summary>
    /// OPTIONAL: A <em>topic</em> describes the content of the card by providing 
    /// a high-level categorization that can be useful for filtering, searching or 
    /// ordered display of related cards in the CDS client's UI. This specification 
    /// does not prescribe a standard set of topics.
    /// </summary>
    public Coding? Coding { get; set; }
}