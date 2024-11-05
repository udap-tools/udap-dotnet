#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.CdsHooks.Model;

/// <summary>
/// For successful responses, CDS Services SHALL respond with a 200 HTTP response with an 
/// object containing a <c>cards</c> array and optionally a <c>systemActions</c> array as 
/// described below.
/// </summary>
/// <remarks>
/// Each card contains decision support guidance from the CDS Service. Cards are intended 
/// for display to an end user. The data format of a card defines a very minimal set of 
/// required attributes with several more optional attributes to suit a variety of use 
/// cases, such as: narrative informational decision support, actionable suggestions to 
/// modify data, and links to SMART apps.
/// </remarks>
/// <para>
/// Note that because the CDS client may be invoking multiple services from the same hook, 
/// there may be multiple responses related to the same information. This specification 
/// does not address these scenarios specifically; both CDS Services and CDS Clients should 
/// consider the implications of multiple CDS Services in their integrations and are invited 
/// to consider <see href="#card-attributes">card attributes</see> when determining 
/// prioritization and presentation options.
/// </para>
/// <h3>HTTP Status Codes</h3>
/// <list type="table">
/// <listheader>
/// <term>Code</term>
/// <description>Description</description>
/// </listheader>
/// <item>
/// <term><c>200 OK</c></term>
/// <description>A successful response.</description>
/// </item>
/// <item>
/// <term><c>412 Precondition Failed</c></term>
/// <description>The CDS Service is unable to retrieve the necessary FHIR data to execute 
/// its decision support, either through a prefetch request or directly calling the FHIR 
/// server.</description>
/// </item>
/// </list>
/// <para>
/// CDS Services MAY return other HTTP statuses, specifically 4xx and 5xx HTTP error codes.
/// </para>
[Serializable]
public class CdsResponse
{
    /// <summary>
    /// REQUIRED: An array of
    /// <strong><a href="https://cds-hooks.hl7.org/2.0/#card-attributes">Cards</a></strong>.
    /// Cards can provide a combination of information (for reading), suggested actions
    /// (to be applied if a user selects them),  and links (to launch an app if the user
    /// selects them). The CDS Client decides how to display cards, but this specification
    /// recommends displaying suggestions using buttons, and links using underlined text.
    /// </summary>
    public List<CdsCard>? Cards { get; set; }

    /// <summary>
    /// OPTIONAL: An array of
    /// <strong><a href="https://cds-hooks.hl7.org/2.0/#action">Actions</a></strong>
    /// that the CDS Service proposes to auto-apply. Each action follows the schema of a
    /// <a href="https://cds-hooks.hl7.org/2.0/#action">card-based <code>suggestion.action</code></a>.
    /// The CDS Client decides whether to auto-apply actions.
    /// </summary>
    public List<CdsAction>? SystemActions { get; set; }
}