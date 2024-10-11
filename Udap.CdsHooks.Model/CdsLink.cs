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
/// Placed in a <see cref="CdsCard"/>, allows a service to suggest a
/// link to an app that the user might want to run for additional
/// information or to help guide a decision.
/// </summary>
[Serializable]
public class CdsLink
{
    /// <summary>
    /// REQUIRED: Human-readable label to display for this link (e.g. the CDS Client
    /// might render this as the underlined text of a clickable link).
    /// </summary>
    public string? Label { get; set; }

    /// <summary>
    /// REQUIRED: URL to load (via <code>GET</code>, in a browser context) when a user
    /// clicks on this link. Note that this MAY be a "deep link" with context embedded
    /// in path segments, query parameters, or a hash.
    /// </summary>
    public Uri? Url { get; set; }

    /// <summary>
    /// REQUIRED: The type of the given URL. There are two possible values for this
    /// field. A type of <code>absolute</code> indicates that the URL is absolute and
    /// should be treated as-is. A type of <code>smart</code> indicates that the URL is
    /// a SMART app launch URL and the CDS Client should ensure the SMART app launch URL
    /// is populated with the appropriate SMART launch parameters.
    /// </summary>
    public string? Type { get; set; }

    /// <summary>
    /// OPTIONAL: An optional field that allows the CDS Service to share information
    /// from the CDS card with a subsequently launched SMART app. The <code>appContext
    /// </code> field should only be valued if the link type is <code>smart</code> and
    /// is not valid for <code>absolute</code> links. The <code>appContext</code> field
    /// and value will be sent to the SMART app as part of the <a href="https://oauth.net/2/">OAuth 2.0</a>
    /// access token response, alongside the other
    /// <a href="http://hl7.org/fhir/smart-app-launch/1.0.0/scopes-and-launch-context/#launch-context-arrives-with-your-access_token">
    /// SMART launch parameters</a> when the SMART app is launched. Note that
    /// <code>appContext</code> could be escaped JSON, base64 encoded XML, or even
    /// a simple string, so long as the SMART app can recognize it. CDS Client support
    /// for <code>appContext</code> requires additional coordination with the
    /// authorization server that is not described or specified in CDS Hooks nor SMART.
    /// </summary>
    public string? AppContext { get; set; }
}