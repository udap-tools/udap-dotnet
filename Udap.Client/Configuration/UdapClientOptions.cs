#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Serialization;
using Udap.Model;

namespace Udap.Client.Configuration;

/// <summary>
/// Properties that can be configured by a client application using the <see cref="UdapClient"/>.
/// Typically placed in appsettings under the name UdapClientOptions and registered with dependency injection.
/// </summary>
/// <remarks>
///
/// <pre>
///
/// services.Configure&lt;UdapClientOptions&gt;(configuration.GetSection("UdapClientOptions")); <br/><br/>
///
/// 
/// "UdapClientOptions": { 
///    "ClientName": "Udap.Auth.SecuredControls",
///    "Contacts": [ "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com" ],
///    "Headers": {
///        "USER_KEY": "hobojoe",
///        "ORG_KEY": "travelOrg"
///    },
///    "TieredOAuthClientLogo": "https://securedcontrols.net/_content/Udap.UI/udapAuthLogo.jpg"
/// }
///  
/// </pre>
/// </remarks>


public class UdapClientOptions
{
    public UdapClientOptions()
    {
        ClientName = string.Empty;
        Contacts = [];
        Headers = [];
        TieredOAuthClientLogo = string.Empty;
        UdapVersion = UdapConstants.UdapVersionsSupportedValue;
    }

    [JsonConstructor]
    public UdapClientOptions(
        string? clientName = null,
        HashSet<string>? contacts = null,
        Dictionary<string, string>? headers = null,
        string tieredOAuthClientLogo = "",
        string? udapVersion = null)
    {
        ClientName = clientName ?? string.Empty;
        Contacts = contacts ?? [];
        Headers = headers ?? [];
        TieredOAuthClientLogo = tieredOAuthClientLogo;
        UdapVersion = udapVersion ?? UdapConstants.UdapVersionsSupportedValue;
    }

    [JsonPropertyName("ClientName")]
    public string? ClientName { get; set; }

    [JsonPropertyName("Contacts")]
    public HashSet<string>? Contacts { get; set; }

    [JsonPropertyName("Headers")]
    public Dictionary<string, string>? Headers { get; set; }

    /// <summary>
    /// Gets or sets the logo URI sent in the Tiered OAuth dynamic client registration request.
    /// </summary>
    [JsonPropertyName("TieredOAuthClientLogo")]
    public string TieredOAuthClientLogo { get; set; }

    /// <summary>
    /// The UDAP protocol version sent in the <c>udap</c> field of every registration request.
    /// Per the udap.org specification this is always <c>"1"</c>. Do not change this value.
    /// Which SSRAA IG version the server enforces is a server-side setting (<see cref="SsraaVersion"/>).
    /// </summary>
    [JsonPropertyName("UdapVersion")]
    public string UdapVersion { get; set; }
}
