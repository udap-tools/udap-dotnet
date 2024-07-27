#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json.Serialization;
using Udap.Client.Client;

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
    [JsonPropertyName("ClientName")]
    public string? ClientName { get; set; }

    [JsonPropertyName("Contacts")]
    public HashSet<string>? Contacts { get; set; }

    [JsonPropertyName("Headers")]
    public Dictionary<string, string>? Headers { get; set; }

    [JsonPropertyName("TieredOAuthClientLogo")]
    public string TieredOAuthClientLogo { get; set; }
}
