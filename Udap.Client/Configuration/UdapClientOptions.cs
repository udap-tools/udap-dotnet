#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json.Serialization;

namespace Udap.Client.Configuration;
public class UdapClientOptions
{
    [JsonPropertyName("ClientName")]
    public string? ClientName { get; set; }

    [JsonPropertyName("Contacts")]
    public HashSet<string>? Contacts { get; set; }

    [JsonPropertyName("Headers")]
    public Dictionary<string, string>? Headers { get; set; }
}
