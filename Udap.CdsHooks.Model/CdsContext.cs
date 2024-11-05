#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json;
using System.Text.Json.Serialization;

namespace Udap.CdsHooks.Model;

public class CdsContext
{
    public string? UserId { get; set; }
    public string? PatientId { get; set; }
    public string? EncounterId { get; set; }
    [JsonExtensionData] public Dictionary<string, JsonElement>? Fields { get; set; }
}