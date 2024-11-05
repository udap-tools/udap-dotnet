#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json.Serialization;

namespace Udap.CdsHooks.Model;

/// <summary>
/// Collection of CDS <see cref="CdsService"/> objects.  Convenience object for placing in appsettings."/>
/// </summary>
[Serializable]
public class CdsServices
{
    [JsonPropertyName("services")]
    public List<CdsService>? Services { get; set; }
}