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
/// A See <a href="https://cds-hooks.hl7.org/2.0/#response">CDS Service object</a>.
/// </summary>
[Serializable]
public class CdsService
{
    /// <summary>
    /// REQUIRED:  The hook this service should be invoked on. See <a href="https://cds-hooks.hl7.org/2.0/#hooks">Hooks</a>.
    /// </summary>
    [JsonPropertyName("hook")]
    public string? Hook { get; set; }
    /// <summary>
    /// RECOMMENDED:  The human-friendly name of this service.
    /// </summary>
    [JsonPropertyName("title")]
    public string? Title { get; set; }
    /// <summary>
    /// REQUIRED:  The description of this service.
    /// </summary>
    [JsonPropertyName("description")]
    public string? Description { get; set; }
    /// <summary>
    /// REQUIRED:  The {id} portion of the URL to this service which is available at {baseUrl}/cds-services/{id}
    /// </summary>
    [JsonPropertyName("id")]
    public string? Id { get; set; }
    /// <summary>
    /// OPTIONAL:  An object containing key/value pairs of FHIR queries that this service is requesting the
    /// CDS Client to perform and provide on each service call. The key is a string that describes the type
    /// of data being requested and the value is a string representing the FHIR query.
    /// See <a href="https://cds-hooks.hl7.org/2.0/#prefetch-template">Prefetch Template</a>.
    /// </summary>
    [JsonPropertyName("prefetch")]
    public Dictionary<string, string>? Prefetch { get; set; }
    /// <summary>
    /// OPTIONAL:  Human-friendly description of any preconditions for the use of this CDS Service.
    /// </summary>
    [JsonPropertyName("usageRequirements")]
    public string? UsageRequirements { get; set; }
}