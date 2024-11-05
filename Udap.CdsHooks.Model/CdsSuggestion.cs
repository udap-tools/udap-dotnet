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
/// Allows a service to suggest a set of changes in the <see cref="CdsCard"/>.
/// (e.g. changing the dose of a medication currently being prescribed,
/// for the order-sign activity). 
/// </summary>
[Serializable]
public class CdsSuggestion
{
    /// <summary>
    /// REQUIRED: Human-readable label to display for this suggestion (e.g. the 
    /// CDS Client might render this as the text on a button tied to this 
    /// suggestion).
    /// </summary>
    public string? Label { get; set; }

    /// <summary>
    /// OPTIONAL: Unique identifier, used for auditing and logging suggestions.
    /// </summary>
    public string? Uuid { get; set; }

    /// <summary>
    /// OPTIONAL: When there are multiple suggestions, allows a service to 
    /// indicate that a specific suggestion is recommended from all the 
    /// available suggestions on the card. CDS Hooks clients may choose to 
    /// influence their UI based on this value, such as pre-selecting, or 
    /// highlighting recommended suggestions. Multiple suggestions MAY be 
    /// recommended, if <code>card.selectionBehavior</code> is <code>any</code>.
    /// </summary>
    public bool IsRecommended { get; set; }

    /// <summary>
    /// OPTIONAL: Array of objects, each defining a suggested action. Within a 
    /// suggestion, all actions are logically AND'd together, such that a user 
    /// selecting a suggestion selects all of the actions within it. When a 
    /// suggestion contains multiple actions, the actions SHOULD be processed as 
    /// per FHIR's rules for processing 
    /// <a href="https://hl7.org/fhir/http.html#trules">transactions</a> with the 
    /// CDS Client's <code>fhirServer</code> as the base url for the inferred 
    /// full URL of the transaction bundle entries. (Specifically, deletes 
    /// happen first, then creates, then updates).
    /// </summary>
    public List<CdsAction>? Actions { get; set; }
}