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
/// Within a <see cref="CdsSuggestion"/>, all actions are logically AND'd together,
/// such that a user selecting a suggestion selects all of the actions within it.
/// When a suggestion contains multiple actions, the actions SHOULD be processed
/// as per FHIR's rules for processing transactions with the CDS Client's
/// fhirServer as the base url for the inferred full URL of the transaction
/// bundle entries. (Specifically, deletes happen first, then creates, then updates).
///
/// A systemAction is a Action which may be returned in a
/// <see cref="CdsResponse.SystemActions"/>, but is instead returned alongside the
/// array of cards. A systemAction is not presented to the user within a card, but
/// rather may be auto-applied without user intervention.
/// </summary>
[Serializable]
public class CdsAction
{
    /// <summary>
    /// REQUIRED: The type of action being performed. Allowed values are: 
    /// <code>create</code>, <code>update</code>, <code>delete</code>.
    /// </summary>
    public string? Type { get; set; }

    /// <summary>
    /// REQUIRED: Human-readable description of the suggested action MAY be 
    /// presented to the end-user.
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// CONDITIONAL: A FHIR resource. When the <code>type</code> attribute is 
    /// <code>create</code>, the <code>resource</code> attribute SHALL contain a 
    /// new FHIR resource to be created. For <code>update</code>, this holds the 
    /// updated resource in its entirety and not just the changed fields. Use of 
    /// this field to communicate a string of a FHIR id for delete suggestions is 
    /// DEPRECATED and <code>resourceId</code> SHOULD be used instead.
    /// </summary>
    public Resource? Resource { get; set; }

    /// <summary>
    /// CONDITIONAL: A relative reference to the relevant resource. SHOULD be 
    /// provided when the <code>type</code> attribute is <code>delete</code>.
    /// </summary>
    public string? ResourceId { get; set; }
}