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

[Serializable]
public class CdsCard
{
    /// <summary>
    /// OPTIONAL: Unique identifier of the card. MAY be used for auditing and
    /// logging cards and SHALL be included in any subsequent calls to the CDS
    /// service's feedback endpoint.
    /// </summary>
    public string? Uuid { get; set; }

    /// <summary>
    /// REQUIRED: One-sentence, &lt;140-character summary message for display to
    /// the user inside of this card.
    /// </summary>
    public string? Summary { get; set; }

    /// <summary>
    /// OPTIONAL: Optional detailed information to display; if provided MUST be
    /// represented in <a href="https://github.github.com/gfm/">(GitHub Flavored)
    /// Markdown</a>. (For non-urgent cards, the CDS Client MAY hide these details
    /// until the user clicks a link like "view more details...").
    /// </summary>
    public string? Detail { get; set; }

    /// <summary>
    /// REQUIRED: Urgency/importance of what this card conveys. Allowed values,
    /// in order of increasing urgency, are: <code>info</code>, <code>warning</code>,
    /// <code>critical</code>. The CDS Client MAY use this field to help make UI
    /// display decisions such as sort order or coloring.
    /// </summary>
    public string? Indicator { get; set; }

    /// <summary>
    /// REQUIRED: Grouping structure for the <strong><a href="https://cds-hooks.hl7.org/2.0/#source">Source</a></strong>
    /// of the information displayed on this card. The source should be the primary
    /// source of guidance for the decision support the card represents.
    /// </summary>
    public CdsSource? Source { get; set; }

    /// <summary>
    /// OPTIONAL: Allows a service to suggest a set of changes in the context of
    /// the current activity (e.g. changing the dose of a medication currently
    /// being prescribed, for the <code>order-sign</code> activity). If suggestions
    /// are present, <code>selectionBehavior</code> MUST also be provided.
    /// </summary>
    public List<CdsSuggestion>? Suggestions { get; set; }

    /// <summary>
    /// CONDITIONAL: Describes the intended selection behavior of the suggestions
    /// in the card. Allowed values are: <code>at-most-one</code>, indicating that
    /// the user may choose none or at most one of the suggestions; <code>any</code>,
    /// indicating that the end user may choose any number of suggestions including
    /// none of them and all of them. CDS Clients that do not understand the value
    /// MUST treat the card as an error.
    /// </summary>
    public string? SelectionBehavior { get; set; }

    /// <summary>
    /// OPTIONAL: Override reasons can be selected by the end user when overriding
    /// a card without taking the suggested recommendations. The CDS service MAY
    /// return a list of override reasons to the CDS client. If override reasons
    /// are present, the CDS Service MUST populate a <code>display</code> value for
    /// each reason's <a href="https://cds-hooks.hl7.org/2.0/#coding">Coding</a>. The CDS Client SHOULD present
    /// these reasons to the clinician when they dismiss a card. A CDS Client MAY
    /// augment the override reasons presented to the user with its own reasons.
    /// </summary>
    public List<Coding>? OverrideReasons { get; set; }

    /// <summary>
    /// OPTIONAL: Allows a service to suggest a link to an app that the user might
    /// want to run for additional information or to help guide a decision.
    /// </summary>
    public List<CdsLink>? Links { get; set; }
}