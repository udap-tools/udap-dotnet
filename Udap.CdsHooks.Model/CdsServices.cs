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
using Hl7.Fhir.Model;

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

/// <summary>
/// Grouping structure for the Source of the information displayed on a card.
/// The source should be the primary source of guidance for the decision support
/// the card represents.
/// </summary>
[Serializable]
public class CdsSource
{
    /// <summary>
    /// REQUIRED: A short, human-readable label to display for the source of the 
    /// information displayed on this card. If a <code>url</code> is also 
    /// specified, this MAY be the text for the hyperlink.
    /// </summary>
    public string? Label { get; set; }

    /// <summary>
    /// OPTIONAL: An optional absolute URL to load (via <code>GET</code>, in a 
    /// browser context) when a user clicks on this link to learn more about the 
    /// organization or data set that provided the information on this card. Note 
    /// that this URL should not be used to supply a context-specific "drill-down" 
    /// view of the information on this card. For that, use 
    /// <a href="#link">card.link.url</a> instead.
    /// </summary>
    public Uri? Url { get; set; }

    /// <summary>
    /// OPTIONAL: An absolute URL to an icon for the source of this card. The icon 
    /// returned by this URL SHOULD be a 100x100 pixel PNG image without any 
    /// transparent regions. The CDS Client may ignore or scale the image during 
    /// display as appropriate for user experience.
    /// </summary>
    public Uri? Icon { get; set; }

    /// <summary>
    /// OPTIONAL: A <em>topic</em> describes the content of the card by providing 
    /// a high-level categorization that can be useful for filtering, searching or 
    /// ordered display of related cards in the CDS client's UI. This specification 
    /// does not prescribe a standard set of topics.
    /// </summary>
    public Coding? Coding { get; set; }
}

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

/// <summary>
/// A CDS Request object. See <a href="https://cds-hooks.hl7.org/2.0/#request">
/// CDS Request</a>.
/// </summary>
[Serializable]
public class CdsRequest
{
    /// <summary>
    /// REQUIRED: The hook that triggered this CDS Service call. See 
    /// <a href="https://cds-hooks.hl7.org/2.0/#hooks">Hooks</a>.
    /// </summary>
    public string? Hook { get; set; }

    /// <summary>
    /// REQUIRED: A universally unique identifier (UUID) for this particular 
    /// hook call (see more information below).
    /// </summary>
    public string? HookInstance { get; set; }

    /// <summary>
    /// CONDITIONAL: The base URL of the CDS Client's FHIR server. If 
    /// fhirAuthorization is provided, this field is REQUIRED. The scheme MUST 
    /// be https when production data is exchanged. See 
    /// <a href="https://cds-hooks.hl7.org/2.0/#fhir-server">FHIR Server</a>.
    /// </summary>
    public Uri? FhirServer { get; set; }

    /// <summary>
    /// OPTIONAL: A structure holding an OAuth 2.0 bearer access token granting 
    /// the CDS Service access to FHIR resources, along with supplemental 
    /// information relating to the token. See 
    /// <a href="https://cds-hooks.hl7.org/2.0/#fhir-authorization">FHIR 
    /// Resource Access</a> for more information.
    /// </summary>
    public CdsAuthorization? FhirAuthorization { get; set; }

    /// <summary>
    /// REQUIRED: Hook-specific contextual data that the CDS service will need. 
    /// For example, with the patient-view hook this will include the FHIR id 
    /// of the Patient being viewed. For details, see the Hooks specific 
    /// specification page (example: 
    /// <a href="https://cds-hooks.hl7.org/2.0/#patient-view">patient-view</a>).
    /// </summary>
    public CdsContext? Context { get; set; }

    /// <summary>
    /// OPTIONAL: The FHIR data that was prefetched by the CDS Client (see more 
    /// information below).
    /// </summary>
    public Dictionary<string, Resource>? Prefetch { get; set; }
}

/// <summary>
/// For successful responses, CDS Services SHALL respond with a 200 HTTP response with an 
/// object containing a <c>cards</c> array and optionally a <c>systemActions</c> array as 
/// described below.
/// </summary>
/// <remarks>
/// Each card contains decision support guidance from the CDS Service. Cards are intended 
/// for display to an end user. The data format of a card defines a very minimal set of 
/// required attributes with several more optional attributes to suit a variety of use 
/// cases, such as: narrative informational decision support, actionable suggestions to 
/// modify data, and links to SMART apps.
/// </remarks>
/// <para>
/// Note that because the CDS client may be invoking multiple services from the same hook, 
/// there may be multiple responses related to the same information. This specification 
/// does not address these scenarios specifically; both CDS Services and CDS Clients should 
/// consider the implications of multiple CDS Services in their integrations and are invited 
/// to consider <see href="#card-attributes">card attributes</see> when determining 
/// prioritization and presentation options.
/// </para>
/// <h3>HTTP Status Codes</h3>
/// <list type="table">
/// <listheader>
/// <term>Code</term>
/// <description>Description</description>
/// </listheader>
/// <item>
/// <term><c>200 OK</c></term>
/// <description>A successful response.</description>
/// </item>
/// <item>
/// <term><c>412 Precondition Failed</c></term>
/// <description>The CDS Service is unable to retrieve the necessary FHIR data to execute 
/// its decision support, either through a prefetch request or directly calling the FHIR 
/// server.</description>
/// </item>
/// </list>
/// <para>
/// CDS Services MAY return other HTTP statuses, specifically 4xx and 5xx HTTP error codes.
/// </para>
[Serializable]
public class CdsResponse
{
    /// <summary>
    /// REQUIRED: An array of
    /// <strong><a href="https://cds-hooks.hl7.org/2.0/#card-attributes">Cards</a></strong>.
    /// Cards can provide a combination of information (for reading), suggested actions
    /// (to be applied if a user selects them),  and links (to launch an app if the user
    /// selects them). The CDS Client decides how to display cards, but this specification
    /// recommends displaying suggestions using buttons, and links using underlined text.
    /// </summary>
    public List<CdsCard>? Cards { get; set; }

    /// <summary>
    /// OPTIONAL: An array of
    /// <strong><a href="https://cds-hooks.hl7.org/2.0/#action">Actions</a></strong>
    /// that the CDS Service proposes to auto-apply. Each action follows the schema of a
    /// <a href="https://cds-hooks.hl7.org/2.0/#action">card-based <code>suggestion.action</code></a>.
    /// The CDS Client decides whether to auto-apply actions.
    /// </summary>
    public List<CdsAction>? SystemActions { get; set; }
}

public class CdsContext
{
    public string? UserId { get; set; }
    public string? PatientId { get; set; }
    public string? EncounterId { get; set; }
    [JsonExtensionData] public Dictionary<string, JsonElement>? Fields { get; set; }
}

/// <summary>
/// FHIR Resource Access
/// If the CDS Client provides both fhirServer and fhirAuthorization request
/// parameters, the CDS Service MAY use the FHIR server to obtain any FHIR
/// resources for which it's authorized, beyond those provided by the CDS Client
/// as prefetched data. This is similar to the approach used by SMART on FHIR
/// wherein the SMART app requests and ultimately obtains an access token from
/// the CDS Client's Authorization server using the SMART launch workflow, as
/// described in SMART App Launch Implementation Guide.
///
/// Like SMART on FHIR, CDS Hooks requires that CDS Services present a valid
/// access token to the FHIR server with each API call. Thus, a CDS Service
/// requires an access token before communicating with the CDS Client's FHIR
/// resource server. While CDS Hooks shares the underlying technical framework
/// and standards as SMART on FHIR, the CDS Hooks workflow MUST accommodate the
/// automated, low-latency delivery of an access token to the CDS service.
///
/// With CDS Hooks, if the CDS Client wants to provide the CDS Service direct
/// access to FHIR resources, the CDS Client creates or obtains an access token
/// prior to invoking the CDS Service, passing this token to the CDS Service as
/// part of the service call. This approach remains compatible with OAuth 2.0's
/// bearer token protocol while minimizing the number of HTTPS round-trips and
/// the service invocation latency. The CDS Client remains in control of
/// providing an access token that is associated with the specific CDS Service,
/// user, and context of the invocation. As the CDS Service executes on behalf
/// of a user, the data to which the CDS Service is given access by the CDS
/// Client MUST be limited to the same restrictions and authorizations afforded
/// the current user. As such, the access token SHALL be scoped to:
///
/// The CDS Service being invoked
/// The current user
/// Passing the Access Token to the CDS Service
/// The access token is specified in the CDS Service request via the
/// fhirAuthorization request parameter. This parameter is an object that
/// contains both the access token as well as other related information as
/// specified below. If the CDS Client chooses not to pass along an access
/// token, the fhirAuthorization parameter is omitted.
/// </summary>
public class CdsAuthorization
{
    /// <summary>
    /// REQUIRED: This is the <a href="https://oauth.net/2/">OAuth 2.0</a> access token
    /// that provides access to the FHIR server.
    /// </summary>
    [JsonPropertyName("access_token")]
    public string? AccessToken { get; set; }

    /// <summary>
    /// REQUIRED: Fixed value: <code>Bearer</code>
    /// </summary>
    [JsonPropertyName("token_type")]
    public string? TokenType { get; set; }

    /// <summary>
    /// REQUIRED: The lifetime in seconds of the access token.
    /// </summary>
    [JsonPropertyName("expires_in")]
    public int? ExpiresIn { get; set; }

    /// <summary>
    /// REQUIRED: The scopes the access token grants the CDS Service.
    /// </summary>
    public string? Scope { get; set; }

    /// <summary>
    /// REQUIRED: The <a href="https://oauth.net/2/">OAuth 2.0</a> client identifier of
    /// the CDS Service, as registered with the CDS Client's authorization server.
    /// </summary>
    public string? Subject { get; set; }

    /// <summary>
    /// CONDITIONAL: If the granted SMART scopes include patient scopes (i.e.
    /// "patient/"), the access token is restricted to a specific patient. This field
    /// SHOULD be populated to identify the FHIR id of that patient.
    /// </summary>
    public string? Patient { get; set; }
}
