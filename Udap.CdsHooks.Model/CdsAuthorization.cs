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