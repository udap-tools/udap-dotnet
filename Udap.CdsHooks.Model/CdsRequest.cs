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