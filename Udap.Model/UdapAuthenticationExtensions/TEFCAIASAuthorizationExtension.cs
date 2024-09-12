#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Udap.Model.UdapAuthenticationExtensions;

/// <summary>
/// User this for code like building hl7-b2b extension objects
///
/// <a href="https://rce.sequoiaproject.org/wp-content/uploads/2024/07/SOP-Facilitated-FHIR-Implementation_508-1.pdf#page=17">TEFCA IAS AUTHORIZATION EXTENSION OBJECT</a>
/// </summary>
public class TEFCAIASAuthorizationExtension
{
    private string _version = "1";
    private JsonElement? _userInformation;
    private JsonElement? _patientInformation;
    private string _purposeOfUse = UdapConstants.TEFCAIASAuthorizationExtension.PurposeOfUseCode;
    private ICollection<string>? _consentPolicy;
    private ICollection<string>? _consentReference;
    private JsonElement? _idToken;
    private JsonElement? _ialVetted;

    public TEFCAIASAuthorizationExtension()
    {
        Version = _version;
        ConsentPolicy = new List<string>();
        ConsentReference = new List<string>();
    }

    /// <summary>
    /// version required
    ///
    /// String with fixed value: "1"
    /// </summary>
    [JsonPropertyName(UdapConstants.TEFCAIASAuthorizationExtension.Version)]
    public string Version
    {
        get => _version;
        set => _version = value;
    }

    /// <summary>
    /// purpose_of_use required:
    /// 
    /// Fixed Value “T-IAS”. 
    /// </summary>
    [JsonPropertyName(UdapConstants.TEFCAIASAuthorizationExtension.PurposeOfUse)]
    public string PurposeOfUse
    {
        get => _purposeOfUse;
        set => _purposeOfUse = value;
    }

    /// <summary>
    /// user_information required:
    ///
    /// FHIR RelatedPerson Resource with all known
    /// demographics.Where the user is the patient, the value of
    /// the relationship element MUST be "ONESELF"
    /// </summary>
    [JsonPropertyName(UdapConstants.TEFCAIASAuthorizationExtension.UserInformation)]
    public JsonElement? UserInformation
    {
        get => _userInformation;
        set => _userInformation = value;
    }

    /// <summary>
    /// patient_information required:
    ///
    /// FHIR US Core Patient Resource with all known and validated demographics
    /// </summary>
    [JsonPropertyName(UdapConstants.TEFCAIASAuthorizationExtension.PatientInformation)]
    public JsonElement? PatientInformation
    {
        get => _patientInformation;
        set => _patientInformation = value;
    }
    
    /// <summary>
    /// consent_policy required:
    /// 
    /// The Access Consent Policy Identifier corresponding to the asserted
    /// Access Policy that represents the identity proofing level of assurance
    /// of the user, array of string values from the subset of valid policy
    /// OIDs in that represent identity proofing levels of assurance, each
    /// expressed as a URI, e.g. ["urn:oid:2.16.840.1.113883.3.7204.1.1.1.1.2.1"]
    /// </summary>
    [JsonPropertyName(UdapConstants.TEFCAIASAuthorizationExtension.ConsentPolicy)]
    public ICollection<string>? ConsentPolicy
    {
        get => _consentPolicy;
        set => _consentPolicy = value;
    }

    /// <summary>
    /// consent_reference optional:
    /// 
    /// An array of FHIR Document Reference or Consent Resources where the
    /// supporting access consent documentation can be retrieved, each
    /// expressed as an absolute URL,
    /// e.g. ["https://tefca.example.com/fhir/R4/DocumentReference/consent-6461766570"]
    /// </summary>
    [JsonPropertyName(UdapConstants.TEFCAIASAuthorizationExtension.ConsentReference)]
    public ICollection<string>? ConsentReference
    {
        get => _consentReference;
        set => _consentReference = value;
    }
    
    /// <summary>
    /// id_token optional:
    /// 
    /// Additional token as per relevant SOP
    /// </summary>
    [JsonPropertyName(UdapConstants.TEFCAIASAuthorizationExtension.IdToken)]
    public JsonElement? IdToken
    {
        get => _idToken;
        set => _idToken = value;
    }

    /// <summary>
    /// ial_vetted conditional:
    /// 
    /// OIDC token provided by Identity Verifier when the Identity Verifier is not
    /// the Responding Node. Responding server MAY respond with invalid_grant if missing.
    /// </summary>
    [JsonPropertyName(UdapConstants.TEFCAIASAuthorizationExtension.IalVetted)]
    public JsonElement? IalVetted
    {
        get => _ialVetted;
        set => _ialVetted = value;
    }

    public List<string> Validate()
    {
        var notes = new List<string>();

        if (string.IsNullOrWhiteSpace(Version))
        {
            notes.Add($"Missing required {UdapConstants.TEFCAIASAuthorizationExtension.Version}");
        }

        if (!UserInformation.HasValue || string.IsNullOrEmpty(UserInformation.Value.ToString()))
        {
            notes.Add($"Missing required {UdapConstants.TEFCAIASAuthorizationExtension.UserInformation}");
        }

        if (!PatientInformation.HasValue || string.IsNullOrEmpty(PatientInformation.Value.ToString()))
        {
            notes.Add($"Missing required {UdapConstants.TEFCAIASAuthorizationExtension.PatientInformation}");
        }

        if (PurposeOfUse != UdapConstants.TEFCAIASAuthorizationExtension.PurposeOfUseCode)
        {
            notes.Add($"{UdapConstants.TEFCAIASAuthorizationExtension.PurposeOfUse} must be {UdapConstants.TEFCAIASAuthorizationExtension.PurposeOfUseCode}");
        }

        return notes;
    }

    internal IList<string> GetIListClaims(string claimType)
    {
        var claimValues = new List<string>();

        // Implement logic to retrieve claims based on claimType
        // This method can be customized as per your requirements

        return claimValues;
    }
    
    internal string? GetStandardClaim(string claimType)
    {
        // Implement logic to retrieve a standard claim based on claimType
        // This method can be customized as per your requirements

        return null;
    }

    /// <summary>
    /// Serializes this instance to JSON.
    /// </summary>
    /// <returns>This instance as JSON.</returns>
    public virtual string SerializeToJson(bool indented = false)
    {
        return JsonSerializer.Serialize(this, new JsonSerializerOptions
        {
            WriteIndented = indented
        });
    }
}
