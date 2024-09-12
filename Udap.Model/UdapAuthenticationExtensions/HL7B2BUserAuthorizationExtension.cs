#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Udap.Model.UdapAuthenticationExtensions;

/// <summary>
/// User this for code like building hl7-b2b-user extension objects in UIs.
///
/// <a href="https://build.fhir.org/ig/HL7/fhir-identity-matching-ig/patient-matching.html#consumer-match">Consumer Match</a>
/// </summary>
public class HL7B2BUserAuthorizationExtension
{
    private string _version = "1";
    private JsonElement? _userPerson;
    private ICollection<string>? _purposeOfUse;
    private ICollection<string>? _consentPolicy;
    private ICollection<string>? _consentReference;

    public HL7B2BUserAuthorizationExtension()
    {
        Version = _version;
        PurposeOfUse = new List<string>();
        ConsentPolicy = new List<string>();
        ConsentReference = new List<string>();
    }

    /// <summary>
    /// version required
    ///
    /// String with fixed value: "1"
    /// </summary>
    [JsonPropertyName(UdapConstants.HL7B2BUserAuthorizationExtension.Version)]
    public string Version
    {
        get => _version;
        set => _version = value;
    }

    /// <summary>
    /// subject_name conditional:
    ///
    /// String containing the human-readable name of the human or non-human requestor; required if known.
    /// </summary>
    [JsonPropertyName(UdapConstants.HL7B2BUserAuthorizationExtension.UserPerson)]
    [Required(ErrorMessage = "FHIR Person is required")]
    public JsonElement? UserPerson
    {
        get => _userPerson;
        set => _userPerson = value;
    }

    /// <summary>
    /// purpose_of_use required:
    /// 
    /// An array of one or more strings, each containing a code identifying a purpose for which the data is being
    /// requested. For US Realm, trust communities SHOULD constrain the allowed values, and are encouraged to
    /// draw from the HL7 PurposeOfUse value set, but are not required to do so to be considered conformant.
    /// See Section 5.2.1.2 below for the preferred format of each code value string array element.
    /// </summary>
    [JsonPropertyName(UdapConstants.HL7B2BUserAuthorizationExtension.PurposeOfUse)]
    public ICollection<string>? PurposeOfUse
    {
        get => _purposeOfUse;
        set => _purposeOfUse = value;
    }

    /// <summary>
    /// consent_policy optional:
    /// 
    /// An array of one or more strings, each containing a URI identifying a privacy consent directive policy
    /// or other policy consistent with the value of the purpose_of_use parameter.
    /// </summary>
    [JsonPropertyName(UdapConstants.HL7B2BUserAuthorizationExtension.ConsentPolicy)]
    public ICollection<string>? ConsentPolicy
    {
        get => _consentPolicy;
        set => _consentPolicy = value;
    }

    /// <summary>
    /// consent_reference conditional:
    /// 
    /// An array of one or more strings, each containing an absolute URL consistent with a literal reference to a FHIR Consent
    /// or DocumentReference resource containing or referencing a privacy consent directive relevant to a purpose identified
    /// by the purpose_of_use parameter and the policy or policies identified by the consent_policy parameter. The issuer of
    /// this Authorization Extension Object SHALL only include URLs that are resolvable by the receiving party. If a referenced
    /// resource does not include the raw document data inline in the resource or as a contained resource, then it SHALL
    /// include a URL to the attachment data that is resolvable by the receiving party. Omit if consent_policy is not present.
    /// </summary>
    [JsonPropertyName(UdapConstants.HL7B2BUserAuthorizationExtension.ConsentReference)]
    public ICollection<string>? ConsentReference
    {
        get => _consentReference;
        set => _consentReference = value;
    }

    public List<string> Validate()
    {
        var notes = new List<string>();

        if (string.IsNullOrWhiteSpace(Version))
        {
            notes.Add($"Missing required {UdapConstants.HL7B2BUserAuthorizationExtension.Version}");
        }

        if (!UserPerson.HasValue || string.IsNullOrEmpty(UserPerson.Value.ToString()))
        {
            notes.Add($"Missing required {UdapConstants.HL7B2BUserAuthorizationExtension.UserPerson}");
        }

        if (PurposeOfUse == null || !PurposeOfUse.Any())
        {
            notes.Add($"Missing required {UdapConstants.HL7B2BUserAuthorizationExtension.PurposeOfUse}");
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
