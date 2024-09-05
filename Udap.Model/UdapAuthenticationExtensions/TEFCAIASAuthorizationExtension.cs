#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Udap.Model.UdapAuthenticationExtensions;

public class TEFCAIASAuthorizationExtension : Dictionary<string, object>
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
        get
        {
            _version = GetStandardClaim(UdapConstants.TEFCAIASAuthorizationExtension.Version) ?? _version;

            return _version;
        }
        set
        {
            _version = value;
            this[UdapConstants.TEFCAIASAuthorizationExtension.Version] = value;
        }
    }

    /// <summary>
    /// purpose_of_use required:
    /// 
    /// Fixed Value “T-IAS”. 
    /// </summary>
    [JsonPropertyName(UdapConstants.TEFCAIASAuthorizationExtension.PurposeOfUse)]
    public string PurposeOfUse
    {
        get
        {
            _purposeOfUse = GetStandardClaim(UdapConstants.TEFCAIASAuthorizationExtension.PurposeOfUse) ?? _purposeOfUse;

            return _purposeOfUse;
        }
        set
        {
            _purposeOfUse = value;
            this[UdapConstants.TEFCAIASAuthorizationExtension.PurposeOfUse] = value;
        }
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
        get
        {
            if (_userInformation.HasValue)
            {
                return _userInformation;
            }

            if (TryGetValue(UdapConstants.TEFCAIASAuthorizationExtension.UserInformation, out var value) && value is JsonElement element)
            {
                _userInformation = element;
                return element;
            }

            return null;
        }
        set
        {
            _userInformation = value;
            if (value != null) this[UdapConstants.TEFCAIASAuthorizationExtension.UserInformation] = value;
        }
    }

    /// <summary>
    /// patient_information required:
    ///
    /// FHIR US Core Patient Resource with all known and validated demographics
    /// </summary>
    [JsonPropertyName(UdapConstants.TEFCAIASAuthorizationExtension.PatientInformation)]
    public JsonElement? PatientInformation
    {
        get
        {
            if (_patientInformation.HasValue)
            {
                return _patientInformation;
            }

            if (TryGetValue(UdapConstants.TEFCAIASAuthorizationExtension.PatientInformation, out var value) && value is JsonElement element)
            {
                _patientInformation = element;
                return element;
            }

            return null;
        }
        set
        {
            _patientInformation = value;
            if (value != null) this[UdapConstants.TEFCAIASAuthorizationExtension.PatientInformation] = value;
        }
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
        get
        {
            if (_consentPolicy != null && !_consentPolicy.Any())
            {
                foreach (var item in GetIListClaims(UdapConstants.HL7B2BAuthorizationExtension.ConsentPolicy))
                {
                    _consentPolicy.Add(item);
                }
            }
            return _consentPolicy;
        }
        set
        {
            _consentPolicy = value;
            if (value != null) this[UdapConstants.TEFCAIASAuthorizationExtension.ConsentPolicy] = value;
        }
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
        get
        {
            if (_consentReference != null && !_consentReference.Any())
            {
                foreach (var item in GetIListClaims(UdapConstants.HL7B2BAuthorizationExtension.ConsentReference))
                {
                    _consentReference.Add(item);
                }
            }
            return _consentReference;
        }
        set
        {
            _consentReference = value;
            if (value != null) this[UdapConstants.TEFCAIASAuthorizationExtension.ConsentReference] = value;
        }
    }
    
    /// <summary>
    /// id_token optional:
    /// 
    /// Additional token as per relevant SOP
    /// </summary>
    [JsonPropertyName(UdapConstants.TEFCAIASAuthorizationExtension.IdToken)]
    public JsonElement? IdToken
    {
        get
        {
            if (_idToken.HasValue)
            {
                return _idToken;
            }

            if (TryGetValue(UdapConstants.TEFCAIASAuthorizationExtension.IdToken, out var value) && value is JsonElement element)
            {
                _idToken = element;
                return element;
            }

            return null;
        }
        set
        {
            _idToken = value;
            if (value != null) this[UdapConstants.TEFCAIASAuthorizationExtension.IdToken] = value;
        }
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
        get
        {
            if (_ialVetted.HasValue)
            {
                return _ialVetted;
            }

            if (TryGetValue(UdapConstants.TEFCAIASAuthorizationExtension.IalVetted, out var value) && value is JsonElement element)
            {
                _ialVetted = element;
                return element;
            }

            return null;
        }
        set
        {
            _ialVetted = value;
            if (value != null) this[UdapConstants.TEFCAIASAuthorizationExtension.IalVetted] = value;
        }
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

        if (!TryGetValue(claimType, out var value))
        {
            return claimValues;
        }

        if (value is string str)
        {
            claimValues.Add(str);
            return claimValues;
        }

        if (value is JsonElement { ValueKind: JsonValueKind.Array } element)
        {
            foreach (var item in element.EnumerateArray())
            {
                claimValues.Add(item.ToString());
            }
            return claimValues;
        }

        if (value is IEnumerable<string> values)
        {
            foreach (var item in values)
            {
                claimValues.Add(item);
            }
        }
        else
        {
            claimValues.Add(JsonSerializer.Serialize(value));
        }

        return claimValues;
    }
    
    internal string? GetStandardClaim(string claimType)
    {
        if (TryGetValue(claimType, out object? value))
        {
            if (value is JsonElement element)
            {
                if (element.ValueKind == JsonValueKind.String)
                {
                    return element.GetString();
                }
                else if (element.ValueKind == JsonValueKind.Object)
                {
                    return element.GetRawText();
                }
            }
        }

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
            Converters = { new TEFCAIASAuthorizationExtensionConverter(indented) },
            WriteIndented = indented
        });
    }

}
