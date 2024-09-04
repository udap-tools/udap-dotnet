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

public class B2BUserAuthorizationExtension : Dictionary<string, object>
{
    private string _version = "1";
    private string? _userPerson;
    private ICollection<string>? _purposeOfUse;
    private ICollection<string>? _consentPolicy;
    private ICollection<string>? _consentReference;

    public B2BUserAuthorizationExtension()
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
    [JsonPropertyName(UdapConstants.B2BUserAuthorizationExtension.Version)]
    public string Version
    {
        get
        {
            _version = GetStandardClaim("version") ?? _version;

            return _version;
        }
        set
        {
            _version = value;
            this["version"] = value;
        }
    }

    /// <summary>
    /// subject_name conditional:
    ///
    /// String containing the human readable name of the human or non-human requestor; required if known.
    /// </summary>
    [JsonPropertyName(UdapConstants.B2BUserAuthorizationExtension.UserPerson)]
    public string? UserPerson
    {
        get
        {
            return _userPerson ??= GetStandardClaim(UdapConstants.B2BUserAuthorizationExtension.UserPerson);
        }
        set
        {
            _userPerson = value;
            if (value != null) this[UdapConstants.B2BUserAuthorizationExtension.UserPerson] = value;
        }
    }

    
    /// <summary>
    /// purpose_of_use required:
    /// 
    /// An array of one or more strings, each containing a code identifying a purpose for which the data is being
    /// requested. For US Realm, trust communities SHOULD constrain the allowed values, and are encouraged to
    /// draw from the HL7 PurposeOfUse value set, but are not required to do so to be considered conformant.
    /// See Section 5.2.1.2 below for the preferred format of each code value string array element.
    /// </summary>
    [JsonPropertyName(UdapConstants.B2BUserAuthorizationExtension.PurposeOfUse)]
    public ICollection<string>? PurposeOfUse
    {
        get
        {
            if (_purposeOfUse != null && !_purposeOfUse.Any())
            {
                foreach (var item in GetIListClaims(UdapConstants.B2BAuthorizationExtension.PurposeOfUse))
                {
                    _purposeOfUse.Add(item);
                }
            }
            return _purposeOfUse;
        }
        set
        {
            
            _purposeOfUse = value;
            if (value == null)
            {
                this.Remove(UdapConstants.B2BUserAuthorizationExtension.PurposeOfUse);
            }
            else
            {
                this[UdapConstants.B2BUserAuthorizationExtension.PurposeOfUse] = value;
            }
        }
    }

    /// <summary>
    /// consent_policy optional:
    /// 
    /// An array of one or more strings, each containing a URI identifying a privacy consent directive policy
    /// or other policy consistent with the value of the purpose_of_use parameter.
    /// </summary>
    [JsonPropertyName(UdapConstants.B2BUserAuthorizationExtension.ConsentPolicy)]
    public ICollection<string>? ConsentPolicy
    {
        get
        {
            if (_consentPolicy != null && !_consentPolicy.Any())
            {
                foreach (var item in GetIListClaims(UdapConstants.B2BAuthorizationExtension.ConsentPolicy))
                {
                    _consentPolicy.Add(item);
                }
            }
            return _consentPolicy;
        }
        set
        {
            _consentPolicy = value;
            if (value != null) this[UdapConstants.B2BUserAuthorizationExtension.ConsentPolicy] = value;
        }
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
    [JsonPropertyName(UdapConstants.B2BUserAuthorizationExtension.ConsentReference)]
    public ICollection<string>? ConsentReference
    {
        get
        {
            if (_consentReference != null && !_consentReference.Any())
            {
                foreach (var item in GetIListClaims(UdapConstants.B2BAuthorizationExtension.ConsentReference))
                {
                    _consentReference.Add(item);
                }
            }
            return _consentReference;
        }
        set
        {
            _consentReference = value;
            if (value != null) this[UdapConstants.B2BUserAuthorizationExtension.ConsentReference] = value;
        }
    }

    public List<string> Validate()
    {
        var notes = new List<string>();

        if (string.IsNullOrWhiteSpace(Version))
        {
            notes.Add("Missing required version");
        }

        if (string.IsNullOrWhiteSpace(UserPerson))
        {
            notes.Add("Missing required user_person");
        }

        if (!PurposeOfUse.Any())
        {
            notes.Add("Missing required purpose_of_use");
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
            Converters = { new B2BUserAuthorizationExtensionConverter() },
            WriteIndented = indented
        });
    }

}
