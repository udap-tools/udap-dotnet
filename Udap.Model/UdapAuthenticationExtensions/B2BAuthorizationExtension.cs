#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Udap.Model.UdapAuthenticationExtensions;

public class B2BAuthorizationExtensionConverter : JsonConverter<B2BAuthorizationExtension>
{
    public override B2BAuthorizationExtension Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var dictionary = JsonSerializer.Deserialize<Dictionary<string, object>>(ref reader, options);
        var extension = new B2BAuthorizationExtension();
        foreach (var kvp in dictionary)
        {
            extension[kvp.Key] = kvp.Value;
        }
        return extension;
    }

    public override void Write(Utf8JsonWriter writer, B2BAuthorizationExtension value, JsonSerializerOptions options)
    {
        var dictionary = new Dictionary<string, object>(value);
        var properties = value.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);

        foreach (var property in properties)
        {
            if (property.CanRead && property.GetValue(value) is object propertyValue)
            {
                var jsonPropertyName = property.GetCustomAttributes(typeof(JsonPropertyNameAttribute), false)
                    .FirstOrDefault() as JsonPropertyNameAttribute;
                var propertyName = jsonPropertyName?.Name ?? property.Name;
                dictionary[propertyName] = propertyValue;
            }
        }
        JsonSerializer.Serialize(writer, dictionary, options);
    }
}

public class B2BAuthorizationExtension : Dictionary<string, object>
{
    private string _version = "1";
    private string? _subjectName;
    private string? _subjectId;
    private string? _subjectRole;
    private string? _organizationName;
    private string? _organizationId = default!;
    private ICollection<string>? _purposeOfUse;
    private ICollection<string>? _consentPolicy;
    private ICollection<string>? _consentReference;

    public B2BAuthorizationExtension()
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
    [JsonPropertyName(UdapConstants.B2BAuthorizationExtension.Version)]
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
    [JsonPropertyName(UdapConstants.B2BAuthorizationExtension.SubjectName)]
    public string? SubjectName
    {
        get
        {
            return _subjectName ??= GetStandardClaim(UdapConstants.B2BAuthorizationExtension.SubjectName);
        }
        set
        {
            _subjectName = value;
            if (value != null) this[UdapConstants.B2BAuthorizationExtension.SubjectName] = value;
        }
    }

    /// <summary>
    /// subject_id conditional:
    ///
    /// String containing a unique identifier for the requestor; required if known for
    /// human requestors when the subject_name parameter is present. For US Realm, the
    /// value SHALL be the subject's individual National Provider Identifier (NPI); omit
    /// for non-human requestors and for requestors who have not been assigned an NPI.
    /// See Section 5.2.1.2 below for the preferred format of the identifier value string.
    /// </summary>
    [JsonPropertyName(UdapConstants.B2BAuthorizationExtension.SubjectId)]
    public string? SubjectId
    {
        get { return _subjectId ??= GetStandardClaim(UdapConstants.B2BAuthorizationExtension.SubjectId); }
        set
        {
            _subjectId = value;
            if (value != null) this[UdapConstants.B2BAuthorizationExtension.SubjectId] = value;
        }
    }

    /// <summary>
    /// subject_role conditional:
    ///
    /// String containing a code identifying the role of the requestor; required if known for
    /// human requestors when the subject_name parameter is present. For US Realm, trust communities
    /// SHOULD constrain the allowed values and formats, and are encouraged to draw from the National
    /// Uniform Claim Committee (NUCC) Provider Taxonomy Code Set, but are not required to do so
    /// to be considered conformant. See Section 5.2.1.2 below for the preferred format of the code
    /// value string.
    /// </summary>
    [JsonPropertyName(UdapConstants.B2BAuthorizationExtension.SubjectRole)]
    public string? SubjectRole
    {
        get
        {
            return _subjectRole ??= GetStandardClaim(UdapConstants.B2BAuthorizationExtension.SubjectRole);
        }
        set
        {
            _subjectRole = value;
            if (value != null) this[UdapConstants.B2BAuthorizationExtension.SubjectRole] = value;
        }
    }

    /// <summary>
    /// organization_name optional:
    ///
    /// String containing the human readable name of the organizational requestor. If a subject is named,
    /// the organizational requestor is the organization represented by the subject.
    /// </summary>
    [JsonPropertyName(UdapConstants.B2BAuthorizationExtension.OrganizationName)]
    public string? OrganizationName
    {
        get
        {
            return _organizationName ??= GetStandardClaim(UdapConstants.B2BAuthorizationExtension.OrganizationName);
        }
        set
        {
            _organizationName = value;
            if (value != null) this[UdapConstants.B2BAuthorizationExtension.OrganizationName] = value;
        }
    }

    /// <summary>
    /// organization_id required:
    /// 
    /// String containing a unique identifier for the organizational requestor. If a subject is named, the
    /// organizational requestor is the organization represented by the subject. The identifier SHALL be a
    /// Uniform Resource Identifier (URI). Trust communities SHALL define the allowed URI scheme(s). If a URL
    /// is used, the issuer SHALL include a URL that is resolvable by the receiving party.
    /// </summary>
    [JsonPropertyName(UdapConstants.B2BAuthorizationExtension.OrganizationId)]
    public string? OrganizationId
    {
        get
        {
            if (_organizationId == null)
            {
                _organizationId = GetStandardClaim(UdapConstants.B2BAuthorizationExtension.OrganizationId);
            }

            return _organizationId;
        }
        set
        {
            _organizationId = value;
            if (value != null) this[UdapConstants.B2BAuthorizationExtension.OrganizationId] = value;
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
    [JsonPropertyName(UdapConstants.B2BAuthorizationExtension.PurposeOfUse)]
    public ICollection<string>? PurposeOfUse
    {
        get
        {
            if (_purposeOfUse != null && !_purposeOfUse.Any())
            {
                _purposeOfUse = GetIListClaims(UdapConstants.B2BAuthorizationExtension.PurposeOfUse);
            }
            return _purposeOfUse;
        }
        set
        {
            
            _purposeOfUse = value;
            if (value == null)
            {
                this.Remove(UdapConstants.B2BAuthorizationExtension.PurposeOfUse);
            }
            else
            {
                this[UdapConstants.B2BAuthorizationExtension.PurposeOfUse] = value;
            }
        }
    }

    /// <summary>
    /// consent_policy optional:
    /// 
    /// An array of one or more strings, each containing a URI identifying a privacy consent directive policy
    /// or other policy consistent with the value of the purpose_of_use parameter.
    /// </summary>
    [JsonPropertyName(UdapConstants.B2BAuthorizationExtension.ConsentPolicy)]
    public ICollection<string>? ConsentPolicy
    {
        get
        {
            if (_consentPolicy != null && !_consentPolicy.Any())
            {
                _consentPolicy = GetIListClaims(UdapConstants.B2BAuthorizationExtension.ConsentPolicy);
            }
            return _consentPolicy;
        }
        set
        {
            _consentPolicy = value;
            if (value != null) this[UdapConstants.B2BAuthorizationExtension.ConsentPolicy] = value;
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
    [JsonPropertyName(UdapConstants.B2BAuthorizationExtension.ConsentReference)]
    public ICollection<string>? ConsentReference
    {
        get
        {
            if (_consentReference != null && !_consentReference.Any())
            {
                _consentReference = GetIListClaims(UdapConstants.B2BAuthorizationExtension.ConsentReference);
            }
            return _consentReference;
        }
        set
        {
            _consentReference = value;
            if (value != null) this[UdapConstants.B2BAuthorizationExtension.ConsentReference] = value;
        }
    }

    public List<string> Validate()
    {
        var notes = new List<string>();

        if (string.IsNullOrWhiteSpace(Version))
        {
            notes.Add("Missing required version");
        }

        if (string.IsNullOrWhiteSpace(OrganizationId))
        {
            notes.Add("Missing required organization_id");
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
            }
        }

        return null;
    }

    /// <summary>
    /// Serializes this instance to JSON.
    /// </summary>
    /// <returns>This instance as JSON.</returns>
    public virtual string SerializeToJson()
    {
        return JsonSerializer.Serialize(this, new JsonSerializerOptions
        {
            Converters = { new B2BAuthorizationExtensionConverter() }
        });
    }

}
