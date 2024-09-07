using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Udap.Model.UdapAuthenticationExtensions;

/// <summary>
/// User this for code like building hl7-b2b extension objects
///
/// <a href="http://hl7.org/fhir/us/udap-security/b2b.html#constructing-authentication-token">HL7 B2B</a>
/// </summary>
public class HL7B2BAuthorizationExtension
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

    public HL7B2BAuthorizationExtension()
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
    [JsonPropertyName(UdapConstants.HL7B2BAuthorizationExtension.Version)]
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
    [JsonPropertyName(UdapConstants.HL7B2BAuthorizationExtension.SubjectName)]
    public string? SubjectName
    {
        get => _subjectName;
        set => _subjectName = value;
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
    [JsonPropertyName(UdapConstants.HL7B2BAuthorizationExtension.SubjectId)]
    public string? SubjectId
    {
        get => _subjectId;
        set => _subjectId = value;
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
    [JsonPropertyName(UdapConstants.HL7B2BAuthorizationExtension.SubjectRole)]
    public string? SubjectRole
    {
        get => _subjectRole;
        set => _subjectRole = value;
    }

    /// <summary>
    /// organization_name optional:
    ///
    /// String containing the human readable name of the organizational requestor. If a subject is named,
    /// the organizational requestor is the organization represented by the subject.
    /// </summary>
    [JsonPropertyName(UdapConstants.HL7B2BAuthorizationExtension.OrganizationName)]
    public string? OrganizationName
    {
        get => _organizationName;
        set => _organizationName = value;
    }

    /// <summary>
    /// organization_id required:
    /// 
    /// String containing a unique identifier for the organizational requestor. If a subject is named, the
    /// organizational requestor is the organization represented by the subject. The identifier SHALL be a
    /// Uniform Resource Identifier (URI). Trust communities SHALL define the allowed URI scheme(s). If a URL
    /// is used, the issuer SHALL include a URL that is resolvable by the receiving party.
    /// </summary>
    [JsonPropertyName(UdapConstants.HL7B2BAuthorizationExtension.OrganizationId)]
    public string? OrganizationId
    {
        get => _organizationId;
        set => _organizationId = value;
    }

    /// <summary>
    /// purpose_of_use required:
    /// 
    /// An array of one or more strings, each containing a code identifying a purpose for which the data is being
    /// requested. For US Realm, trust communities SHOULD constrain the allowed values, and are encouraged to
    /// draw from the HL7 PurposeOfUse value set, but are not required to do so to be considered conformant.
    /// See Section 5.2.1.2 below for the preferred format of each code value string array element.
    /// </summary>
    [JsonPropertyName(UdapConstants.HL7B2BAuthorizationExtension.PurposeOfUse)]
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
    [JsonPropertyName(UdapConstants.HL7B2BAuthorizationExtension.ConsentPolicy)]
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
    [JsonPropertyName(UdapConstants.HL7B2BAuthorizationExtension.ConsentReference)]
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
            notes.Add($"Missing required {UdapConstants.HL7B2BAuthorizationExtension.Version}");
        }

        if (string.IsNullOrWhiteSpace(OrganizationId))
        {
            notes.Add($"Missing required {UdapConstants.HL7B2BAuthorizationExtension.OrganizationId}");
        }

        if (PurposeOfUse != null && !PurposeOfUse.Any())
        {
            notes.Add($"Missing required {UdapConstants.HL7B2BAuthorizationExtension.PurposeOfUse}");
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
