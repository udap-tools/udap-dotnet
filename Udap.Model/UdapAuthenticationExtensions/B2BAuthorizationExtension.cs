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
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Udap.Model.UdapAuthenticationExtensions;


public class B2BAuthorizationExtension : Dictionary<string, object>
{
    private string _version = "1";
    private string? _subjectName;
    private string? _subjectId;
    private string? _subjectRole;
    private string? _organizationName;
    private string? _organizationId = default!;
    private ICollection<string> _purposeOfUse = new HashSet<string>();
    private ICollection<string>? _consentPolicy;
    private ICollection<string>? _consentReference;

    public B2BAuthorizationExtension()
    {
        Version = _version;
    }

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

    [JsonPropertyName(UdapConstants.B2BAuthorizationExtension.OrganizationName)]
    public string? OraganizationName
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

    [JsonPropertyName(UdapConstants.B2BAuthorizationExtension.PurposeOfUse)]
    public ICollection<string> PurposeOfUse
    {
        get
        {
            if (!_purposeOfUse.Any())
            {
                _purposeOfUse = GetIListClaims(UdapConstants.B2BAuthorizationExtension.PurposeOfUse);
            }
            return _purposeOfUse;
        }
        set
        {
            _purposeOfUse = value;
            this[UdapConstants.B2BAuthorizationExtension.PurposeOfUse] = value;
        }
    }

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
            if (value is string str)
                return str;

            if (value is JsonElement element)
            {
                if (element.ValueKind == JsonValueKind.String)
                {
                    return element.GetString();
                }
            }

            return JsonSerializer.Serialize(value);
        }

        return null;
    }
}
