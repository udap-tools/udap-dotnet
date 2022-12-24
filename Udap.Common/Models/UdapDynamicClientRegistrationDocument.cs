#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Microsoft.IdentityModel.Tokens;

namespace Udap.Common.Models;

public class UdapDynamicClientRegistrationDocument : Dictionary<string, object>
{
    private string? _clientId;
    private string? _softwareStatement;
    private string? _issuer;
    private string? _subject;
    private string? _audience;
    private long _expiration;
    private long _issuedAt;
    private string? _jwtId;
    private string? _clientName;
    private ICollection<Uri> _redirectUris = new HashSet<Uri>();
    private ICollection<string> _contacts = new HashSet<string>();
    private ICollection<string> _grantTypes = new HashSet<string>();
    private ICollection<string> _responseTypes = new HashSet<string>();
    private string? _tokenEndpointAuthMethod;
    private string? _scope;
    private Uri? _clientUri;


    [JsonPropertyName(UdapConstants.RegistrationDocumentValues.ClientId)]
    public string? ClientId
    {
        get
        {
            if (_clientId == null)
            {
                _clientId = GetStandardClaim(UdapConstants.RegistrationDocumentValues.ClientId);
            }

            return _clientId;
        }
        set
        {
            _clientId = value;
            if (value != null) this[UdapConstants.RegistrationDocumentValues.ClientId] = value;
        }
    }

    [JsonPropertyName(UdapConstants.RegistrationRequestBody.SoftwareStatement)]
    public string? SoftwareStatement
    {
        get
        {
            if (_softwareStatement == null)
            {
                _softwareStatement = GetStandardClaim(UdapConstants.RegistrationDocumentValues.SoftwareStatement);
            }

            return _softwareStatement;
        }
        set
        {
            _softwareStatement = value;
            if (value != null) this[UdapConstants.RegistrationDocumentValues.SoftwareStatement] = value;
        }
    }

    /// <summary>
/// Issuer of the JWT -- unique identifying client URI. This SHALL match the value of a
/// uniformResourceIdentifier entry in the Subject Alternative Name extension of the client's
/// certificate included in the x5c JWT header
/// </summary>
[JsonPropertyName(UdapConstants.RegistrationDocumentValues.Issuer)]
    public string? Issuer
    {
        get
        {
            if (_issuer == null)
            {
                _issuer = GetStandardClaim(UdapConstants.RegistrationDocumentValues.Issuer);
            }
            return _issuer;
        }
        set
        {
            _issuer = value;
            if (value != null) this[UdapConstants.RegistrationDocumentValues.Issuer] = value;
        }
    }

    /// <summary>
    /// Same as iss. In typical use, the client application will not yet have a client_id from
    /// the Authorization Server
    /// </summary>
    [JsonPropertyName(UdapConstants.RegistrationDocumentValues.Subject)]
    public string? Subject
    {
        get
        {
            if (_subject == null)
            {
                _subject = GetStandardClaim(UdapConstants.RegistrationDocumentValues.Subject);
            }
            return _subject;
        }
        set
        {
            _subject = value;
            if (value != null) this[UdapConstants.RegistrationDocumentValues.Subject] = value;
        }
    }

    /// <summary>
    /// The Authorization Server's "registration URL" (the same URL to which the registration
    /// request  will be posted)
    /// </summary>
    [JsonPropertyName(UdapConstants.RegistrationDocumentValues.Audience)]
    public string? Audience
    {
        get
        {
            if (_audience == null)
            {
                _audience = GetStandardClaim(UdapConstants.RegistrationDocumentValues.Audience);
            }
            return _audience;
        }
        set
        {
            _audience = value;
            if (value != null) this[UdapConstants.RegistrationDocumentValues.Audience] = value;
        }
    }

    /// <summary>
    /// Expiration time integer for this software statement, expressed in seconds since the
    /// "Epoch" (1970-01-01T00:00:00Z UTC). The exp time SHALL be no more than 5 minutes after
    /// the value of the iat claim.
    /// </summary>
    [JsonPropertyName(UdapConstants.RegistrationDocumentValues.Expiration)]
    public long Expiration
    {
        get => _expiration;
        set
        {
            _expiration = value;
            this[UdapConstants.RegistrationDocumentValues.Expiration] = value;
        }
    }

    /// <summary>
    /// Issued time integer for this software statement, expressed in seconds since the "Epoch"
    /// </summary>
    [JsonPropertyName(UdapConstants.RegistrationDocumentValues.IssuedAt)]
    public long IssuedAt
    {
        get => _issuedAt;
        set
        {
            _issuedAt = value;
            this[UdapConstants.RegistrationDocumentValues.IssuedAt] = value;
        }
    }

    /// <summary>
    /// A nonce string value that uniquely identifies this software statement. This value
    /// SHALL NOT be reused by the client app in another software statement or authentication
    /// JWT before the time specified in the exp claim has passed
    /// </summary>
    [JsonPropertyName(UdapConstants.RegistrationDocumentValues.JwtId)]
    public string? JwtId
    {
        get => _jwtId;
        set
        {
            _jwtId = value;
            if (value != null) this[UdapConstants.RegistrationDocumentValues.JwtId] = value;
        }
    }

    /// <summary>
    /// A string containing the human readable name of the client application
    /// </summary>
    [JsonPropertyName(UdapConstants.RegistrationDocumentValues.ClientName)]
    public string? ClientName
    {
        get
        {
            if (string.IsNullOrEmpty(_clientName))
            {
                _clientName = GetStandardClaim(UdapConstants.RegistrationDocumentValues.ClientName);
            }
            return _clientName;
        }
        set
        {
            _clientName = value;
            if (value != null) this[UdapConstants.RegistrationDocumentValues.ClientName] = value;
        }
    }

    /// <summary>
    /// List of redirection URI strings for use in redirect-based flows such as the authorization code and implicit flows.
    /// </summary>
    /// <remarks>
    /// Clients using flows with redirection must register their redirection URI values.
    /// </remarks>
    [JsonPropertyName(UdapConstants.RegistrationDocumentValues.RedirectUris)]
    public ICollection<Uri> RedirectUris
    {
        get => _redirectUris;
        set => _redirectUris = value;
    }

    /// <summary>
    /// A string containing the human readable name of the client application
    /// </summary>
    [JsonPropertyName(UdapConstants.RegistrationDocumentValues.Contacts)]
    public ICollection<string> Contacts
    {
        get
        {
            if (!_contacts.Any())
            {
                _contacts = GetIListClaims(UdapConstants.RegistrationDocumentValues.Contacts);
            }
            return _contacts;
        }
        set
        {
            _contacts = value;
            this[UdapConstants.RegistrationDocumentValues.Contacts] = value;
        }
    }

    /// <summary>
    /// List of OAuth 2.0 grant type strings that the client can use at the token endpoint.
    /// </summary>
    /// <remarks>
    /// Example: "authorization_code", "client_credentials", "refresh_token".
    /// </remarks>
    [JsonPropertyName(UdapConstants.RegistrationDocumentValues.GrantTypes)]
    public ICollection<string> GrantTypes
    {
        get
        {
            if (!_grantTypes.Any())
            {
                _grantTypes = GetIListClaims(UdapConstants.RegistrationDocumentValues.GrantTypes);
            }
            return _grantTypes;
        }
        set
        {
            _grantTypes = value;
            this[UdapConstants.RegistrationDocumentValues.GrantTypes] = value;
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

        if (value is IEnumerable<string> values)
        {
            foreach (var item in values)
            {
                claimValues.Add(item);
            }
        }
        else
        {
            claimValues.Add(JsonExtensions.SerializeToJson(value));
        }

        return claimValues;
    }

    /// <summary>
/// Array of strings. If grant_types contains "authorization_code", then this element SHALL
/// have a fixed value of ["code"], and SHALL be omitted otherwise
/// </summary>
[JsonPropertyName(UdapConstants.RegistrationDocumentValues.ResponseTypes)]
    public ICollection<string> ResponseTypes
    {
        get => _responseTypes;
        set
        {
            _responseTypes = value;
            this[UdapConstants.RegistrationDocumentValues.ResponseTypes] = value;
        }
    }


    [JsonPropertyName(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethod)]
    public string? TokenEndpointAuthMethod
    {
        get
        {
            if (string.IsNullOrEmpty(_tokenEndpointAuthMethod))
            {
                _tokenEndpointAuthMethod = this[UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethod] as string;
            }
            return _tokenEndpointAuthMethod;
        }
        set
        {
            _tokenEndpointAuthMethod = value;
            if (value != null) this[UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethod] = value;
        }
    }


    /// <summary>
    /// String containing a space delimited list of scopes requested by the client application
    /// for use in subsequent requests. The Authorization Server MAY consider this list when
    /// deciding the scopes that it will allow the application to subsequently request. Note
    /// for client apps that also support the SMART App Launch framework: apps requesting the
    /// "client_credentials" grant type SHOULD request system scopes; apps requesting the
    /// "authorization_code" grant type SHOULD request user or patient scopes.
    /// </summary>
    [JsonPropertyName(UdapConstants.RegistrationDocumentValues.Scope)]
    public string? Scope
    {
        get
        {
            if (string.IsNullOrEmpty(_scope))
            {
                _scope = this[UdapConstants.RegistrationDocumentValues.Scope] as string;
            }
            return _scope;
        }
        set
        {
            _scope = value;
            if (value != null) this[UdapConstants.RegistrationDocumentValues.Scope] = value;
        }
    }

    /// <summary>
    /// Similar to  <see cref="JwtPayload.AddClaims"/>.
    /// Adds a number of <see cref="System.Security.Claims.Claim"/> to the <see cref="UdapDynamicClientRegistrationDocument"/>.
    /// Unlike <see cref="JwtPayload.AddClaims"/>, UDAP claims defined to be collections of values will be maintained as
    /// collections even if only one item exists.  
    /// </summary>
    /// <param name="claims">For each <see cref="System.Security.Claims.Claim"/> a JSON pair { 'Claim.Type', 'Claim.Value' } is added.
    /// If duplicate claims are found then a { 'Claim.Type', List&lt;object&gt; } will be created to contain the duplicate values.
    /// This is only needed for claims not defined in the UDAP profile</param>
    /// <remarks>
    /// <para>Any <see cref="System.Security.Claims.Claim"/> in the <see cref="System.Collections.Generic.IEnumerable{T}"/> that is null, will be ignored.</para></remarks>
    /// <exception cref="System.ArgumentNullException"><paramref name="claims"/> is null.</exception>
    public void AddClaims(IEnumerable<Claim> claims)
    {
        if (claims == null)
        {   //TODO: Add telemetry data via Activity.  
            // The JwtPayload.AddClaims uses a EventSource implementation called IdentityModelEventSource to allow visibility into errors.
            //
            // The code was this:
            //
            // if (claims == null)
            //     throw LogHelper.LogExceptionMessage(new ArgumentNullException(nameof(claims)));
            //

            throw new ArgumentNullException(nameof(claims));
        }
        

        foreach (Claim claim in claims)
        {
            if (claim == null)
            {
                continue;
            }

            string jsonClaimType = claim.Type;
            object jsonClaimValue = claim.ValueType.Equals(ClaimValueTypes.String) ? claim.Value : GetClaimValueUsingValueType(claim);
            object existingValue;

            // If there is an existing value, append to it.
            // What to do if the 'ClaimValueType' is not the same.
            if (TryGetValue(jsonClaimType, out existingValue))
            {
                if (existingValue is HashSet<string> knownClaimValueType)
                {
                    switch (claim.Type)
                    {
                        case UdapConstants.RegistrationDocumentValues.Contacts:
                        case UdapConstants.RegistrationDocumentValues.GrantTypes:
                        case UdapConstants.RegistrationDocumentValues.ResponseTypes:
                            

                            knownClaimValueType.Add(jsonClaimValue as string);
                            continue;
                    }
                }

                if (existingValue is not IList<object> claimValues)
                {
                    claimValues = new List<object>();
                    claimValues.Add(existingValue);
                    this[jsonClaimType] = claimValues;
                }

                claimValues.Add(jsonClaimValue);
                break;
            }
            else
            {
                switch (claim.Type)
                {
                    case UdapConstants.RegistrationDocumentValues.Contacts:
                    case UdapConstants.RegistrationDocumentValues.GrantTypes:
                    case UdapConstants.RegistrationDocumentValues.ResponseTypes:

                        var grantTypes = new HashSet<string>() { jsonClaimValue as string };

                        this[jsonClaimType] = grantTypes;
                        break;

                    default:
                        this[jsonClaimType] = jsonClaimValue;
                        break;
                }
            }
        }
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

            return JsonExtensions.SerializeToJson(value);
        }

        return null;
    }

    internal static object GetClaimValueUsingValueType(Claim claim)
    {
        if (claim.ValueType == ClaimValueTypes.String)
            return claim.Value;

        if (claim.ValueType == ClaimValueTypes.Boolean && bool.TryParse(claim.Value, out bool boolValue))
            return boolValue;

        if (claim.ValueType == ClaimValueTypes.Double && double.TryParse(claim.Value, NumberStyles.Any, CultureInfo.InvariantCulture, out double doubleValue))
            return doubleValue;

        if ((claim.ValueType == ClaimValueTypes.Integer || claim.ValueType == ClaimValueTypes.Integer32) && int.TryParse(claim.Value, NumberStyles.Any, CultureInfo.InvariantCulture, out int intValue))
            return intValue;

        if (claim.ValueType == ClaimValueTypes.Integer64 && long.TryParse(claim.Value, out long longValue))
            return longValue;

        if (claim.ValueType == ClaimValueTypes.DateTime && DateTime.TryParse(claim.Value, out DateTime dateTimeValue))
            return dateTimeValue;

        if (claim.ValueType == JsonClaimValueTypes.Json)
            return JsonObject.Parse(claim.Value);

        if (claim.ValueType == JsonClaimValueTypes.JsonArray)
            return JsonArray.Parse(claim.Value);

        if (claim.ValueType == JsonClaimValueTypes.JsonNull)
            return string.Empty;

        return claim.Value;
    }


    /// <summary>
    /// Serializes this instance to JSON.
    /// </summary>
    /// <returns>This instance as JSON.</returns>
    /// <remarks>Use <see cref="JsonExtensions.Serializer"/> to customize JSON serialization.</remarks>
    public virtual string SerializeToJson()
    {
        return JsonExtensions.SerializeToJson(this as IDictionary<string, object>);
    }

    /// <summary>
    /// Encodes this instance as Base64UrlEncoded JSON.
    /// </summary>
    /// <returns>Base64UrlEncoded JSON.</returns>
    /// <remarks>Use <see cref="JsonExtensions.Serializer"/> to customize JSON serialization.</remarks>
    public virtual string Base64UrlEncode()
    {
        return Base64UrlEncoder.Encode(SerializeToJson());
    }
}