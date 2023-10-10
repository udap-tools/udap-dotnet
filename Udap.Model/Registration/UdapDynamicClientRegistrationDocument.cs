#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

//
// Most of this file is copied from Duende's Identity Server dom/dcr-proc branch
// Note in my case it inherits from Dictionary<string, object> so I can use it like
// a System.IdentityModel.Tokens.Jwt.JwtPayload object.
//

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Microsoft.IdentityModel.Tokens;

namespace Udap.Model.Registration;

/// <summary>
/// https://www.rfc-editor.org/rfc/rfc7591#section-2
/// Client Metadata
/// </summary>
public class UdapDynamicClientRegistrationDocument : Dictionary<string, object>, ISoftwareStatementSerializer
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
    private Uri? _clientUri;
    private ICollection<string>? _redirectUris = new List<string>();
    private string? _logoUri;
    private ICollection<string>? _contacts = new HashSet<string>();
    private ICollection<string>? _grantTypes = new HashSet<string>();
    private ICollection<string>? _responseTypes = new HashSet<string>();
    private string? _tokenEndpointAuthMethod;
    private string? _scope;

    /// <summary>
    /// Array of redirection URI strings for use in redirect-based flows
    /// such as the authorization code and implicit flows.  As required by
    /// Section 2 of OAuth 2.0 [RFC6749], clients using flows with
    /// redirection MUST register their redirection URI values.
    /// Authorization servers that support dynamic registration for
    ///redirect-based flows MUST implement support for this metadata
    /// value.
    /// </summary>
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
        get
        {
            if (_expiration == 0)
            {
                _expiration = GetStandardInt64Claim(UdapConstants.RegistrationDocumentValues.Expiration);
            }

            return _expiration;
        }
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
        get
        {
            if (_issuedAt == 0)
            {
                _issuedAt = GetStandardInt64Claim(UdapConstants.RegistrationDocumentValues.IssuedAt);
            }

            return _issuedAt;
        }
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
        get
        {
            if (string.IsNullOrEmpty(_jwtId))
            {
                _jwtId = GetStandardClaim(UdapConstants.RegistrationDocumentValues.JwtId);
            }
            return _jwtId;
        }
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
    /// Web page providing information about the client.
    /// See <a aref="https://datatracker.ietf.org/doc/html/rfc7591#section-2"/>
    /// </summary>
    [JsonPropertyName(UdapConstants.RegistrationDocumentValues.ClientUri)]
    public Uri? ClientUri {
        get
        {
            if (_clientUri == null)
            {
                if (Uri.TryCreate(GetStandardClaim(UdapConstants.RegistrationDocumentValues.ClientUri), UriKind.Absolute, out var value ))
                {
                    _clientUri = value;
                }
            }
            return _clientUri;
        }
        set
        {
            _clientUri = value;
            if (value != null) this[UdapConstants.RegistrationDocumentValues.ClientUri] = value;
        }
    }


    /// <summary>
    /// List of redirection URI strings for use in redirect-based flows such as the authorization code and implicit flows.
    /// </summary>
    /// <remarks>
    /// Clients using flows with redirection must register their redirection URI values.
    /// </remarks>
    [JsonPropertyName(UdapConstants.RegistrationDocumentValues.RedirectUris)]
    public ICollection<string>? RedirectUris
    {
        get
        {
            if (_redirectUris != null && !_redirectUris.Any())
            {
                _redirectUris = GetIListClaims(UdapConstants.RegistrationDocumentValues.RedirectUris);
            }
            return _redirectUris;
        }
        set
        {
            _redirectUris = value;
            if (value == null)
            {
                this.Remove(UdapConstants.RegistrationDocumentValues.RedirectUris);
            }
            else
            {
                this[UdapConstants.RegistrationDocumentValues.RedirectUris] = value;
            }
        }
    }

    // /// <summary>
    // /// URL string that references a logo for the client.  If present, the
    // /// server SHOULD display this image to the end-user during approval.
    // /// The value of this field MUST point to a valid image file.  The
    // /// value of this field MAY be internationalized, as described in
    // /// <a href="https://datatracker.ietf.org/doc/html/rfc7591#section-2.2">Section 2.2</a>.
    // /// </summary>
    [JsonPropertyName(UdapConstants.RegistrationDocumentValues.LogoUri)]
    public string? LogoUri
    {
        get
        {
            if (_logoUri == null)
            {
                if (Uri.TryCreate(GetStandardClaim(UdapConstants.RegistrationDocumentValues.LogoUri), UriKind.Absolute, out var value))
                {
                    _logoUri = value.OriginalString;
                }
            }
            return _logoUri;
        }
        set
        {
            _logoUri = value;
            if (value != null) this[UdapConstants.RegistrationDocumentValues.LogoUri] = value;
        }
    }

    /// <summary>
    /// A string containing the human readable name of the client application
    /// </summary>
    [JsonPropertyName(UdapConstants.RegistrationDocumentValues.Contacts)]
    public ICollection<string>? Contacts
    {
        get
        {
            if (_contacts != null && !_contacts.Any())
            {
                _contacts = GetIListClaims(UdapConstants.RegistrationDocumentValues.Contacts);
            }
            return _contacts;
        }
        set
        {
            _contacts = value;
            if (value == null)
            {
                this.Remove(UdapConstants.RegistrationDocumentValues.Contacts);
            }
            else
            {
                this[UdapConstants.RegistrationDocumentValues.Contacts] = value;
            }
        }
    }

    /// <summary>
    /// List of OAuth 2.0 grant type strings that the client can use at the token endpoint.
    /// </summary>
    /// <remarks>
    /// Example: "authorization_code", "client_credentials", "refresh_token".
    /// </remarks>
    [JsonPropertyName(UdapConstants.RegistrationDocumentValues.GrantTypes)]
    public ICollection<string>? GrantTypes
    {
        get
        {
            if (_grantTypes != null && !_grantTypes.Any())
            {
                _grantTypes = GetIListClaims(UdapConstants.RegistrationDocumentValues.GrantTypes);
            }
            return _grantTypes;
        }
        set
        {
            _grantTypes = value;
            
            if (value == null)
            {
                this.Remove(UdapConstants.RegistrationDocumentValues.GrantTypes);
            }
            else
            {
                this[UdapConstants.RegistrationDocumentValues.GrantTypes] = value;
            }
        }
    }

    /// <summary>
    /// Array of strings. If grant_types contains "authorization_code", then this element SHALL
    /// have a fixed value of ["code"], and SHALL be omitted otherwise
    /// </summary>
    [JsonPropertyName(UdapConstants.RegistrationDocumentValues.ResponseTypes)]
    public ICollection<string>? ResponseTypes
    {
        get
        {
            if (_responseTypes != null && !_responseTypes.Any())
            {
                _responseTypes = GetIListClaims(UdapConstants.RegistrationDocumentValues.ResponseTypes);
            }
            return _responseTypes;
        }
        set
        {
            _responseTypes = value;
            
            if (value == null)
            {
                this.Remove(UdapConstants.RegistrationDocumentValues.ResponseTypes);
            }
            else
            {
                this[UdapConstants.RegistrationDocumentValues.ResponseTypes] = value;
            }
        }
    }

    /// <summary>
    /// String indicator of the requested authentication method for the
    /// token endpoint.Values defined by this specification are:
    /// 
    /// *  "none": The client is a public client as defined in OAuth 2.0,
    /// Section 2.1, and does not have a client secret.
    /// 
    /// *  "client_secret_post": The client uses the HTTP POST parameters
    /// as defined in OAuth 2.0, Section 2.3.1.
    /// 
    /// *  "client_secret_basic": The client uses HTTP Basic as defined in
    /// OAuth 2.0, Section 2.3.1.
    /// 
    /// Additional values can be defined via the IANA "OAuth Token
    /// Endpoint Authentication Methods" registry established in
    /// Section 4.2.  Absolute URIs can also be used as values for this
    /// parameter without being registered.If unspecified or omitted,
    /// the default is "client_secret_basic", denoting the HTTP Basic
    /// authentication scheme as specified in Section 2.3.1 of OAuth 2.0.
    /// </summary>
    [JsonPropertyName(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethod)]
    public string? TokenEndpointAuthMethod
    {
        get
        {
            if (string.IsNullOrEmpty(_tokenEndpointAuthMethod))
            {
                if (this.TryGetValue(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethod, out var value))
                {
                    _tokenEndpointAuthMethod = value as string;
                }
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
                _scope = GetStandardClaim(UdapConstants.RegistrationDocumentValues.Scope);
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
    /// Similar to  <see cref="System.IdentityModel.Tokens.Jwt.JwtPayload.AddClaims(System.Collections.Generic.IEnumerable{System.Security.Claims.Claim})"/>.
    /// Adds a number of <see cref="System.Security.Claims.Claim"/> to the <see cref="UdapDynamicClientRegistrationDocument"/>.
    /// Unlike <see cref="System.IdentityModel.Tokens.Jwt.JwtPayload.AddClaims(System.Collections.Generic.IEnumerable{System.Security.Claims.Claim})"/>, UDAP claims defined to be collections of values will be maintained as
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

            // If there is an existing value, append to it.
            // What to do if the 'ClaimValueType' is not the same.
            if (TryGetValue(jsonClaimType, out var existingValue))
            {
                if (existingValue is ICollection<string> knownClaimValueType)
                {
                    switch (claim.Type)
                    {
                        case UdapConstants.RegistrationDocumentValues.Contacts:
                        case UdapConstants.RegistrationDocumentValues.GrantTypes:
                        case UdapConstants.RegistrationDocumentValues.ResponseTypes:
                        case UdapConstants.RegistrationDocumentValues.RedirectUris:    

                            knownClaimValueType.Add((string)jsonClaimValue);
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

                        var grantTypes = new HashSet<string>() { (string)jsonClaimValue };

                        this[jsonClaimType] = grantTypes;
                        break;

                    case UdapConstants.RegistrationDocumentValues.RedirectUris:
                        var redirectUris = new List<string>() { (string)jsonClaimValue};

                        this[jsonClaimType] = redirectUris;
                        break;
                    default:
                        this[jsonClaimType] = jsonClaimValue;
                        break;
                }
            }
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

    internal long GetStandardInt64Claim(string claimType)
    {
        if (TryGetValue(claimType, out object? value))
        {
            if (value is long numLong)
                return numLong;

            if (value is int numInt)
                return numInt;

            if (value is JsonElement { ValueKind: JsonValueKind.Number } element)
            {
                return element.GetInt64();
            }
            return 0;
        }

        return 0;
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

        if (claim.ValueType == JsonClaimValueTypes.JsonNull)
            return string.Empty;

        if (claim.Value == null)
        {
            return string.Empty;
        }

        if (claim.ValueType == JsonClaimValueTypes.Json)
            return JsonNode.Parse(claim.Value)!;

        if (claim.ValueType == JsonClaimValueTypes.JsonArray)
            return JsonNode.Parse(claim.Value)!;
        

        return claim.Value;
    }


    /// <summary>
    /// Serializes this instance to JSON.
    /// </summary>
    /// <returns>This instance as JSON.</returns>
    public virtual string SerializeToJson()
    {
        return JsonSerializer.Serialize(this);
    }

    /// <summary>
    /// Encodes this instance as Base64UrlEncoded JSON.
    /// </summary>
    /// <returns>Base64UrlEncoded JSON.</returns>
    public virtual string Base64UrlEncode()
    {
        return Base64UrlEncoder.Encode(SerializeToJson());
    }
}

public interface ISoftwareStatementSerializer
{
    public string SerializeToJson();
    public string Base64UrlEncode();
}