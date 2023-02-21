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
using System.Security.Cryptography.X509Certificates;
using IdentityModel;
using Microsoft.IdentityModel.Tokens;

namespace Udap.Model.Registration;

/// <summary>
/// Dynamic Client Registration builder.
/// Recommended way to build a <see cref="UdapDynamicClientRegistrationDocument"/>
/// for authorization_code flow.
/// </summary>
public class UdapDcrBuilderForAuthorizationCode
{
    private DateTime _now;
    private UdapDynamicClientRegistrationDocument _document;

    private UdapDcrBuilderForAuthorizationCode(X509Certificate2 cert)
    {
        _now = DateTime.UtcNow;

        _document = new UdapDynamicClientRegistrationDocument();
        _document.GrantTypes = new List<string?> { OidcConstants.GrantTypes.AuthorizationCode };
        _document.IssuedAt = EpochTime.GetIntDate(_now.ToUniversalTime());
        _document.Issuer = cert.GetNameInfo(X509NameType.UrlName, false);
        _document.Subject = cert.GetNameInfo(X509NameType.UrlName, false);
    }

    public static UdapDcrBuilderForAuthorizationCode Create(X509Certificate2 cert)
    {
        return new UdapDcrBuilderForAuthorizationCode(cert);
    }

    //TODO: Safe for multi SubjectAltName scenarios
    public static UdapDcrBuilderForAuthorizationCode Create(X509Certificate2 cert, string subjectAltName)
    {
        return new UdapDcrBuilderForAuthorizationCode(cert);
    }

    /// <summary>
    /// Set at construction time. 
    /// </summary>
    public DateTime Now
    {
        get
        {
            return _now;
        }
    }
    
    public UdapDcrBuilderForAuthorizationCode WithAudience(string? audience)
    {
        _document.Audience = audience;
        return this;
    }

    public UdapDcrBuilderForAuthorizationCode WithExpiration(TimeSpan expirationOffset)
    {
        _document.Expiration = EpochTime.GetIntDate(_now.Add(expirationOffset));
        return this;
    }

    /// <summary>
    /// Generally one should just let the constructor set IssuedAt
    /// </summary>
    /// <param name="issuedAt"></param>
    /// <returns></returns>
    public UdapDcrBuilderForAuthorizationCode OverrideIssuedAt(DateTime issuedAt)
    {
        _document.IssuedAt = EpochTime.GetIntDate(issuedAt.ToUniversalTime());
        return this;
    }

    public UdapDcrBuilderForAuthorizationCode WithJwtId()
    {
        _document.JwtId = CryptoRandom.CreateUniqueId();
        return this;
    }

    public UdapDcrBuilderForAuthorizationCode WithClientName(string clientName)
    {
        _document.ClientName = clientName;
        return this;
    }

    public UdapDcrBuilderForAuthorizationCode WithContacts(ICollection<string?> contacts)
    {
        _document.Contacts = contacts;
        return this;
    }

    public UdapDcrBuilderForAuthorizationCode WithTokenEndpointAuthMethod(string tokenEndpointAuthMethod)
    {
        _document.TokenEndpointAuthMethod = tokenEndpointAuthMethod;
        return this;
    }

    public UdapDcrBuilderForAuthorizationCode WithScope(string scope)
    {
        _document.Scope = scope;
        return this;
    }

    public UdapDcrBuilderForAuthorizationCode WithResponseTypes(ICollection<string?> responseTypes)
    {
        _document.ResponseTypes = responseTypes;
        return this;
    }

    public UdapDcrBuilderForAuthorizationCode WithRedirectUrls(ICollection<string?> redirectUrls)
    {
        _document.RedirectUris = redirectUrls;
        return this;
    }

    public UdapDcrBuilderForAuthorizationCode WithLogoUri(string logoUri)
    {
        _document.LogoUri = new Uri(logoUri);
        return this;
    }

    public UdapDynamicClientRegistrationDocument Build()
    {
        return _document;
    }
}