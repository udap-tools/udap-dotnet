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
using System.Security.Cryptography.X509Certificates;
using IdentityModel;
using Microsoft.IdentityModel.Tokens;
using Udap.Model.Statement;
using Udap.Util.Extensions;

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
    private X509Certificate2? _certificate;

    protected X509Certificate2? Certificate
    {
        get => _certificate;
        set => _certificate = value;
    }

    protected UdapDynamicClientRegistrationDocument Document
    {
        get => _document;
        set => _document = value;
    }
    
    protected UdapDcrBuilderForAuthorizationCode(X509Certificate2 certificate, bool cancelRegistration) : this(cancelRegistration)
    {
        this.WithCertificate(certificate);
    }

    protected UdapDcrBuilderForAuthorizationCode(bool cancelRegistration)
    {
        _now = DateTime.UtcNow;

        _document = new UdapDynamicClientRegistrationDocument();
        if (!cancelRegistration)
        {
            _document.GrantTypes = new List<string> { OidcConstants.GrantTypes.AuthorizationCode };
        }
        else
        {
            //
            // Cancel registration is requested with an empty GranTypes array, not a missing grant_types element
            //
            _document.GrantTypes = new List<string>();
        }
        _document.IssuedAt = EpochTime.GetIntDate(_now.ToUniversalTime());
    }
    /// <summary>
    /// Register or update an existing registration
    /// </summary>
    /// <param name="cert"></param>
    /// <returns></returns>
    public static UdapDcrBuilderForAuthorizationCode Create(X509Certificate2 cert)
    {
        return new UdapDcrBuilderForAuthorizationCode(cert, false);
    }
    
    /// <summary>
    /// Register or update an existing registration
    /// </summary>
    /// <returns></returns>
    public static UdapDcrBuilderForAuthorizationCode Create()
    {
        return new UdapDcrBuilderForAuthorizationCode(false);
    }

    /// <summary>
    /// Cancel an existing registration.
    /// </summary>
    /// <param name="cert"></param>
    /// <returns></returns>
    public static UdapDcrBuilderForAuthorizationCode Cancel(X509Certificate2 cert)
    {
        return new UdapDcrBuilderForAuthorizationCode(cert, true);
    }

    /// <summary>
    /// Cancel an existing registration.
    /// </summary>
    /// <returns></returns>
    public static UdapDcrBuilderForAuthorizationCode Cancel()
    {
        return new UdapDcrBuilderForAuthorizationCode(true);
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

    public UdapDcrBuilderForAuthorizationCode WithGrantType(string grantType)
    {
        _document.GrantTypes!.Add(grantType);

        return this;
    }

#if NET6_0_OR_GREATER
    /// <summary>
    /// If the certificate has more than one uniformResourceIdentifier in the Subject Alternative Name
    /// extension of the client certificate then this will allow one to be picked.
    /// </summary>
    /// <param name="issuer"></param>
    /// <returns></returns>
    public UdapDcrBuilderForAuthorizationCode WithIssuer(Uri issuer)
    {
        var uriNames = _certificate!.GetSubjectAltNames(n => n.TagNo == (int)X509Extensions.GeneralNameType.URI);
        if (!uriNames.Select(u => u.Item2).Contains(issuer.AbsoluteUri))
        {
            throw new Exception($"Certificate does not contain a URI Subject Alternative Name of, {issuer.AbsoluteUri}");
        }
        _document.Issuer = issuer.AbsoluteUri;
        _document.Subject = issuer.AbsoluteUri;
        return this;
    }

#endif

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
    /// Typically easier to use <see cref="WithExpiration(TimeSpan)"/>
    /// </summary>
    /// <param name="secondsSinceEpoch"></param>
    /// <returns></returns>
    public UdapDcrBuilderForAuthorizationCode WithExpiration(long secondsSinceEpoch)
    {
        _document.Expiration = secondsSinceEpoch;
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

    public UdapDcrBuilderForAuthorizationCode WithJwtId(string? jwtId = null)
    {
        _document.JwtId = jwtId ?? CryptoRandom.CreateUniqueId();
        return this;
    }

    public UdapDcrBuilderForAuthorizationCode WithClientName(string clientName)
    {
        _document.ClientName = clientName;
        return this;
    }

    public UdapDcrBuilderForAuthorizationCode WithContacts(ICollection<string>? contacts)
    {
        _document.Contacts = contacts;
        return this;
    }

    public UdapDcrBuilderForAuthorizationCode WithTokenEndpointAuthMethod(string tokenEndpointAuthMethod)
    {
        _document.TokenEndpointAuthMethod = tokenEndpointAuthMethod;
        return this;
    }

    public UdapDcrBuilderForAuthorizationCode WithScope(string? scope)
    {
        _document.Scope = scope;
        return this;
    }

    public UdapDcrBuilderForAuthorizationCode WithResponseTypes(ICollection<string>? responseTypes)
    {
        _document.ResponseTypes = responseTypes;
        return this;
    }

    public UdapDcrBuilderForAuthorizationCode WithRedirectUrls(ICollection<string>? redirectUrls)
    {
        _document.RedirectUris = redirectUrls;
        return this;
    }

    public UdapDcrBuilderForAuthorizationCode WithLogoUri(string logoUri)
    {
        _ = new Uri(logoUri);
        _document.LogoUri = logoUri;
        return this;
    }

    public UdapDcrBuilderForAuthorizationCode WithCertificate(X509Certificate2 certificate)
    {
        _certificate = certificate;

        _document.Issuer = certificate.GetNameInfo(X509NameType.UrlName, false);
        _document.Subject = certificate.GetNameInfo(X509NameType.UrlName, false);

        return this;
    }

    public UdapDynamicClientRegistrationDocument Build()
    {
        return Document;
    }

    public string BuildSoftwareStatement(string? signingAlgorithm = UdapConstants.SupportedAlgorithm.RS256)
    {
        if (_certificate == null)
        {
            return "missing certificate";
        }

        return SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
            .Create(_certificate, Document)
            .Build(signingAlgorithm);
    }
}