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
/// for client_credentials flow.
/// </summary>
public class UdapDcrBuilderForClientCredentials
{
    private DateTime _now;
    private UdapDynamicClientRegistrationDocument _document;
    private X509Certificate2? _certificate;

    protected X509Certificate2? Certificate
    {
        get => _certificate;
        set => _certificate = value;
    }

    protected  UdapDynamicClientRegistrationDocument Document
    {
        get => _document;
        set => _document = value;
    }
    
    protected UdapDcrBuilderForClientCredentials(X509Certificate2 certificate, bool cancelRegistration) : this(cancelRegistration)
    {
        this.WithCertificate(certificate);
    }

    protected UdapDcrBuilderForClientCredentials(bool cancelRegistration)
    {
        _now = DateTime.UtcNow;

        _document = new UdapDynamicClientRegistrationDocument();
        if (!cancelRegistration)
        {
            _document.GrantTypes = new List<string> { OidcConstants.GrantTypes.ClientCredentials };
        }
        _document.IssuedAt = EpochTime.GetIntDate(_now.ToUniversalTime());
    }

    /// <summary>
    /// Register or update an existing registration
    /// </summary>
    /// <param name="cert"></param>
    /// <returns></returns>
    public static UdapDcrBuilderForClientCredentials Create(X509Certificate2 cert)
    {
        return new UdapDcrBuilderForClientCredentials(cert, false);
    }

    //TODO: Safe for multi SubjectAltName scenarios
    /// <summary>
    /// Register or update an existing registration by subjectAltName
    /// </summary>
    /// <param name="cert"></param>
    /// <returns></returns>
    public static UdapDcrBuilderForClientCredentials Create(X509Certificate2 cert, string subjectAltName)
    {
        return new UdapDcrBuilderForClientCredentials(cert, false);
    }

    /// <summary>
    /// Register or update an existing registration
    /// </summary>
    /// <param name="cert"></param>
    /// <returns></returns>
    public static UdapDcrBuilderForClientCredentials Create()
    {
        return new UdapDcrBuilderForClientCredentials(false);
    }

    /// <summary>
    /// Cancel an existing registration.
    /// </summary>
    /// <param name="cert"></param>
    /// <returns></returns>
    public static UdapDcrBuilderForClientCredentials Cancel(X509Certificate2 cert)
    {
        return new UdapDcrBuilderForClientCredentials(cert, true);
    }

    //TODO: Safe for multi SubjectAltName scenarios
    /// <summary>
    /// Cancel an existing registration by subject alt name.
    /// </summary>
    /// <param name="cert"></param>
    /// <param name="subjectAltName"></param>
    /// <returns></returns>
    public static UdapDcrBuilderForClientCredentials Cancel(X509Certificate2 cert, string subjectAltName)
    {
        return new UdapDcrBuilderForClientCredentials(cert, true);
    }

    /// <summary>
    /// Cancel an existing registration.
    /// </summary>
    /// <returns></returns>
    public static UdapDcrBuilderForClientCredentials Cancel()
    {
        return new UdapDcrBuilderForClientCredentials(true);
    }


    /// <summary>
    /// Set at construction time. 
    /// </summary>
    public DateTime Now {
        get
        {
            return _now;
        }
    }

    /// <summary>
    /// If the certificate has more than one uniformResourceIdentifier in the Subject Alternative Name
    /// extension of the client certificate then this will allow one to be picked.
    /// </summary>
    /// <param name="issuer"></param>
    /// <returns></returns>
    public UdapDcrBuilderForClientCredentials WithIssuer(Uri issuer)
    {
        var uriNames = _certificate!.GetSubjectAltNames(n=>n.TagNo == (int)X509Extensions.GeneralNameType.URI);
        if (!uriNames.Select(u => u.Item2).Contains(issuer.AbsoluteUri))
        {
            throw new Exception($"Certificate does not contain a URI Subject Alternative Name of, {issuer.AbsoluteUri}");
        }
        _document.Issuer = issuer.AbsoluteUri;
        _document.Subject = issuer.AbsoluteUri;
        return this;
    }
    


    public UdapDcrBuilderForClientCredentials WithAudience(string? audience)
    {
        _document.Audience = audience;
        return this;
    }

    public UdapDcrBuilderForClientCredentials WithExpiration(TimeSpan expirationOffset)
    {
        _document.Expiration = EpochTime.GetIntDate(_now.Add(expirationOffset));
        return this;
    }

    /// <summary>
    /// Typically easier to use <see cref="WithExpiration(TimeSpan)"/>
    /// </summary>
    /// <param name="secondsSinceEpoch"></param>
    /// <returns></returns>
    public UdapDcrBuilderForClientCredentials WithExpiration(long secondsSinceEpoch)
    {
        _document.Expiration = secondsSinceEpoch;
        return this;
    }

    /// <summary>
    /// Generally one should just let the constructor set IssuedAt
    /// </summary>
    /// <param name="issuedAt"></param>
    /// <returns></returns>
    public UdapDcrBuilderForClientCredentials OverrideIssuedAt(DateTime issuedAt)
    {
        _document.IssuedAt = EpochTime.GetIntDate(issuedAt.ToUniversalTime());
        return this;
    }
    
    public UdapDcrBuilderForClientCredentials WithJwtId(string? jwtId = null)
    {
        _document.JwtId = jwtId ?? CryptoRandom.CreateUniqueId();
        return this;
    }

    public UdapDcrBuilderForClientCredentials WithClientName(string clientName)
    {
        _document.ClientName = clientName;
        return this;
    }

    public UdapDcrBuilderForClientCredentials WithContacts(ICollection<string> contacts)
    {
        _document.Contacts = contacts;
        return this;
    }

    public UdapDcrBuilderForClientCredentials WithTokenEndpointAuthMethod(string tokenEndpointAuthMethod)
    {
        _document.TokenEndpointAuthMethod = tokenEndpointAuthMethod;
        return this;
    }
    
    public UdapDcrBuilderForClientCredentials WithScope(string? scope)
    {
        _document.Scope = scope;
        return this;
    }

    public UdapDcrBuilderForClientCredentials WithLogoUri(string logoUri)
    {
        _document.LogoUri = new Uri(logoUri);
        return this;
    }

    //TODO: should be able to build with all certs in path.
    public UdapDcrBuilderForClientCredentials WithCertificate(X509Certificate2 certificate)
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