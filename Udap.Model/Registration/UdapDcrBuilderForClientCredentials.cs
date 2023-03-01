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
using Udap.Model.Statement;

namespace Udap.Model.Registration;

/// <summary>
/// Dynamic Client Registration builder.
/// Recommended way to build a <see cref="UdapDynamicClientRegistrationDocument"/>
/// for client_credentials flow.
/// </summary>
public class UdapDcrBuilderForClientCredentials
{
    private X509Certificate2? _certificate;
    private UdapDynamicClientRegistrationDocument _document;
    private DateTime _now;

    private UdapDcrBuilderForClientCredentials(X509Certificate2 certificate) : this()
    {
        this.WithCertificate(certificate);
    }

    private UdapDcrBuilderForClientCredentials()
    {
        _now = DateTime.UtcNow;

        _document = new UdapDynamicClientRegistrationDocument();
        _document.GrantTypes = new List<string?> { OidcConstants.GrantTypes.ClientCredentials };
        _document.IssuedAt = EpochTime.GetIntDate(_now.ToUniversalTime());
    }

    public static UdapDcrBuilderForClientCredentials Create(X509Certificate2 cert)
    {
        return new UdapDcrBuilderForClientCredentials(cert);
    }

    //TODO: Safe for multi SubjectAltName scenarios
    public static UdapDcrBuilderForClientCredentials Create(X509Certificate2 cert, string subjectAltName)
    {
        return new UdapDcrBuilderForClientCredentials(cert);
    }
    
    public static UdapDcrBuilderForClientCredentials Create()
    {
        return new UdapDcrBuilderForClientCredentials();
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

    //
    // Not sure I want to Expose these
    //

    // public UdapClientCredentialsDcrBuilder WithIssuer(string issuer)
    // {
    //     _document.Issuer = issuer;
    //     return this;
    // }
    //
    // public UdapClientCredentialsDcrBuilder WithSubject(string subject)
    // {
    //     _document.Subject = subject;
    //     return this;
    // }

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

    public UdapDcrBuilderForClientCredentials WithContacts(ICollection<string?> contacts)
    {
        _document.Contacts = contacts;
        return this;
    }

    public UdapDcrBuilderForClientCredentials WithTokenEndpointAuthMethod(string tokenEndpointAuthMethod)
    {
        _document.TokenEndpointAuthMethod = tokenEndpointAuthMethod;
        return this;
    }

    public UdapDcrBuilderForClientCredentials WithScope(string scope)
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
        return _document;
    }
    
    public string BuildSoftwareStatement()
    {
        if (_certificate == null)
        {
            return "missing certificate";
        }

        return SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(_certificate, _document)
                .Build();
    }
}