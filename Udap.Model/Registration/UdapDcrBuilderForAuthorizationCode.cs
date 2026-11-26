#region (c) 2024 Joseph Shook. All rights reserved.
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
using Duende.IdentityModel;
using Microsoft.IdentityModel.Tokens;
using Udap.Model.Statement;
using Udap.Util.Extensions;
using System.Linq;

namespace Udap.Model.Registration;

/// <summary>
/// Dynamic Client Registration builder.
/// Recommended way to build a <see cref="UdapDynamicClientRegistrationDocument"/>
/// for authorization_code flow.
/// </summary>
public class UdapDcrBuilderForAuthorizationCode
{
    private readonly DateTime _now;
    private readonly UdapDynamicClientRegistrationDocument _document;
    private List<X509Certificate2>? _certificates;

    protected UdapDynamicClientRegistrationDocument Document
    {
        get => _document;
    }
    
    protected UdapDcrBuilderForAuthorizationCode(X509Certificate2 certificate, bool cancelRegistration) : this(cancelRegistration)
    {
        this.WithCertificate(certificate);
    }

    protected UdapDcrBuilderForAuthorizationCode(List<X509Certificate2> certificates, bool cancelRegistration) : this(cancelRegistration)
    {
        this.WithCertificates(certificates);
    }

    protected UdapDcrBuilderForAuthorizationCode(bool cancelRegistration)
    {
        _now = DateTime.UtcNow;

        _document = [];
        if (!cancelRegistration)
        {
            _document.GrantTypes = [OidcConstants.GrantTypes.AuthorizationCode];
        }
        else
        {
            //
            // Cancel registration is requested with an empty GranTypes array, not a missing grant_types element
            //
            _document.GrantTypes = [];
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
    /// <param name="certs">Certificate chain where the first certificate is the end certificate</param>
    /// <returns></returns>
    public static UdapDcrBuilderForAuthorizationCode Create(List<X509Certificate2> certs)
    {
        return new UdapDcrBuilderForAuthorizationCode(certs, false);
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
    
    public UdapDcrBuilderForAuthorizationCode WithGrantType(string grantType)
    {
        _document.GrantTypes!.Add(grantType);

        return this;
    }

    /// <summary>
    /// If the certificate has more than one uniformResourceIdentifier in the Subject Alternative Name
    /// extension of the client certificate then this will allow one to be picked.
    /// </summary>
    /// <param name="issuer">One of the certificate's URI SANs, exactly as it appears in the certificate.</param>
    /// <returns></returns>
    public UdapDcrBuilderForAuthorizationCode WithIssuer(Uri issuer)
    {
        // OriginalString, not AbsoluteUri: AbsoluteUri adds "/" to a URI with no path, and iss must equal the SAN exactly.
        return WithIssuer(issuer.OriginalString);
    }

    /// <summary>
    /// If the certificate has more than one uniformResourceIdentifier in the Subject Alternative Name
    /// extension of the client certificate then this will allow one to be picked.
    /// </summary>
    /// <param name="issuer">One of the certificate's URI SANs, exactly as it appears in the certificate.
    /// iss and sub are set to this value unchanged; the comparison with the SANs is ordinal.</param>
    /// <returns></returns>
    public UdapDcrBuilderForAuthorizationCode WithIssuer(string issuer)
    {
        var uriNames = _certificates!.First().GetSubjectAltNames(n => n.TagNo == (int)X509Extensions.GeneralNameType.URI);
        if (!uriNames.Any(u => string.Equals(u.Item2, issuer, StringComparison.Ordinal)))
        {
            throw new Exception($"End certificate does not contain a URI Subject Alternative Name of, {issuer}");
        }
        _document.Issuer = issuer;
        _document.Subject = issuer;
        return this;
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
    /// Generally one should just let the constructor set IssuedAt.  But clients like UdapEd like to have control over settings to produce negative tests.
    /// </summary>
    /// <param name="secondsSinceEpoch"></param>
    /// <returns></returns>
    public UdapDcrBuilderForAuthorizationCode WithIssuedAt(long secondsSinceEpoch)
    {
        _document.IssuedAt = secondsSinceEpoch;
        return this;
    }

    public UdapDcrBuilderForAuthorizationCode WithJwtId(string? jwtId = null)
    {
        _document.JwtId = jwtId ?? CryptoRandom.CreateUniqueId();
        return this;
    }

    public UdapDcrBuilderForAuthorizationCode WithClientName(string? clientName)
    {
        _document.ClientName = clientName;
        return this;
    }

    public UdapDcrBuilderForAuthorizationCode WithContacts(ICollection<string>? contacts)
    {
        _document.Contacts = contacts;
        return this;
    }

    public UdapDcrBuilderForAuthorizationCode WithTokenEndpointAuthMethod(string? tokenEndpointAuthMethod)
    {
        _document.TokenEndpointAuthMethod = tokenEndpointAuthMethod;
        return this;
    }

    public UdapDcrBuilderForAuthorizationCode WithScope(string? scope)
    {
        _document.Scope = scope;
        return this;
    }

    public UdapDcrBuilderForAuthorizationCode WithDPoPEnabled(bool dpopEnabled)
    {
        _document.DPoPEnabled = dpopEnabled;
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
        _certificates = new List<X509Certificate2> { certificate };

        _document.Issuer = certificate.GetNameInfo(X509NameType.UrlName, false);
        _document.Subject = certificate.GetNameInfo(X509NameType.UrlName, false);

        return this;
    }

    public UdapDcrBuilderForAuthorizationCode WithCertificates(List<X509Certificate2> certificates)
    {
        _certificates = certificates;

        _document.Issuer = _certificates.First().GetNameInfo(X509NameType.UrlName, false);
        _document.Subject = _certificates.First().GetNameInfo(X509NameType.UrlName, false);

        return this;
    }

    public UdapDynamicClientRegistrationDocument Build()
    {
        if(_document.ResponseTypes == null || _document.ResponseTypes.Count == 0)
        {
            _document.ResponseTypes = new HashSet<string> { "code" };
        }

        return Document;
    }

    public string BuildSoftwareStatement(string? signingAlgorithm = UdapConstants.SupportedAlgorithm.RS256)
    {
        if (_certificates == null)
        {
            throw new Exception("Missing certificate");
        }

        return SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
            .Create(_certificates, Build())
            .Build(signingAlgorithm);
    }
}