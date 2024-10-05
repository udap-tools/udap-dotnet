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
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
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
    private readonly DateTime _now;
    private readonly UdapDynamicClientRegistrationDocument _document;
    private X509Certificate2? _certificate;

    protected  UdapDynamicClientRegistrationDocument Document
    {
        get => _document;
    }
    
    protected UdapDcrBuilderForClientCredentials(X509Certificate2 certificate, bool cancelRegistration) : this(cancelRegistration)
    {
        this.WithCertificate(certificate);
    }

    protected UdapDcrBuilderForClientCredentials(bool cancelRegistration)
    {
        _now = DateTime.UtcNow;

        _document = [];
        if (!cancelRegistration)
        {
            _document.GrantTypes = new HashSet<string> { OidcConstants.GrantTypes.ClientCredentials };
        }
        else
        {
            //
            // Cancel registration is requested with an empty GranTypes array, not a missing grant_types element
            //
            _document.GrantTypes = new HashSet<string>(); 
        }
        _document.IssuedAt = EpochTime.GetIntDate(_now.ToUniversalTime());
    }

    /// <summary>
    /// Create a builder for registration
    /// </summary>
    /// <param name="cert"></param>
    /// <returns></returns>
    public static UdapDcrBuilderForClientCredentials Create(X509Certificate2 cert)
    {
        return new UdapDcrBuilderForClientCredentials(cert, false);
    }

    
    /// <summary>
    /// Create a builder for registration.
    /// </summary>
    /// <returns></returns>
    public static UdapDcrBuilderForClientCredentials Create()
    {
        return new UdapDcrBuilderForClientCredentials(false);
    }

    /// <summary>
    /// Create a builder to cancel an existing registration.
    /// </summary>
    /// <param name="cert"></param>
    /// <returns></returns>
    public static UdapDcrBuilderForClientCredentials Cancel(X509Certificate2 cert)
    {
        return new UdapDcrBuilderForClientCredentials(cert, true);
    }


    /// <summary>
    /// Create a builder to cancel an existing registration.
    /// </summary>
    /// <returns></returns>
    public static UdapDcrBuilderForClientCredentials Cancel()
    {
        return new UdapDcrBuilderForClientCredentials(true);
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
    /// Generally one should just let the constructor set IssuedAt.  But clients like UdapEd like to have control over settings to produce negative tests.
    /// </summary>
    /// <param name="secondsSinceEpoch"></param>
    /// <returns></returns>
    public UdapDcrBuilderForClientCredentials WithIssuedAt(long secondsSinceEpoch)
    {
        _document.IssuedAt = secondsSinceEpoch;
        return this;
    }

    /// <summary>
    /// Set string, token identifier that uniquely identifies this JWT until the expiration time
    /// </summary>
    /// <param name="jwtId"></param>
    /// <returns></returns>
    public UdapDcrBuilderForClientCredentials WithJwtId(string? jwtId = null)
    {
        _document.JwtId = jwtId ?? CryptoRandom.CreateUniqueId();
        return this;
    }

    public UdapDcrBuilderForClientCredentials WithClientName(string? clientName)
    {
        _document.ClientName = clientName;
        return this;
    }

    public UdapDcrBuilderForClientCredentials WithContacts(ICollection<string>? contacts)
    {
        _document.Contacts = contacts;
        return this;
    }

    public UdapDcrBuilderForClientCredentials WithTokenEndpointAuthMethod(string? tokenEndpointAuthMethod)
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
        if (string.IsNullOrEmpty(logoUri))
        {
            return this;
        }

        _ = new Uri(logoUri);
        _document.LogoUri = logoUri;
        return this;
    }

    private readonly Dictionary<string, object> _extensions = [];

    /// <summary>
    /// Add Typed extension object
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="key"></param>
    /// <param name="value"></param>
    /// <returns></returns>
    public UdapDcrBuilderForClientCredentials WithExtension<T>(string key, T value) where T : class
    {
        var jsonElement = JsonSerializer.Deserialize<JsonElement>(JsonSerializer.Serialize(value));
        _extensions[key] = jsonElement;
        _document.Extensions = _extensions;
        return this;
    }


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
            throw new Exception("Missing certificate");
        }

        return SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(_certificate, Build())
                .Build(signingAlgorithm);
    }
}