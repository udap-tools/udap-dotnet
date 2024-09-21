#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using System;
using Microsoft.IdentityModel.Tokens;
using IdentityModel;
using System.Collections.Generic;
using Udap.Model.Statement;

namespace Udap.Model.Registration;

/// <summary>
/// Builder for Certifications and Endorsement signed JWT.
/// </summary>
public class UdapCertificationsAndEndorsementBuilder
{
    private readonly DateTime _now;
    private readonly UdapCertificationAndEndorsementDocument _document;
    private X509Certificate2? _certificate;

    /// <summary>
    /// Let implementer bypass fluent interface and access Document directly
    /// </summary>
    protected UdapCertificationAndEndorsementDocument Document => _document;

    protected UdapCertificationsAndEndorsementBuilder(string certificationName, X509Certificate2 certificate) : this(certificationName)
    {
        this.WithCertificate(certificate);
    }

    protected UdapCertificationsAndEndorsementBuilder(string certificationName)
    {
        _now = DateTime.UtcNow;
        _document = new UdapCertificationAndEndorsementDocument(certificationName);
    }

    /// <summary>
    /// Create a builder for registration
    /// </summary>
    /// <param name="certificationName">Short name for certification</param>
    /// <param name="cert"></param>
    /// <returns></returns>
    public static UdapCertificationsAndEndorsementBuilder Create(string certificationName, X509Certificate2 cert)
    {
        return new UdapCertificationsAndEndorsementBuilder(certificationName, cert);
    }

    /// <summary>
    /// Create a builder for registration
    /// </summary>
    /// <param name="certificationName"></param>
    /// <returns></returns>
    public static UdapCertificationsAndEndorsementBuilder Create(string certificationName)
    {
        return new UdapCertificationsAndEndorsementBuilder(certificationName);
    }

    public UdapCertificationsAndEndorsementBuilder WithAudience(string? audience)
    {
        if (!string.IsNullOrEmpty(audience))
        {
            _ = new Uri(audience);
            _document.Audience = audience;
        }
        
        return this;
    }

    /// <summary>
    /// Set expiration time (max 3 years, must not expire after certificate).
    /// Expressed in seconds since the "Epoch".
    /// </summary>
    /// <param name="expirationOffset"></param>
    /// <returns></returns>
    public UdapCertificationsAndEndorsementBuilder WithExpiration(TimeSpan expirationOffset)
    {
        if (expirationOffset > TimeSpan.FromDays(365 * 3)) //ignoring leap year
        {
            throw new ArgumentOutOfRangeException(nameof(expirationOffset), "Expiration limit to 3 years");
        }

        if (_certificate == null)
        {
            throw new Exception("Certificate required");
        }

        if (_certificate.NotAfter.ToUniversalTime() < (_now + expirationOffset))
        {
            throw new ArgumentOutOfRangeException(nameof(expirationOffset), "Expiration must not expire after certificate");
        }

        _document.Expiration = EpochTime.GetIntDate(_now.Add(expirationOffset));
        return this;
    }

    /// <summary>
    /// Typically easier to use <see cref="WithExpiration(TimeSpan)"/>
    /// </summary>
    /// <param name="expiration"></param>
    /// <returns></returns>
    public UdapCertificationsAndEndorsementBuilder WithExpiration(DateTime expiration)
    {
        return WithExpiration(expiration.ToUniversalTime() - _now);
    }

    /// <summary>
    /// Typically easier to use <see cref="WithExpiration(TimeSpan)"/>
    /// </summary>
    /// <param name="secondsSinceEpoch"></param>
    /// <returns></returns>
    public UdapCertificationsAndEndorsementBuilder WithExpiration(long secondsSinceEpoch)
    {
        return WithExpiration(EpochTime.DateTime(secondsSinceEpoch));
    }

    /// <summary>
    /// Generally one should just let the constructor set IssuedAt.  But clients like UdapEd like to have control over settings to produce negative tests.
    /// </summary>
    /// <param name="secondsSinceEpoch"></param>
    /// <returns></returns>
    public UdapCertificationsAndEndorsementBuilder WithIssuedAt(long secondsSinceEpoch)
    {
        _document.IssuedAt = secondsSinceEpoch;
        return this;
    }

    /// <summary>
    /// Set token identifier that uniquely identifies this JWT until the expiration time
    /// </summary>
    /// <param name="jwtId"></param>
    /// <returns></returns>
    public UdapCertificationsAndEndorsementBuilder WithJwtId(string? jwtId = null)
    {
        _document.JwtId = jwtId ?? CryptoRandom.CreateUniqueId();
        return this;
    }

    /// <summary>
    /// Set optional URL pointing to logo for this certification, e.g. seal
    /// </summary>
    /// <param name="certificationLogo"></param>
    /// <returns></returns>
    public UdapCertificationsAndEndorsementBuilder WithCertificationLogo(string? certificationLogo)
    {
        if (!string.IsNullOrEmpty(certificationLogo))
        {
            _ = new Uri(certificationLogo);
            _document.CertificationLogo = certificationLogo;
        }
        
        return this;
    }

    /// <summary>
    /// Set optional longer description of what this certification entails
    /// </summary>
    /// <param name="description"></param>
    /// <returns></returns>
    public UdapCertificationsAndEndorsementBuilder WithCertificationDescription(string description)
    {
        _document.CertificationDescription = description;
        return this;
    }

    /// <summary>
    /// Set array of strings where each URI identifies a certification program or set of criteria.
    /// This should be a resolvable URL where more information can be obtained.
    /// (optional; required if certification is self-signed)
    /// </summary>
    /// <param name="uris"></param>
    /// <returns></returns>
    public UdapCertificationsAndEndorsementBuilder WithCertificationUris(ICollection<string>? uris)
    {
        _document.CertificationUris = uris;
        return this;
    }

    /// <summary>
    /// Set optional URL of status endpoint operated by the Certifier
    /// (<a href='https://www.udap.org/udap-certifications-and-endorsements.html'>see section 8</a>); omit if self-signed
    /// </summary>
    /// <param name="endpoint"></param>
    /// <returns></returns>
    public UdapCertificationsAndEndorsementBuilder WithCertificationStatusEndpoint(string? endpoint)
    {
        if (!string.IsNullOrEmpty(endpoint))
        {
            _ = new Uri(endpoint);
            _document.CertificationStatusEndpoint = endpoint;
        }

        return this;
    }

    /// <summary>
    /// Set boolean (optional, default: false); true if this certification represents an endorsement of the Client App by the issuer.
    /// </summary>
    /// <param name="isEndorsement"></param>
    /// <returns></returns>
    public UdapCertificationsAndEndorsementBuilder WithEndorsement(bool isEndorsement)
    {
        _document.IsEndorsement = isEndorsement;
        return this;
    }

    /// <summary>
    /// Set optional developer name
    /// </summary>
    /// <param name="name"></param>
    /// <returns></returns>
    public UdapCertificationsAndEndorsementBuilder WithDeveloperName(string name)
    {
        _document.DeveloperName = name;
        return this;
    }

    /// <summary>
    /// Set JSON object, as per OIDC Core 1.0 Section 5.1.1
    ///
    /// <example>
    /// {
    ///   "address": {
    ///      "formatted": "123 Main St, City, Country",
    ///      "street_address": "123 Main St",
    ///      "locality": "City",
    ///      "region": "State",
    ///      "postal_code": "12345",
    ///      "country": "Country"
    ///   }
    /// }
    /// </example>
    /// </summary>
    /// <param name="address"></param>
    /// <returns></returns>
public UdapCertificationsAndEndorsementBuilder WithDeveloperAddress(string address)
    {
        _document.DeveloperAddress = address;
        return this;
    }

    /// <summary>
    /// Set string, as per RFC 7591
    ///
    /// Human-readable string name of the client to be presented to the
    /// end-user during authorization.If omitted, the authorization
    /// server MAY display the raw "client_id" value to the end-user
    /// instead.It is RECOMMENDED that clients always send this field.
    /// The value of this field MAY be internationalized, as described in
    /// <a href='https://datatracker.ietf.org/doc/html/rfc7591#section-2.2'>Section 2.2</a>.
    /// </summary>
    /// <param name="clientName"></param>
    /// <returns></returns>
    public UdapCertificationsAndEndorsementBuilder WithClientName(string clientName)
    {
        _document.ClientName = clientName;
        return this;
    }

    /// <summary>
    /// Set string, as per RFC 7591 (recommended)
    /// 
    /// A unique identifier string (e.g., a Universally Unique Identifier
    /// (UUID)) assigned by the client developer or software publisher
    /// used by registration endpoints to identify the client software to
    /// be dynamically registered. Unlike "client_id", which is issued by
    /// the authorization server and SHOULD vary between instances, the
    /// "software_id" SHOULD remain the same for all instances of the
    /// client software.The "software_id" SHOULD remain the same across
    /// multiple updates or versions of the same piece of software.The
    /// value of this field is not intended to be human readable and is
    /// usually opaque to the client and authorization server.
    /// </summary>
    /// <param name="softwareId"></param>
    /// <returns></returns>
    public UdapCertificationsAndEndorsementBuilder WithSoftwareId(string softwareId)
    {
        _document.SoftwareId = softwareId;
        return this;
    }

    /// <summary>
    /// Set string, as per RFC 7591 (optional)
    /// 
    /// A version identifier string for the client software identified by
    /// "software_id".  The value of the "software_version" SHOULD change
    /// on any update to the client software identified by the same
    /// "software_id".  The value of this field is intended to be compared
    /// using string equality matching and no other comparison semantics
    /// are defined by this specification.The value of this field is
    /// outside the scope of this specification, but it is not intended to
    /// be human readable and is usually opaque to the client and
    /// authorization server.  The definition of what constitutes an
    /// update to client software that would trigger a change to this
    /// value is specific to the software itself and is outside the scope
    /// of this specification.
    /// </summary>
    /// <param name="softwareVersion"></param>
    /// <returns></returns>
    public UdapCertificationsAndEndorsementBuilder WithSoftwareVersion(string softwareVersion)
    {
        _document.SoftwareVersion = softwareVersion;
        return this;
    }

    /// <summary>
    /// Set string, as per RFC 7591 (optional)
    /// 
    /// URL string of a web page providing information about the client.
    /// If present, the server SHOULD display this URL to the end-user in
    /// a clickable fashion.It is RECOMMENDED that clients always send
    /// this field.The value of this field MUST point to a valid web
    /// page.  The value of this field MAY be internationalized, as
    /// described in <a href='https://datatracker.ietf.org/doc/html/rfc7591#section-2.2'>Section 2.2</a>.
    /// </summary>
    /// <param name="clientUri"></param>
    /// <returns></returns>
    public UdapCertificationsAndEndorsementBuilder WithClientUri(string? clientUri)
    {
        if (!string.IsNullOrEmpty(clientUri))
        {
            _ = new Uri(clientUri);
            _document.ClientUri = clientUri;
        }
        
        return this;
    }

    /// <summary>
    /// Set string, as per RFC 7591
    /// 
    /// URL string that references a logo for the client.  If present, the
    /// server SHOULD display this image to the end-user during approval.
    /// The value of this field MUST point to a valid image file.  The
    /// value of this field MAY be internationalized, as described in
    /// <a href='https://datatracker.ietf.org/doc/html/rfc7591#section-2.2'>Section 2.2</a>.
    /// </summary>
    /// <param name="logoUri"></param>
    /// <returns></returns>
    public UdapCertificationsAndEndorsementBuilder WithLogoUri(string? logoUri)
    {
        if (!string.IsNullOrEmpty(logoUri))
        {
            _ = new Uri(logoUri);
            _document.LogoUri = logoUri;
        }
        
        return this;
    }

    /// <summary>
    /// Set string, as per RFC 7591
    /// 
    /// URL string that points to a human-readable terms of service
    /// document for the client that describes a contractual relationship
    /// between the end-user and the client that the end-user accepts when
    /// authorizing the client.The authorization server SHOULD display
    /// this URL to the end-user if it is provided.The value of this
    /// field MUST point to a valid web page.  The value of this field MAY
    /// be internationalized, as described in
    /// <a href='https://datatracker.ietf.org/doc/html/rfc7591#section-2.2'>Section 2.2</a>.
    /// </summary>
    /// <param name="termsOfService"></param>
    /// <returns></returns>
    public UdapCertificationsAndEndorsementBuilder WithTermsOfService(string termsOfService)
    {
        _document.TosUri = termsOfService;
        return this;
    }

    /// <summary>
    /// Set string, as per RFC 7591
    /// 
    /// URL string that points to a human-readable privacy policy document
    /// that describes how the deployment organization collects, uses,
    /// retains, and discloses personal data.The authorization server
    /// SHOULD display this URL to the end-user if it is provided.The
    /// value of this field MUST point to a valid web page.  The value of
    /// this field MAY be internationalized, as described in
    /// <a href='https://datatracker.ietf.org/doc/html/rfc7591#section-2.2'>Section 2.2</a>.
    /// </summary>
    /// <param name="policyUri"></param>
    /// <returns></returns>
    public UdapCertificationsAndEndorsementBuilder WithPolicyUri(string policyUri)
    {
        _document.ClientUri = policyUri;
        return this;
    }

    /// <summary>
    /// Set, array of strings, as per RFC 7591, further constrained as follows:
    /// each array element MUST be a valid URI with mailto or https scheme
    /// so that AS operator can contact client app developer
    ///
    /// Array of strings representing ways to contact people responsible
    /// for this client, typically email addresses.The authorization
    /// server MAY make these contact addresses available to end-users for
    /// support requests for the client.See Section 6 for information on
    /// Privacy Considerations.
    /// </summary>
    /// <param name="contacts"></param>
    /// <returns></returns>
    public UdapCertificationsAndEndorsementBuilder WithContacts(ICollection<string>? contacts)
    {
        _document.Contacts = contacts;
        return this;
    }

    /// <summary>
    /// Set string, for SMART app launch with EHR launch flow, requires scope includes launch 
    /// </summary>
    /// <param name="launchUri"></param>
    /// <returns></returns>
    public UdapCertificationsAndEndorsementBuilder WithLaunchUri(string? launchUri)
    {
        if (!string.IsNullOrEmpty(launchUri))
        {
            _ = new Uri(launchUri);
            _document.LaunchUri = launchUri;
        }
        
        return this;
    }

    /// <summary>
    /// Set array of strings, as per RFC 7591, except as noted;
    /// an array of fully specified redirection URIs for the client (conditional).
    /// MUST be absent if grant_types = client_credentials.
    /// Note: To support the RFC 8252 requirement that a native mobile app use a
    /// different redirection URI for every Authorization Server,
    /// the Certifier may include the special character * in the URI as a wildcard
    /// for a single path component or query parameter value,
    /// e.g. https://app.example.com/redirect/* or https://app.example.com/redirect?server=*.
    /// For URIs that contain literal asterisk characters, these characters should be
    /// URL-encoded as “%2A”; the Authorization Server MUST NOT interpret such a URL-encoded
    /// asterisk as a wildcard symbol. For a given Authorization Server, the client MUST
    /// register one or more complete redirection URIs with the Authorization Server that
    /// match this pattern; each registered redirect_uri MUST be fully specified and MUST NOT
    /// contain any wildcard symbols, even if the certification includes a wildcard symbol.
    /// </summary>
    /// <param name="redirectUris"></param>
    /// <returns></returns>
    public UdapCertificationsAndEndorsementBuilder WithRedirectUris(ICollection<string>? redirectUris)
    {
        _document.RedirectUris = redirectUris;
        return this;
    }

    /// <summary>
    /// Set array of strings of the form ip, ip1-ip2, or ip/CIDR (optional); origin IP to
    /// connect to token endpoint, e.g. ["198.51.100.0/24", "203.0.113.55"]
    /// </summary>
    /// <param name="ipsAllowed"></param>
    /// <returns></returns>
    public UdapCertificationsAndEndorsementBuilder WithIPsAllowed(ICollection<string>? ipsAllowed)
    {
        _document.IpAllowed = ipsAllowed;
        return this;
    }

    /// <summary>
    /// Set array of strings, as per RFC 7591; e.g. authorization_code, refresh_token, client_credentials (optional)
    /// </summary>
    /// <param name="grantTypes"></param>
    /// <returns></returns>
    public UdapCertificationsAndEndorsementBuilder WithGrantTypes(ICollection<string>? grantTypes)
    {
        _document.GrantTypes = grantTypes;
        return this;
    }

    /// <summary>
    /// Set array of strings, as per RFC 7591; code (omit for client_credentials) (optional)
    /// </summary>
    /// <param name="responseTypes"></param>
    /// <returns></returns>
    public UdapCertificationsAndEndorsementBuilder WithResponseTypes(ICollection<string>? responseTypes)
    {
        _document.ResponseTypes = responseTypes;
        return this;
    }

    /// <summary>
    /// Set string containing space separate list of permitted scopes, as per RFC 7591; optional
    /// </summary>
    /// <param name="scope"></param>
    /// <returns></returns>
    public UdapCertificationsAndEndorsementBuilder WithScope(string scope)
    {
        _document.Scope = scope;
        return this;
    }

    /// <summary>
    /// Set string, as per RFC 7591 (optional); RFC 7591 defines the values: none, client_secret_post,
    /// and client_secret_basic. The additional value private_key_jwt may also be used.
    /// </summary>
    /// <param name="tokenEndpointAuthMethod"></param>
    /// <returns></returns>
    public UdapCertificationsAndEndorsementBuilder WithTokenEndpointAuthMethod(string tokenEndpointAuthMethod)
    {
        _document.TokenEndpointAuthMethod = tokenEndpointAuthMethod;
        return this;
    }

    /// <summary>
    /// Set string, as per RFC 7591 (optional); locks this certification to a specific
    /// client key or keys. Note that jwks_uri MUST NOT be used. The client must prove
    /// possession of this key during registration and during authentication. To facilitate
    /// key rollover, binding using the sub claim URI is preferable to binding to a specific key.
    /// </summary>
    /// <param name="jwks"></param>
    /// <returns></returns>
    public UdapCertificationsAndEndorsementBuilder WithJwks(string jwks)
    {
        throw new NotImplementedException();
        // _document.Jwks = jwks;
        // return this;
    }

    public UdapCertificationsAndEndorsementBuilder WithCertificate(X509Certificate2 certificate)
    {
        _certificate = certificate;

        _document.Issuer = certificate.GetNameInfo(X509NameType.UrlName, false);
        _document.Subject = certificate.GetNameInfo(X509NameType.UrlName, false);

        return this;
    }
    
    public UdapCertificationAndEndorsementDocument Build()
    {
        return Document;
    }

    public string BuildSoftwareStatement(string? signingAlgorithm = UdapConstants.SupportedAlgorithm.RS256)
    {
        if (_certificate == null)
        {
            throw new Exception("Missing certificate");
        }

        return SignedSoftwareStatementBuilder<UdapCertificationAndEndorsementDocument>
            .Create(_certificate, Document)
            .Build(signingAlgorithm);
    }
}
