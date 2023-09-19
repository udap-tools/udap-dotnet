#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;
using System.Text.Json.Serialization;
using IdentityModel;
using Microsoft.IdentityModel.Tokens;

namespace Udap.Model.Registration;

/// <summary>
/// See the <a href="https://www.udap.org/udap-certifications-and-endorsements-stu1.html">
/// "UDAP CERTIFICATIONS AND ENDORSEMENTS FOR CLIENT APPLICATIONS"</a> profile.
/// The certification is signed and assembled using JWS compact serialization as per RFC 7515.
/// </summary>
public class UdapCertificationAndEndorsementDocument : ISoftwareStatementSerializer
{
    /// <summary>
    /// See the <a href="https://www.udap.org/udap-certifications-and-endorsements-stu1.html">
    /// "UDAP CERTIFICATIONS AND ENDORSEMENTS FOR CLIENT APPLICATIONS"</a> profile.
    /// The certification is signed and assembled using JWS compact serialization as per RFC 7515.
    /// <remarks>
    /// Default <see cref="IssuedAt"/> is set to the current GMT.
    /// Default <see cref="JwtId"/> is set by <see cref="CryptoRandom.CreateUniqueId"/>
    /// </remarks>
    /// </summary>
    public UdapCertificationAndEndorsementDocument(string certificationName)
    {
        IssuedAt = EpochTime.GetIntDate(DateTime.Now.ToUniversalTime());
        JwtId = CryptoRandom.CreateUniqueId();
        CertificationName = certificationName;
    }

    /// <summary>
    /// string, Certifier’s unique identifying URI
    /// </summary>
    [JsonPropertyName(UdapConstants.CertificationAndEndorsementDocumentValues.Issuer)]
    public string? Issuer { get; set; }

    /// <summary>
    /// string, client’s unique identifying URI
    /// (binds to SAN:uniformResourceIdentifier in Client App certificate).
    /// For self-signed certifications, this is the same as the iss value.
    /// </summary>
    [JsonPropertyName(UdapConstants.CertificationAndEndorsementDocumentValues.Subject)]
    public string? Subject { get; set; }

    /// <summary>
    /// number, expiration time (max 3 years, must not expire after certificate).
    /// Expressed in seconds since the "Epoch".
    /// </summary>
    [JsonPropertyName(UdapConstants.CertificationAndEndorsementDocumentValues.Expiration)]
    public long Expiration { get; set; }

    /// <summary>
    /// number, issued at time.  Expressed in seconds since the "Epoch"
    /// </summary>
    [JsonPropertyName(UdapConstants.CertificationAndEndorsementDocumentValues.IssuedAt)]
    public long IssuedAt { get; set; }

    /// <summary>
    /// string, token identifier that uniquely identifies this JWT until the expiration time
    /// </summary>
    [JsonPropertyName(UdapConstants.CertificationAndEndorsementDocumentValues.JwtId)]
    public string JwtId { get; set; }

    /// <summary>
    /// string; the entity that operates the certification program 
    /// (required if certification is not self-signed, omit if self-signed)
    /// </summary>
    [JsonPropertyName(UdapConstants.CertificationAndEndorsementDocumentValues.CertificateIssuer)]
    public string? CertificateIssuer { get; set; }

    /// <summary>
    /// string; short name for certification (required)
    /// </summary>
    [JsonPropertyName(UdapConstants.CertificationAndEndorsementDocumentValues.CertificationName)]
    public string CertificationName { get; set; }

    /// <summary>
    /// string (optional); URL pointing to logo for this certification, e.g. seal
    /// </summary>
    [JsonPropertyName(UdapConstants.CertificationAndEndorsementDocumentValues.CertificationLogo)]
    public string? CertificationLogo { get; set; }

    /// <summary>
    /// string; longer description of what this certification entails (optional)
    /// </summary>
    [JsonPropertyName(UdapConstants.CertificationAndEndorsementDocumentValues.CertificationDescription)]
    public string? CertificationDescription { get; set; }

    /// <summary>
    /// array of strings; each URI identifies a certification program or set of criteria. 
    /// This should be a resolvable URL where more information can be obtained. (optional; 
    /// required if certification is self-signed)
    /// </summary>
    [JsonPropertyName(UdapConstants.CertificationAndEndorsementDocumentValues.CertificationUris)]
    public string[]? CertificationUris { get; set; }

    /// <summary>
    /// string (optional); URL of status endpoint operated by the Certifier (see section 8); 
    /// omit if self-signed
    /// </summary>
    [JsonPropertyName(UdapConstants.CertificationAndEndorsementDocumentValues.CertificationStatusEndpoint)]
    public string? CertificationStatusEndpoint { get; set; }

    /// <summary>
    /// boolean (optional, default: false); 
    /// true if this certification represents an endorsement of the Client App by the issuer.
    /// </summary>
    [JsonPropertyName(UdapConstants.CertificationAndEndorsementDocumentValues.IsEndorsement)]
    public bool? IsEndorsement { get; set; }

    /// <summary>
    /// string (optional)
    /// </summary>
    [JsonPropertyName(UdapConstants.CertificationAndEndorsementDocumentValues.DeveloperName)]
    public string? DeveloperName { get; set; }

    /// <summary>
    /// JSON object, as per OIDC Core 1.0 Section 5.1.1
    /// </summary>
    [JsonPropertyName(UdapConstants.CertificationAndEndorsementDocumentValues.DeveloperAddress)]
    public string? DeveloperAddress { get; set; }

    /// <summary>
    /// string, as per RFC 7591
    /// </summary>
    [JsonPropertyName(UdapConstants.CertificationAndEndorsementDocumentValues.ClientName)]
    public string? ClientName { get; set; }

    /// <summary>
    /// string, as per RFC 7591 (recommended)
    /// </summary>
    [JsonPropertyName(UdapConstants.CertificationAndEndorsementDocumentValues.SoftwareId)]
    public string? SoftwareId { get; set; }

    /// <summary>
    /// string, as per RFC 7591 (optional)
    /// </summary>
    [JsonPropertyName(UdapConstants.CertificationAndEndorsementDocumentValues.SoftwareVersion)]
    public string? SoftwareVersion { get; set; }

    /// <summary>
    /// string, as per RFC 7591
    /// </summary>
    [JsonPropertyName(UdapConstants.CertificationAndEndorsementDocumentValues.ClientUri)]
    public string? ClientUri { get; set; }

    /// <summary>
    /// string, as per RFC 7591
    /// </summary>
    [JsonPropertyName(UdapConstants.CertificationAndEndorsementDocumentValues.LogoUri)]
    public string? LogoUri { get; set; }

    /// <summary>
    /// string, as per RFC 7591
    /// </summary>
    [JsonPropertyName(UdapConstants.CertificationAndEndorsementDocumentValues.TosUri)]
    public string? TosUri { get; set; }

    /// <summary>
    /// string, as per RFC 7591
    /// </summary>
    [JsonPropertyName(UdapConstants.CertificationAndEndorsementDocumentValues.PolicyUri)]
    public string? PolicyUri { get; set; }

    /// <summary>
    /// array of strings, as per RFC 7591, further constrained as follows: 
    /// each array element MUST be a valid URI with mailto or https scheme 
    /// so that AS operator can contact client app developer
    /// </summary>
    [JsonPropertyName(UdapConstants.CertificationAndEndorsementDocumentValues.Contacts)]
    public string[]? Contacts { get; set; }

    /// <summary>
    /// string, for SMART app launch with EHR launch flow, requires scope includes launch
    /// </summary>
    [JsonPropertyName(UdapConstants.CertificationAndEndorsementDocumentValues.LaunchUri)]
    public string? LaunchUri { get; set; }

    /// <summary>
    /// array of strings, as per RFC 7591, except as noted; 
    /// an array of fully specified redirection URIs for the client (conditional). 
    /// MUST be absent if grant_types = client_credentials. Note: To support the RFC 8252
    /// requirement that a native mobile app use a different redirection URI for every 
    /// Authorization Server, the Certifier may include the special character * in the URI 
    /// as a wildcard for a single path component or query parameter value, 
    /// e.g. https://app.example.com/redirect/* or https://app.example.com/redirect?server=*. 
    /// For URIs that contain literal asterisk characters, these characters should be 
    /// URL-encoded as “%2A”; the Authorization Server MUST NOT interpret such a URL-encoded 
    /// asterisk as a wildcard symbol. For a given Authorization Server, the client MUST 
    /// register one or more complete redirection URIs with the Authorization Server that 
    /// match this pattern; each registered redirect_uri MUST be fully specified and MUST NOT 
    /// contain any wildcard symbols, even if the certification includes a wildcard symbol.
    /// </summary>
    [JsonPropertyName(UdapConstants.CertificationAndEndorsementDocumentValues.RedirectUris)]
    public string[]? RedirectUris { get; set; }

    /// <summary>
    /// array of strings of the form ip, ip1-ip2, or ip/CIDR (optional); origin IP to connect 
    /// to token endpoint, e.g. ["198.51.100.0/24", "203.0.113.55"]
    /// </summary>
    [JsonPropertyName(UdapConstants.CertificationAndEndorsementDocumentValues.IpAllowed)]
    public string[]? IpAllowed { get; set; }

    /// <summary>
    /// array of strings, as per RFC 7591; e.g. authorization_code, refresh_token, 
    /// client_credentials (optional)
    /// </summary>
    [JsonPropertyName(UdapConstants.CertificationAndEndorsementDocumentValues.GrantTypes)]
    public string[]? GrantTypes { get; set; }

    /// <summary>
    /// array of strings, as per RFC 7591; code (omit for client_credentials) (optional)
    /// </summary>
    [JsonPropertyName(UdapConstants.CertificationAndEndorsementDocumentValues.ResponseTypes)]
    public string[]? ResponseTypes { get; set; }

    /// <summary>
    /// string containing space separate list of permitted scopes, as per RFC 7591; optional
    /// </summary>
    [JsonPropertyName(UdapConstants.CertificationAndEndorsementDocumentValues.Scope)]
    public string? Scope { get; set; }

    /// <summary>
    /// string, as per RFC 7591 (optional); RFC 7591 defines the values: none, client_secret_post, 
    /// and client_secret_basic. The additional value private_key_jwt may also be used.
    /// </summary>
    [JsonPropertyName(UdapConstants.CertificationAndEndorsementDocumentValues.TokenEndpointAuthMethod)]
    public string? TokenEndpointAuthMethod { get; set; }

    /// <summary>
    /// string, as per RFC 7591 (optional); locks this certification to a specific client key
    /// or keys. Note that jwks_uri MUST NOT be used. The client must prove possession of 
    /// this key during registration and during authentication. To facilitate key rollover, 
    /// binding using the sub claim URI is preferable to binding to a specific key.
    [JsonPropertyName(UdapConstants.CertificationAndEndorsementDocumentValues.Jwks)]
    public string? Jwks { get; set; }

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
